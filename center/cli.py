import argparse
import base64
import getpass
import json
import logging
import os
import secrets
import time
from pathlib import Path
from urllib.parse import quote

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .backup import inspect_backup, reconcile, restore, snapshot
from .db import audit, dump, migrate, transaction
from .models import Plan
from .security import Vault, b64, password_hash, private_write


def add_admin(root, username, password, otp_secret, role='owner', products=None):
    if len(password) < 16:
        raise ValueError('管理员密码至少16字符')
    vault = Vault(Path(root) / 'vault.json')
    with transaction(Path(root) / 'center.db') as c:
        c.execute('INSERT INTO admins(username,password,totp,role,products) VALUES(?,?,?,?,?)',
                  (username, password_hash(password), vault.seal(otp_secret), role, dump(products or [])))
        audit(c, int(time.time()), 'local-operator', 'admin.created', target=username, detail={'role': role, 'products': products or []})


def seed(root, product):
    with transaction(Path(root) / 'center.db') as c:
        c.execute('INSERT INTO products VALUES(?,?,?)', (product, product, '1.0'))
        for name, days, label in [('trial', 3, '体验卡'), ('week', 7, '周卡'), ('month', 30, '月卡'), ('year', 365, '年卡'), ('perpetual', None, '永久卡')]:
            plan = Plan(id=product+'-'+name, product=product, name=label, days=days, perpetual=days is None)
            c.execute('INSERT INTO plans VALUES(?,?,?)', (plan.id, product, dump(plan.model_dump())))
        audit(c, int(time.time()), 'local-operator', 'product.seed', product)


def main():
    parser = argparse.ArgumentParser(description='授权中心运维：所有秘密都通过交互或环境变量提供，不放命令行')
    parser.add_argument('--data', default=os.environ.get('LC_DATA', 'data'))
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init')
    init.add_argument('--issuer', required=True)
    init.add_argument('--username', default='admin')
    init.add_argument('--enrollment', required=True, help='首次MFA绑定文件路径，使用后移入密码管理器并删除')
    admin = sub.add_parser('add-admin')
    admin.add_argument('--username', required=True)
    admin.add_argument('--role', choices=['owner', 'operator', 'viewer'], required=True)
    admin.add_argument('--products', nargs='*', default=[])
    admin.add_argument('--enrollment', required=True)
    seed_cmd = sub.add_parser('seed')
    seed_cmd.add_argument('--product', required=True)
    sub.add_parser('serve')
    pub = sub.add_parser('public-keys')
    pub.add_argument('--output', required=True)
    backup = sub.add_parser('backup')
    backup.add_argument('--output', required=True)
    verify = sub.add_parser('verify-backup')
    verify.add_argument('--input', required=True)
    recovery = sub.add_parser('restore')
    recovery.add_argument('--input', required=True)
    recovery.add_argument('--destination', required=True)
    recovery.add_argument('--accept-stale-state', action='store_true')
    diff = sub.add_parser('reconcile')
    diff.add_argument('--other-data', required=True)
    rot = sub.add_parser('rotate-key')
    rot.add_argument('--service-stopped', action='store_true', required=True)
    args = parser.parse_args()
    root = Path(args.data)
    if args.command in ['init', 'add-admin']:
        if Path(args.enrollment).exists():
            raise ValueError('ENROLLMENT_TARGET_EXISTS')
        password = os.environ.get('LC_BOOTSTRAP_PASSWORD') or getpass.getpass('管理员新密码（至少16字符）: ')
        if len(password) < 16:
            raise ValueError('PASSWORD_TOO_SHORT')
        otp = base64.b32encode(secrets.token_bytes(20)).decode()
        if args.command == 'init':
            if root.exists() and any(root.iterdir()):
                raise ValueError('INIT_REQUIRES_EMPTY_DATA_DIRECTORY')
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            Vault.create(root / 'vault.json', args.issuer)
            migrate(root / 'center.db')
        add_admin(root, args.username, password, otp, getattr(args, 'role', 'owner'), getattr(args, 'products', []))
        uri = f'otpauth://totp/{quote("LicenseCenter:"+args.username)}?secret={otp}&issuer=LicenseCenter&algorithm=SHA1&digits=6&period=30'
        private_write(args.enrollment, json.dumps({'username': args.username, 'totp_secret': otp, 'otpauth_uri': uri}, indent=2))
        print('管理员已创建；MFA绑定材料已写入指定文件。请用验证器绑定并安全移除该文件。')
    elif args.command == 'seed':
        seed(root, args.product)
        print('已创建产品及五个内置套餐')
    elif args.command == 'serve':
        import uvicorn
        logging.basicConfig(level=logging.INFO, format='%(message)s')
        os.environ['LC_DATA'] = str(root.resolve())
        uvicorn.run('center.app:create_app', factory=True, host=os.environ.get('LC_HOST', '127.0.0.1'),
                    port=int(os.environ.get('LC_PORT', '8000')), proxy_headers=False, access_log=False)
    elif args.command == 'public-keys':
        vault = Vault(root / 'vault.json')
        private_write(args.output, json.dumps({'issuer': vault.data['issuer'], 'keys': vault.public()}, indent=2))
        print('公钥已导出；请通过可信发布渠道分发')
    elif args.command in ['backup', 'verify-backup', 'restore']:
        password = os.environ.get('LC_BACKUP_PASSWORD') or getpass.getpass('独立备份口令: ')
        if args.command == 'backup':
            result = snapshot(root, args.output, password)
        elif args.command == 'verify-backup':
            result = inspect_backup(args.input, password)[0]['manifest']
        else:
            result = restore(args.input, args.destination, password, args.accept_stale_state)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.command == 'reconcile':
        print(json.dumps(reconcile(root, args.other_data), ensure_ascii=False, indent=2))
    elif args.command == 'rotate-key':
        # Requires stopped service because workers load a fixed keyring at startup.
        from sdk.client import atomic_json
        vault = Vault(root / 'vault.json')
        previous = vault.data['active']
        kid = secrets.token_hex(8)
        vault.data['keys'][kid] = b64(Ed25519PrivateKey.generate().private_bytes_raw())
        vault.data['active'] = kid
        atomic_json(vault.path, vault.data)
        with transaction(root / 'center.db') as c:
            audit(c, int(time.time()), 'local-operator', 'key.rotate', target=kid, detail={'previous': previous})
        print(json.dumps({'previous': previous, 'active': kid, 'notice': '先通过可信渠道分发双公钥，再重新启动服务；旧公钥暂时保留。'}))


if __name__ == '__main__':
    main()
