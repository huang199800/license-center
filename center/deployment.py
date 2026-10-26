"""Container-side deployment helpers. No credentials are accepted as CLI values."""
import argparse
import base64
import hashlib
import json
import os
import secrets
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .backup import _key, inspect_backup, restore, snapshot
from .cli import add_admin, seed
from .db import audit, migrate, transaction
from .security import Vault, private_write


def secret_file(path):
    value = Path(path).read_text(encoding='utf-8').strip()
    if len(value) < 16:
        raise ValueError('SECRET_TOO_SHORT')
    return value


def seal(value, password, context):
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    raw = json.dumps(value, separators=(',', ':')).encode()
    return {'salt': base64.b64encode(salt).decode(), 'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(AESGCM(_key(password, salt)).encrypt(nonce, raw, context)).decode()}


def unseal(value, password, context):
    return json.loads(AESGCM(_key(password, base64.b64decode(value['salt']))).decrypt(
        base64.b64decode(value['nonce']), base64.b64decode(value['ciphertext']), context))


def pack(root, output, config, metadata, password, key_password):
    if password == key_password:
        raise ValueError('BACKUP_AND_KEY_PASSWORDS_MUST_DIFFER')
    with tempfile.TemporaryDirectory() as temp:
        legacy = Path(temp) / 'consistent.lcb'
        snapshot(root, legacy, password)
        payload, _ = inspect_backup(legacy, password)
    vault = payload.pop('vault')
    payload['deployment_config'] = config
    header = {'format': 2, 'version': metadata['version'], 'commit': metadata['commit'], 'schema': 1,
              'created_at': int(time.time()), 'issuer': vault['issuer']}
    context = json.dumps(header, sort_keys=True, separators=(',', ':')).encode()
    bundle = {'header': header, 'state': seal(payload, password, b'LC-STATE-2'+context),
              'keys': seal(vault, key_password, b'LC-KEYS-2'+context)}
    private_write(output, json.dumps(bundle))
    return header


def unpack(source, destination, config_output, password, key_password, accept_stale, bundle_value=None):
    if not accept_stale:
        raise ValueError('ACCEPT_STALE_STATE_REQUIRED')
    envelope = bundle_value if bundle_value is not None else json.loads(Path(source).read_text())
    header = envelope['header']
    if header['format'] != 2 or header['schema'] != 1:
        raise ValueError('BACKUP_FORMAT_OR_SCHEMA_UNSUPPORTED')
    context = json.dumps(header, sort_keys=True, separators=(',', ':')).encode()
    payload = unseal(envelope['state'], password, b'LC-STATE-2'+context)
    vault = unseal(envelope['keys'], key_password, b'LC-KEYS-2'+context)
    if vault['issuer'] != header['issuer']:
        raise ValueError('BACKUP_ISSUER_MISMATCH')
    config = payload.pop('deployment_config')
    payload['vault'] = vault
    # Reuse the established checksum/schema/DB/decryption validation and audited new-dir restore.
    with tempfile.TemporaryDirectory() as temp:
        legacy = Path(temp) / 'restore.lcb'
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        cipher = AESGCM(_key(password, salt)).encrypt(nonce, json.dumps(payload).encode(), b'LC-BACKUP-1')
        private_write(legacy, json.dumps({'format':1,'salt':base64.b64encode(salt).decode(),
                                         'nonce':base64.b64encode(nonce).decode(),'ciphertext':base64.b64encode(cipher).decode()}))
        # The restored vault is staged in data; the host moves it into its distinct keys directory.
        previous = os.environ.pop('LC_VAULT', None)
        try:
            restore(legacy, destination, password, True)
        finally:
            if previous is not None:
                os.environ['LC_VAULT'] = previous
    private_write(config_output, json.dumps({'header': header, 'config': config}, indent=2))
    return header


def initialize(root, credentials, issuer, username, enrollment, password_value=None):
    root = Path(root)
    if (root/'center.db').exists():
        raise ValueError('DATABASE_ALREADY_EXISTS_NO_RESET')
    if root.exists() and any(root.iterdir()):
        raise ValueError('DATA_DIRECTORY_NOT_EMPTY')
    password = password_value if password_value is not None else secret_file(credentials)
    otp = base64.b32encode(secrets.token_bytes(20)).decode()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    Vault.create(root/'vault.json', issuer)
    migrate(root/'center.db')
    add_admin(root, username, password, otp)
    seed(root, 'demo')
    private_write(enrollment, json.dumps({'username': username, 'totp_secret': otp,
                    'otpauth_uri': f'otpauth://totp/LicenseCenter:{username}?secret={otp}&issuer=LicenseCenter'}, indent=2))
    return {'initialized': True, 'schema': 1, 'issuer': issuer}


def selftest():
    """Real service logic in an isolated DB; never generates entitlements in production DB."""
    from fastapi.testclient import TestClient
    from .app import create_app
    from .db import dump
    from .security import sha
    from sdk import verify_token
    previous = os.environ.pop('LC_VAULT', None)
    try:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            v = Vault.create(root/'vault.json', 'urn:deployment:selftest')
            migrate(root/'center.db');seed(root, 'test')
            def issue(kind):
                code = secrets.token_urlsafe(32)
                with transaction(root/'center.db') as c:
                    spec = c.execute('SELECT spec FROM plans WHERE id=?',('test-month',)).fetchone()[0]
                    c.execute('INSERT INTO codes(id,digest,prefix,product,snapshot,kind,max_uses,note) VALUES(?,?,?,?,?,?,1,?)',
                              (secrets.token_hex(16),v.digest_code(code),'selftest','test',spec,kind,'isolated'))
                return code
            with TestClient(create_app(root)) as c:
                r = c.post('/v1/redeem',json={'product':'test','code':issue('new'),'customer':'selftest','instance':'deployment-selftest-instance'},
                           headers={'Idempotency-Key':secrets.token_hex(16)})
                if r.status_code != 200:raise ValueError('SELFTEST_ACTIVATION_FAILED')
                result = r.json()
                p = verify_token(result['token'],keys=v.public(),issuer=v.data['issuer'],product='test',instance='deployment-selftest-instance')
                if 'basic' not in p['features']:raise ValueError('SELFTEST_FEATURE_FAILED')
                renew = c.post('/v1/renew',json={'product':'test','license_id':result['license_id'],'code':issue('renew')},
                               headers={'Authorization':'Bearer '+result['license_secret'],'Idempotency-Key':secrets.token_hex(16)})
                if renew.status_code != 200:raise ValueError('SELFTEST_RENEW_FAILED')
                refreshed = c.post('/v1/refresh',json={'product':'test','activation_id':result['activation_id']},
                                   headers={'Authorization':'Bearer '+result['activation_secret']})
                if refreshed.status_code != 200:raise ValueError('SELFTEST_REFRESH_FAILED')
        return {'selftest':'passed','checks':['redeem','signature','feature','renew','refresh'],'production_data_modified':False}
    finally:
        if previous is not None:os.environ['LC_VAULT']=previous


def main():
    p=argparse.ArgumentParser()
    sub=p.add_subparsers(dest='command',required=True)
    init=sub.add_parser('init');init.add_argument('--root',required=True);init.add_argument('--password-file',required=True)
    init.add_argument('--issuer',required=True);init.add_argument('--username',default='admin');init.add_argument('--enrollment',required=True)
    backup=sub.add_parser('backup');backup.add_argument('--root',required=True);backup.add_argument('--output',required=True)
    backup.add_argument('--config',required=True);backup.add_argument('--metadata',required=True)
    recovery=sub.add_parser('restore');recovery.add_argument('--input',required=True);recovery.add_argument('--destination',required=True)
    recovery.add_argument('--config-output',required=True);recovery.add_argument('--accept-stale-state',action='store_true')
    for command in [backup,recovery]:
        command.add_argument('--password-file',required=True);command.add_argument('--key-password-file',required=True)
    sub.add_parser('selftest')
    args=p.parse_args()
    password = secret_file(args.password_file) if args.command != 'selftest' else None
    key_password = secret_file(args.key_password_file) if args.command in ['backup','restore'] else None
    config = json.loads(Path(args.config).read_text()) if args.command == 'backup' else None
    metadata = json.loads(Path(args.metadata).read_text()) if args.command == 'backup' else None
    bundle_value = json.loads(Path(args.input).read_text()) if args.command == 'restore' else None
    # Read mounted root-only secrets first, then drop to the normal data owner before
    # touching SQLite. This avoids root-owned WAL files during online backups.
    if os.name != 'nt' and os.geteuid() == 0 and os.environ.get('LC_DROP_UID'):
        uid = int(os.environ['LC_DROP_UID'])
        gid = int(os.environ.get('LC_DROP_GID', str(uid)))
        if uid <= 0 or gid <= 0:
            raise ValueError('HELPER_REQUIRES_UNPRIVILEGED_IDENTITY')
        os.setgroups([]);os.setgid(gid);os.setuid(uid)
    if args.command=='init':result=initialize(args.root,args.password_file,args.issuer,args.username,args.enrollment,password)
    elif args.command=='backup':result=pack(args.root,args.output,config,metadata,password,key_password)
    elif args.command=='restore':result=unpack(args.input,args.destination,args.config_output,password,key_password,args.accept_stale_state,bundle_value)
    else:result=selftest()
    print(json.dumps(result,ensure_ascii=True))


if __name__=='__main__':
    try:main()
    except Exception as exc:
        # Container helper errors must not echo secrets, raw config, or subprocess output.
        print(json.dumps({'error':'DEPLOYMENT_OPERATION_FAILED','type':type(exc).__name__}))
        raise SystemExit(1)
