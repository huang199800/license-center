#!/usr/bin/env python3
"""Root-only native Debian/Ubuntu lifecycle. Never installs Docker or a gateway."""
import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

try:
    from . import ops
except ImportError:
    import ops

DEFAULT_PORT = 43871


def config_file(path):
    raw = json.loads(ops.protected(path).read_text())
    result = ops.read_config(path)
    if 'port' not in raw:
        result['port'] = DEFAULT_PORT
    return result


def check_port(config):
    # Domain describes an external reverse proxy, never a request to bind 80/443.
    with socket.socket() as sock:
        try:
            sock.bind(('127.0.0.1', config['port']))
        except OSError:
            ops.fail('REQUESTED_PORT_IN_USE_127.0.0.1_'+str(config['port']))


def unit_text(root, runtime, user, port):
    for value in [str(root), str(runtime)]:
        if not re.fullmatch(r'/[A-Za-z0-9_./-]+', value):
            ops.fail('NATIVE_PATH_REQUIRES_SIMPLE_ABSOLUTE_PATH')
    return f'''# License Center managed native service: {root}
[Unit]
Description=License Center native service
After=network.target
[Service]
Type=simple
User={user}
Group={user}
WorkingDirectory={runtime}/app
ExecStart={runtime}/venv/bin/python -m center.cli --data {root}/state/data serve
Environment=LC_HOST=127.0.0.1 LC_PORT={port} LC_VAULT={root}/state/keys/vault.json PYTHONDONTWRITEBYTECODE=1
UMask=0077
Restart=on-failure
RestartSec=3
TimeoutStopSec=45
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths={root}/state
CapabilityBoundingSet=
RestrictSUIDSGID=true
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
'''


class Native(ops.Deployment):
    def __init__(self, root):
        super().__init__(root)
        suffix = hashlib.sha256(str(self.root).encode()).hexdigest()[:10]
        self.user = 'lc-'+suffix
        self.unit = 'license-center-'+suffix+'.service'
        self.unit_path = Path('/etc/systemd/system')/self.unit
        self.runtime = None

    def config(self):
        return config_file(self.config_path)

    def account(self):
        import pwd
        try:
            value = pwd.getpwnam(self.user)
        except KeyError:
            ops.run(['useradd', '--system', '--user-group', '--home-dir', self.root,
                     '--shell', '/usr/sbin/nologin', self.user])
            value = pwd.getpwnam(self.user)
        if value.pw_uid == 0 or value.pw_gid == 0 or value.pw_dir != str(self.root) or value.pw_shell != '/usr/sbin/nologin':
            ops.fail('SERVICE_ACCOUNT_CONFLICT')
        return value.pw_uid, value.pw_gid

    def permissions(self, data=True):
        uid, gid = self.account()
        os.chmod(self.root, 0o711)
        for name in ['state', 'state/keys', 'exchange'] + (['state/data'] if data else []):
            path = self.root/name
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chown(path, uid, gid)
            os.chmod(path, 0o700)
            for item in path.iterdir():
                if item.is_file() and not item.is_symlink():
                    os.chown(item, uid, gid)
                    os.chmod(item, 0o600)

    def build(self, source, commit):
        runtime = self.root/'runtimes'/commit
        if (runtime/'ready.json').exists():
            marker = json.loads((runtime/'ready.json').read_text())
            if marker != {'commit': commit, 'requirements_sha256': hashlib.sha256((source/'requirements.lock').read_bytes()).hexdigest()}:
                ops.fail('RUNTIME_MANIFEST_MISMATCH')
            return runtime
        runtime.mkdir(parents=True, exist_ok=True, mode=0o755)
        os.chmod(runtime.parent, 0o755)
        # Root owns code and venv. The service account can read but cannot modify them.
        app = runtime/'app'
        app.mkdir(exist_ok=True)
        for name in ['center', 'sdk']:
            shutil.copytree(source/name, app/name, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        shutil.copy2(source/'release.json', app/'release.json')
        print('准备原生 Python 虚拟环境及固定哈希依赖（不安装 Docker）……', flush=True)
        ops.run(['/usr/bin/python3', '-m', 'venv', runtime/'venv'])
        ops.run([runtime/'venv/bin/python', '-m', 'pip', 'install', '--disable-pip-version-check',
                 '--only-binary=:all:', '--require-hashes', '-r', source/'requirements.lock'])
        for directory, dirs, files in os.walk(runtime):
            os.chmod(directory, 0o755)
            for name in files:
                path = Path(directory)/name
                if not path.is_symlink():
                    os.chmod(path, 0o755 if path.stat().st_mode & 0o111 else 0o644)
        ops.write_json(runtime/'ready.json', {'commit': commit, 'requirements_sha256': hashlib.sha256((source/'requirements.lock').read_bytes()).hexdigest()})
        return runtime

    def helper(self, command, *args, config=None, mounts=None):
        config = config or self.config()
        runtime = self.runtime or Path(self.meta()['runtime'])
        uid, gid = self.account()
        mapping = {'/state': str(self.root/'state'), '/exchange': str(self.root/'exchange'),
                   '/deployment': str(self.root/'config'),
                   '/run/secrets/admin': config.get('admin_password_file', ''),
                   '/run/secrets/backup': config.get('backup_password_file', ''),
                   '/run/secrets/key': config.get('key_password_file', '')}
        for source, target, mode in mounts or []:
            mapping[target] = str(source)
        def translate(value):
            value = str(value)
            for prefix in sorted(mapping, key=len, reverse=True):
                if value == prefix or value.startswith(prefix+'/'):
                    return mapping[prefix]+value[len(prefix):]
            return value
        return ops.run([runtime/'venv/bin/python', '-m', 'center.deployment', command, *map(translate, args)],
                       cwd=runtime/'app', env={'LC_DROP_UID': str(uid), 'LC_DROP_GID': str(gid),
                       'LC_VAULT': str(self.root/'state/keys/vault.json'), 'PYTHONDONTWRITEBYTECODE': '1'})

    def activate(self, runtime, config):
        marker = '# License Center managed native service: '+str(self.root)+'\n'
        if self.unit_path.exists() and not self.unit_path.read_text().startswith(marker):
            ops.fail('SYSTEMD_UNIT_ALREADY_OWNED_BY_OTHER_PROJECT')
        text = unit_text(self.root, runtime, self.user, config['port'])
        self.unit_path.write_text(text)
        os.chmod(self.unit_path, 0o644)
        ops.run(['systemctl', 'daemon-reload'])
        ops.run(['systemctl', 'enable', self.unit])
        ops.run(['systemctl', 'restart', self.unit])

    def dc(self, *args, **kwargs):
        # Reuse the existing strict structured-log allowlist, never echo raw journal.
        if args[0] == 'logs':
            return ops.run(['journalctl', '-u', self.unit, '-o', 'cat', '-n', '300', '--no-pager'], **kwargs)
        ops.fail('NATIVE_BACKEND_HAS_NO_DOCKER_COMMANDS')

    def record(self, source, runtime, commit, previous=None):
        meta = {'backend': 'native', 'version': ops.release(source)['version'], 'schema': 1,
                'commit': commit, 'source': str(source), 'runtime': str(runtime),
                'unit': self.unit, 'installed_at': int(time.time()), 'previous': previous}
        ops.write_json(self.meta_path, meta)
        ops.write_json(self.root/'config/version.json', meta)


def prepare(args, dep):
    if args.config:
        return config_file(args.config)
    if args.non_interactive:
        ops.fail('NON_INTERACTIVE_REQUIRES_PROTECTED_CONFIG')
    domain = input('现有反向代理使用的域名（可留空；不会安装网关或占用80/443）: ').strip().lower()
    port = input(f'本机监听端口 [{DEFAULT_PORT}]: ').strip() or str(DEFAULT_PORT)
    issuer = input('稳定签发者身份 [urn:license-center:production]: ').strip() or 'urn:license-center:production'
    path = dep.root/'config/native-initial.json'
    ops.write_json(path, {'domain': domain, 'port': int(port), 'issuer': issuer})
    return config_file(path)


def prerequisites(root):
    ops.host_check(root, require_docker=False)
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(root)) or str(root).startswith(('/root/', '/home/')):
        ops.fail('NATIVE_ROOT_REQUIRES_SIMPLE_PATH_OUTSIDE_HOME')
    if not Path('/run/systemd/system').is_dir():
        ops.fail('SYSTEMD_SYSTEM_INSTANCE_REQUIRED')
    if sys.version_info < (3, 10):
        ops.fail('PYTHON_3_10_OR_NEWER_REQUIRED')


def summary(dep):
    ops.summary(dep, dep.diagnostics())
    print(json.dumps({'backend': 'native', 'unit': dep.unit,
        'listen': '127.0.0.1:'+str(dep.config()['port']),
        'manage': str(Path(dep.meta()['source'])/'scripts/manage.sh')+' --root '+str(dep.root),
        'https': '配置现有反向代理后验证域名HTTPS；安装器不修改任何网关配置。'}, ensure_ascii=False))


def install(args, dep):
    if dep.meta_path.exists():
        if dep.meta().get('backend') != 'native':
            ops.fail('EXISTING_BACKEND_MISMATCH')
        if dep.meta()['commit'] != ops.commit_of():
            ops.fail('EXISTING_DEPLOYMENT_DIFFERENT_VERSION_USE_UPDATE')
        ops.run(['systemctl', 'start', dep.unit])
        summary(dep)
        return
    if any(p.name not in ['.operation.lock', 'config', 'releases', 'runtimes'] for p in dep.root.iterdir()):
        ops.fail('INSTALL_TARGET_HAS_EXISTING_DATA_USE_RECOVERY')
    config = prepare(args, dep)
    check_port(config)
    commit = ops.commit_of()
    dep.runtime = dep.build(ops.SOURCE, commit)
    config = ops.create_secrets(dep, config)
    ops.write_json(dep.config_path, config)
    dep.permissions()
    dep.helper('init', '--root', '/state/data', '--password-file', '/run/secrets/admin',
               '--issuer', config['issuer'], '--username', config['admin_username'],
               '--enrollment', '/exchange/admin-enrollment.json')
    dep.record(ops.SOURCE, dep.runtime, commit)
    dep.activate(dep.runtime, config)
    summary(dep)


def update(args, dep):
    old, config = dep.meta(), dep.config()
    source = ops.fetch_source(dep, config['repo'], args.ref, args.commit, config)
    info = ops.release(source)
    if old['schema'] != info['schema'] or old['schema'] not in info['upgrade_from_schemas']:
        ops.fail('SCHEMA_CHANGE_REQUIRES_SEPARATE_MIGRATION_PLAN')
    runtime = dep.build(source, args.commit)
    dep.runtime = Path(old['runtime'])
    backup = None
    ops.run(['systemctl', 'stop', dep.unit])
    try:
        backup = dep.backup()
        dep.runtime = runtime
        dep.activate(runtime, config)
        dep.diagnostics()
        dep.record(source, runtime, args.commit, {**old, 'backup': backup})
        summary(dep)
    except BaseException:
        print(json.dumps({'error': 'NATIVE_UPGRADE_FAILED', 'backup': backup,
            'previous_commit': old['commit'], 'previous_runtime': old['runtime'],
            'recovery': '先停止 '+dep.unit+'，保全当前数据。使用备份对应提交的restore.sh --mode native --root 新目录 --config 受保护配置 --bundle 备份 --accept-stale-state；不自动回退数据库。'}, ensure_ascii=False))
        raise


def recover(args, dep):
    if dep.meta_path.exists() or (dep.root/'state').exists():
        ops.fail('RESTORE_REQUIRES_NEW_DEPLOYMENT_ROOT')
    if not args.accept_stale_state:
        ops.fail('RESTORE_REQUIRES_ACCEPT_STALE_STATE')
    config = prepare(args, dep)
    for key in ['backup_password_file', 'key_password_file']:
        if not config.get(key):
            ops.fail('RESTORE_REQUIRES_BOTH_PROTECTED_PASSWORD_FILES')
        ops.protected(config[key])
    source = Path(args.bundle).resolve(strict=True)
    header = json.loads(source.read_text())['header']
    if header['schema'] != 1 or header['commit'] != ops.commit_of() or header['version'] != ops.release()['version']:
        ops.fail('RESTORE_MUST_USE_BACKUP_EXACT_SOURCE_VERSION_AND_COMMIT')
    check_port(config)
    print(json.dumps({'restore_target': str(dep.root), 'backup_time': header['created_at'],
         'scope': ['database', 'licenses', 'activations', 'revocations', 'audit', 'keys'], 'overwrites_existing_data': False}))
    if not args.non_interactive and input('确认旧服务已隔离，接受备份时间点回退？输入 RESTORE: ') != 'RESTORE':
        ops.fail('RESTORE_CANCELLED')
    dep.runtime = dep.build(ops.SOURCE, header['commit'])
    ops.write_json(dep.config_path, config)
    dep.permissions(data=False)
    dep.helper('restore', '--input', str(source), '--destination', '/state/data',
        '--config-output', '/exchange/restored-config.json', '--password-file', '/run/secrets/backup',
        '--key-password-file', '/run/secrets/key', '--accept-stale-state')
    restored = json.loads((dep.root/'exchange/restored-config.json').read_text())
    if restored['header'] != header:
        ops.fail('RESTORE_AUTHENTICATED_METADATA_MISMATCH')
    os.replace(dep.root/'state/data/vault.json', dep.root/'state/keys/vault.json')
    config['issuer'] = header['issuer']
    ops.write_json(dep.config_path, config)
    dep.permissions()
    dep.record(ops.SOURCE, dep.runtime, header['commit'])
    dep.activate(dep.runtime, config)
    summary(dep)


def main():
    parser = argparse.ArgumentParser(description='原生 systemd 运维，不依赖Docker')
    parser.add_argument('command', choices=['install', 'update', 'restore', 'backup', 'doctor', 'status',
                        'start', 'stop', 'restart', 'logs', 'version', 'uninstall'])
    parser.add_argument('--root', default='/opt/license-center')
    parser.add_argument('--config')
    parser.add_argument('--non-interactive', action='store_true')
    parser.add_argument('--ref');parser.add_argument('--commit');parser.add_argument('--bundle');parser.add_argument('--output')
    parser.add_argument('--accept-stale-state', action='store_true')
    args = parser.parse_args()
    if args.command == 'update' and (not args.ref or not args.commit):
        parser.error('update requires --ref and --commit')
    if args.command == 'restore' and not args.bundle:
        parser.error('restore requires --bundle')
    dep = Native(args.root)
    prerequisites(dep.root)
    with ops.lock(dep.root):
        if args.command in ['install', 'restore']:
            # Venv is the only missing runtime dependency we install; no Docker repos.
            if not dep.meta_path.exists():
                ops.run(['apt-get', 'update', '-qq'])
                ops.run(['apt-get', 'install', '-y', '-qq', 'python3-venv', 'ca-certificates'])
            (install if args.command == 'install' else recover)(args, dep)
        elif args.command == 'update':
            update(args, dep)
        elif args.command == 'backup':
            print(json.dumps({'backup': dep.backup(args.output)}))
        elif args.command == 'doctor':
            summary(dep)
        elif args.command == 'version':
            print(json.dumps(dep.meta()))
        elif args.command == 'logs':
            ops.logs(dep)
        elif args.command == 'status':
            print(ops.run(['systemctl', 'show', dep.unit, '-p', 'ActiveState', '-p', 'SubState', '-p', 'UnitFileState']).stdout)
        elif args.command == 'uninstall':
            ops.run(['systemctl', 'disable', '--now', dep.unit])
            print('服务已停用，配置、业务数据、密钥、备份、程序及服务账户全部保留。')
        else:
            ops.run(['systemctl', args.command, dep.unit])
            if args.command != 'stop':
                summary(dep)


if __name__ == '__main__':
    try:
        main()
    except (ops.OperationError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(json.dumps({'error': str(exc) if isinstance(exc, ops.OperationError) else type(exc).__name__,
            'hint': '原生安装不会占用80/443；原始外部输出已隐藏。请检查受保护配置、systemd和网络。'}, ensure_ascii=False))
        raise SystemExit(1)
