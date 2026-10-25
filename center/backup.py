"""Encrypted, consistent SQLite snapshots; restore is always to a new directory."""
import base64
import hashlib
import json
import os
import secrets
import sqlite3
import tempfile
import time
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .db import audit, connect, transaction
from .security import Vault, private_write


def _key(password, salt):
    if len(password) < 16:
        raise ValueError('备份口令至少16字符；请与备份分开保管')
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode())


def snapshot(data_dir, output, password):
    root, output = Path(data_dir), Path(output)
    if output.exists():
        raise ValueError('BACKUP_TARGET_EXISTS')
    vault = Vault(root / 'vault.json')
    # Key/config changes must be fenced while taking backup; ordinary API writes are safe.
    with tempfile.TemporaryDirectory() as temp:
        target = Path(temp) / 'center.db'
        src, dst = connect(root / 'center.db'), sqlite3.connect(target)
        try:
            src.backup(dst)
        finally:
            src.close()
            dst.close()
        raw = target.read_bytes()
    with connect(root / 'center.db') as c:
        schema = c.execute('PRAGMA user_version').fetchone()[0]
    manifest = {'format': 1, 'schema': schema, 'created_at': int(time.time()), 'issuer': vault.data['issuer'],
                'database_sha256': hashlib.sha256(raw).hexdigest(), 'active_kid': vault.data['active']}
    payload = json.dumps({'manifest': manifest, 'database': base64.b64encode(raw).decode(), 'vault': vault.data}).encode()
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    cipher = AESGCM(_key(password, salt)).encrypt(nonce, payload, b'LC-BACKUP-1')
    envelope = {'format': 1, 'salt': base64.b64encode(salt).decode(), 'nonce': base64.b64encode(nonce).decode(),
                'ciphertext': base64.b64encode(cipher).decode()}
    private_write(output, json.dumps(envelope))
    with transaction(root / 'center.db') as c:
        audit(c, int(time.time()), 'local-operator', 'backup.created', detail={'file': output.name, 'snapshot_at': manifest['created_at']})
    return manifest


def inspect_backup(path, password):
    envelope = json.loads(Path(path).read_text())
    if envelope.get('format') != 1:
        raise ValueError('BACKUP_FORMAT_UNSUPPORTED')
    plain = AESGCM(_key(password, base64.b64decode(envelope['salt']))).decrypt(
        base64.b64decode(envelope['nonce']), base64.b64decode(envelope['ciphertext']), b'LC-BACKUP-1')
    payload = json.loads(plain)
    manifest = payload['manifest']
    if manifest['format'] != 1 or manifest['schema'] != 1:
        raise ValueError('BACKUP_SCHEMA_UNSUPPORTED')
    raw = base64.b64decode(payload['database'])
    if hashlib.sha256(raw).hexdigest() != manifest['database_sha256']:
        raise ValueError('BACKUP_CHECKSUM_FAILED')
    if payload['vault']['issuer'] != manifest['issuer'] or payload['vault']['active'] != manifest['active_kid']:
        raise ValueError('BACKUP_IDENTITY_MISMATCH')
    with tempfile.TemporaryDirectory() as temp:
        db = Path(temp) / 'check.db'
        db.write_bytes(raw)
        with closing(sqlite3.connect(db)) as c:
            if c.execute('PRAGMA integrity_check').fetchone()[0] != 'ok' or c.execute('PRAGMA foreign_key_check').fetchall():
                raise ValueError('BACKUP_DATABASE_INVALID')
            if c.execute('PRAGMA user_version').fetchone()[0] != 1:
                raise ValueError('BACKUP_SCHEMA_MISMATCH')
            # Restored key material must decrypt persisted authentication material.
            vpath = Path(temp) / 'vault.json'
            vpath.write_text(json.dumps(payload['vault']))
            v = Vault(vpath, use_env=False)
            v.public()
            for (encrypted,) in c.execute('SELECT totp FROM admins'):
                v.open(encrypted)
    return payload, raw


def restore(path, destination, password, accept_stale=False):
    if not accept_stale:
        raise ValueError('必须显式接受备份时点回退，先对账并隔离旧服务')
    destination = Path(destination).resolve()
    if destination.exists():
        raise ValueError('RESTORE_REQUIRES_NONEXISTENT_DIRECTORY')
    payload, raw = inspect_backup(path, password)
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Build and validate before publishing the target directory.
    with tempfile.TemporaryDirectory(dir=destination.parent, prefix='.restore-') as temp:
        stage = Path(temp) / 'data'
        stage.mkdir(mode=0o700)
        private_write(stage / 'vault.json', json.dumps(payload['vault']))
        (stage / 'center.db').write_bytes(raw)
        if os.name != 'nt':
            os.chmod(stage / 'center.db', 0o600)
        with transaction(stage / 'center.db') as c:
            c.execute('DELETE FROM sessions')
            c.execute('DELETE FROM rate_limits')
            audit(c, int(time.time()), 'local-operator', 'restore.completed', detail=payload['manifest'])
        # Rename only the known staging directory; never overwrite production data.
        stage.rename(destination)
    return payload['manifest']


def reconcile(left_dir, right_dir):
    """Read-only report, never replays payments or silently revives revoked licenses."""
    report = {}
    tables = {'licenses': ['id', 'product', 'status', 'expires_at', 'version', 'snapshot'],
              'codes': ['id', 'product', 'uses', 'disabled'],
              'instances': ['id', 'license', 'active', 'token_until'],
              'redemptions': ['id', 'code', 'license', 'at', 'kind']}
    for table, columns in tables.items():
        datasets = []
        for directory in [left_dir, right_dir]:
            path = Path(directory) / 'center.db'
            c = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)
            try:
                datasets.append({row[0]: row[1:] for row in c.execute('SELECT ' + ','.join(columns) + ' FROM ' + table)})
            finally:
                c.close()
        left, right = datasets
        report[table] = {'only_left': list(left.keys() - right.keys()), 'only_right': list(right.keys() - left.keys()),
                         'changed': [key for key in left.keys() & right.keys() if left[key] != right[key]]}
    return report
