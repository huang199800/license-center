import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def unb64(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def password_hash(value):
    salt = secrets.token_bytes(16)
    return b64(salt) + ':' + b64(hashlib.scrypt(value.encode(), salt=salt, n=16384, r=8, p=1))


def password_check(value, encoded):
    salt, expected = encoded.split(':')
    return hmac.compare_digest(b64(hashlib.scrypt(value.encode(), salt=unb64(salt), n=16384, r=8, p=1)), expected)


def totp(secret, counter=None):
    counter = int(time.time()) // 30 if counter is None else counter
    key = base64.b32decode(secret)
    mac = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = mac[-1] & 15
    return f'{(struct.unpack(">I", mac[offset:offset+4])[0] & 0x7fffffff) % 1000000:06d}'


def check_totp(secret, code, now, last):
    for counter in range(now // 30 - 1, now // 30 + 2):
        if counter > last and hmac.compare_digest(totp(secret, counter), code):
            return counter
    return None


def private_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(data)


class Vault:
    def __init__(self, path, use_env=True):
        self.path = Path(os.environ.get('LC_VAULT', path) if use_env else path)
        self.data = json.loads(self.path.read_text(encoding='utf-8'))
        self.fernet = Fernet(self.data['encryption_key'].encode())

    @staticmethod
    def create(path, issuer):
        path = os.environ.get('LC_VAULT', path)
        kid = secrets.token_hex(8)
        data = {'issuer': issuer, 'active': kid, 'code_pepper': secrets.token_hex(32),
                'encryption_key': Fernet.generate_key().decode(),
                'keys': {kid: b64(Ed25519PrivateKey.generate().private_bytes_raw())}}
        private_write(path, json.dumps(data, indent=2))
        return Vault(path)

    def digest_code(self, code):
        return hmac.new(bytes.fromhex(self.data['code_pepper']), code.encode(), hashlib.sha256).hexdigest()

    def seal(self, value):
        return self.fernet.encrypt(json.dumps(value).encode()).decode()

    def open(self, value):
        return json.loads(self.fernet.decrypt(value.encode()))

    def public(self):
        return {kid: b64(Ed25519PrivateKey.from_private_bytes(unb64(raw)).public_key().public_bytes_raw())
                for kid, raw in self.data['keys'].items()}

    def sign(self, claims):
        kid = self.data['active']
        head = b64(json.dumps({'alg': 'EdDSA', 'typ': 'JWT', 'kid': kid}, separators=(',', ':')).encode())
        body = b64(json.dumps(claims, separators=(',', ':')).encode())
        message = f'{head}.{body}'
        sig = Ed25519PrivateKey.from_private_bytes(unb64(self.data['keys'][kid])).sign(message.encode())
        return message + '.' + b64(sig)
