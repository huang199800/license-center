"""Python reference SDK. Trust is configured out-of-band; no automatic JWKS download."""
import base64
import hashlib
import json
import os
import random
import tempfile
import threading
import time
import uuid
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class LicenseError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _decode(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def verify_token(token, *, keys, issuer, product, instance, now=None):
    now = int(time.time()) if now is None else now
    try:
        if not isinstance(token, str) or len(token) > 65536:
            raise ValueError('size')
        head, body, sig = token.split('.')
        h = json.loads(_decode(head), object_pairs_hook=_object)
        if set(h) != {'alg', 'typ', 'kid'} or h['alg'] != 'EdDSA' or h['typ'] != 'JWT':
            raise LicenseError('TOKEN_ALGORITHM')
        if h['kid'] not in keys:
            raise LicenseError('TOKEN_UNKNOWN_KEY')
        Ed25519PublicKey.from_public_bytes(_decode(keys[h['kid']])).verify(_decode(sig), f'{head}.{body}'.encode())
        p = json.loads(_decode(body), object_pairs_hook=_object)
        required = {'iss', 'aud', 'sub', 'act', 'inst', 'features', 'quotas', 'iat', 'nbf', 'exp',
                    'license_exp', 'perpetual', 'jti', 'ver', 'status', 'policy'}
        if not required <= p.keys():
            raise ValueError('missing claims')
        if any(type(p[k]) is not int for k in ['iat', 'nbf', 'exp', 'ver']):
            raise ValueError('time types')
        if any(not isinstance(p[k], str) or not p[k] for k in ['iss', 'aud', 'sub', 'act', 'inst', 'jti']):
            raise ValueError('identity types')
        if p['iss'] != issuer or p['aud'] != product:
            raise LicenseError('TOKEN_AUDIENCE')
        if p['inst'] != hashlib.sha256(instance.encode()).hexdigest():
            raise LicenseError('TOKEN_INSTANCE')
        if not p['iat'] <= p['nbf'] < p['exp'] or p['iat'] > now or p['nbf'] > now:
            raise LicenseError('TOKEN_TIME_INVALID')
        if type(p['perpetual']) is not bool or p['status'] != 'active' or p['policy'] not in ['periodic', 'online', 'offline']:
            raise ValueError('status rules')
        if p['perpetual']:
            if p['license_exp'] is not None:
                raise ValueError('perpetual expiry')
        else:
            if type(p['license_exp']) is not int or p['exp'] > p['license_exp']:
                raise ValueError('license expiry')
            if now >= p['license_exp']:
                raise LicenseError('LICENSE_EXPIRED')
        if now >= p['exp']:
            raise LicenseError('TOKEN_EXPIRED')
        if not isinstance(p['features'], list) or any(not isinstance(x, str) for x in p['features']):
            raise ValueError('features')
        if not isinstance(p['quotas'], dict) or any(type(v) is not int or v < 0 for v in p['quotas'].values()):
            raise ValueError('quotas')
        return p
    except LicenseError:
        raise
    except Exception as exc:
        raise LicenseError('TOKEN_INVALID') from exc


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.license-')
    try:
        if os.name != 'nt':
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(value, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


class LicenseClient:
    def __init__(self, url, product, issuer, keys, cache, *, allow_http=False, transport=None, timeout=5):
        if not url.startswith('https://') and not (allow_http and url.startswith('http://')):
            raise ValueError('HTTPS required; allow_http is for development only')
        self.url, self.product, self.issuer, self.keys = url.rstrip('/'), product, issuer, keys
        self.cache = Path(cache)
        self.http = httpx.Client(timeout=timeout, transport=transport, follow_redirects=False, trust_env=False)
        self.data = {}
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.thread = None
        self.wall, self.mono = time.time(), time.monotonic()

    def _time(self):
        current = time.time()
        expected = self.wall + (time.monotonic() - self.mono)
        if current < expected - 5 or current < self.data.get('seen_time', 0) - 5:
            raise LicenseError('CLOCK_ROLLBACK')
        self.data['seen_time'] = max(current, self.data.get('seen_time', 0))
        return int(current)

    def initialize(self, instance=None):
        with self.lock:
            if self.cache.exists():
                try:
                    self.data = json.loads(self.cache.read_text(encoding='utf-8'))
                except Exception as exc:
                    raise LicenseError('CACHE_INVALID') from exc
                if self.data.get('product') != self.product or self.data.get('issuer') != self.issuer:
                    raise LicenseError('CACHE_SCOPE')
                if instance and instance != self.data['instance']:
                    raise LicenseError('CACHE_INSTANCE')
                if 'token' in self.data:
                    try:
                        self._claims()
                    except LicenseError as exc:
                        if exc.code not in ['TOKEN_EXPIRED', 'LICENSE_EXPIRED']:
                            raise
            else:
                self.data = {'product': self.product, 'issuer': self.issuer, 'instance': instance or str(uuid.uuid4())}
                self._save()
        return self

    def _save(self):
        atomic_json(self.cache, self.data)

    def _claims(self):
        return verify_token(self.data.get('token', ''), keys=self.keys, issuer=self.issuer, product=self.product,
                            instance=self.data['instance'], now=self._time())

    def _call(self, endpoint, body, secret=None, key=None):
        headers = {}
        if secret:
            headers['Authorization'] = 'Bearer ' + secret
        if key:
            headers['Idempotency-Key'] = key
        try:
            response = self.http.post(self.url + '/v1/' + endpoint, json=body, headers=headers)
        except httpx.TransportError as exc:
            raise LicenseError('NETWORK_UNAVAILABLE') from exc
        if response.status_code >= 500:
            raise LicenseError('CENTER_UNAVAILABLE')
        if response.status_code == 429:
            raise LicenseError('RATE_LIMIT')
        try:
            result = response.json()
        except Exception as exc:
            raise LicenseError('PROTOCOL_INVALID') from exc
        if response.status_code >= 400:
            code = result.get('error', {}).get('code', 'REQUEST_INVALID')
            if code in ['LICENSE_REVOKED', 'LICENSE_PAUSED', 'ACTIVATION_AUTH_FAILED', 'LICENSE_EXPIRED']:
                self.data.pop('token', None)
                self._save()
            raise LicenseError(code)
        return result

    def _accept(self, response):
        try:
            p = verify_token(response['token'], keys=self.keys, issuer=self.issuer, product=self.product,
                             instance=self.data['instance'], now=self._time())
            interval = response.get('refresh_interval', 300)
            if type(interval) is not int or interval < 1 or interval > 86400:
                raise LicenseError('PROTOCOL_INVALID')
            for field, claim in [('license_id', 'sub'), ('activation_id', 'act')]:
                if field in response and response[field] != p[claim]:
                    raise LicenseError('PROTOCOL_INVALID')
            for field in ['license_secret', 'activation_secret']:
                if field in response and (not isinstance(response[field], str) or not 32 <= len(response[field]) <= 200):
                    raise LicenseError('PROTOCOL_INVALID')
        except Exception as exc:
            self.data.pop('token', None)
            self._save()
            if isinstance(exc, LicenseError):
                raise
            raise LicenseError('PROTOCOL_INVALID') from exc
        # Only accept expected fields. Signed identity/time claims take precedence over metadata.
        for field in ['token', 'license_secret', 'activation_secret']:
            if field in response:
                self.data[field] = response[field]
        self.data.update(license_id=p['sub'], activation_id=p['act'], expires_at=p['exp'], refresh_interval=interval)
        self.data['seen_time'] = max(self.data.get('seen_time', 0), p['iat'])
        self._save()
        return self.getLicenseStatus()

    def activate(self, code, customer, *, idempotency_key=None):
        with self.lock:
            # Persist request key before sending so timeout/restart retries do not create a second entitlement.
            request = {'product': self.product, 'code': code, 'customer': customer, 'instance': self.data['instance']}
            fingerprint = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
            if self.data.get('pending_fingerprint') != fingerprint:
                self.data['pending_key'] = idempotency_key or str(uuid.uuid4())
                self.data['pending_fingerprint'] = fingerprint
                self._save()
            response = self._call('redeem', request, key=self.data['pending_key'])
            result = self._accept(response)
            self.data.pop('pending_key', None)
            self.data.pop('pending_fingerprint', None)
            self._save()
            return result

    def activate_existing(self, license_id, license_secret, *, idempotency_key):
        with self.lock:
            response = self._call('activate', {'product': self.product, 'license_id': license_id, 'instance': self.data['instance']},
                                  license_secret, idempotency_key)
            self.data['license_secret'] = license_secret
            return self._accept(response)

    def installOffline(self, license_file):
        with self.lock:
            try:
                response = json.loads(Path(license_file).read_text(encoding='utf-8'))
                p = verify_token(response['token'], keys=self.keys, issuer=self.issuer, product=self.product,
                                 instance=self.data['instance'], now=self._time())
                if p['policy'] != 'offline':
                    raise LicenseError('OFFLINE_POLICY_REQUIRED')
                self.data.pop('activation_secret', None)
                self.data.pop('license_secret', None)
                return self._accept(response)
            except LicenseError:
                raise
            except Exception as exc:
                raise LicenseError('OFFLINE_FILE_INVALID') from exc

    def refresh(self):
        with self.lock:
            if not self.data.get('activation_secret'):
                raise LicenseError('NOT_ACTIVATED')
            response = self._call('refresh', {'product': self.product, 'activation_id': self.data['activation_id']}, self.data['activation_secret'])
            return self._accept(response)

    def renew(self, code, *, idempotency_key):
        with self.lock:
            result = self._call('renew', {'product': self.product, 'license_id': self.data['license_id'], 'code': code},
                                self.data['license_secret'], idempotency_key)
            self.refresh()
            return result

    def getLicenseStatus(self):
        with self.lock:
            if not self.data.get('token'):
                return {'status': 'not_activated'}
            try:
                p = self._claims()
                return {'status': 'active', 'license_id': p['sub'], 'expires_at': p['license_exp'],
                        'credential_expires_at': p['exp'], 'perpetual': p['perpetual'], 'features': p['features'], 'quotas': p['quotas']}
            except LicenseError as exc:
                return {'status': 'denied', 'error': exc.code}

    def _authorize(self):
        p = self._claims()
        if p['policy'] == 'online':
            result = self._call('check', {'product': self.product, 'activation_id': self.data['activation_id']}, self.data['activation_secret'])
            if 'token' in result:
                self._accept(result)
                p = self._claims()
            if result.get('version', p['ver']) != p['ver']:
                self.refresh()
                p = self._claims()
        return p

    def requireFeature(self, feature):
        with self.lock:
            if feature not in self._authorize()['features']:
                raise LicenseError('FEATURE_DENIED')
            return True

    def checkQuota(self, name, current, additional=1):
        with self.lock:
            if type(current) is not int or type(additional) is not int or min(current, additional) < 0:
                raise ValueError('quota inputs must be non-negative integers')
            limit = self._authorize()['quotas'].get(name)
            if limit is None or current + additional > limit:
                raise LicenseError('QUOTA_EXCEEDED')
            return True

    def deactivate(self):
        with self.lock:
            result = self._call('deactivate', {'product': self.product, 'activation_id': self.data['activation_id']}, self.data['activation_secret'])
            self.data.pop('token', None)
            self.data.pop('activation_secret', None)
            self._save()
            return result

    def start_background_refresh(self):
        if self.data.get('token'):
            try:
                if self._claims()['policy'] == 'offline':
                    return
            except LicenseError as exc:
                if exc.code not in ['TOKEN_EXPIRED', 'LICENSE_EXPIRED']:
                    raise
        if self.thread and self.thread.is_alive():
            return
        self.stop.clear()
        def loop():
            failures = 0
            while not self.stop.wait(random.uniform(.8, 1.2) * (min(60, 2**min(failures, 6)) if failures else self.data.get('refresh_interval', 300))):
                try:
                    self.refresh()
                    failures = 0
                except LicenseError as exc:
                    failures += 1
                    # Only transport/service/rate failures may continue with an already valid credential.
                    if exc.code not in ['NETWORK_UNAVAILABLE', 'CENTER_UNAVAILABLE', 'RATE_LIMIT']:
                        with self.lock:
                            self.data.pop('token', None)
                            self._save()
                        return
        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=6)
        self.http.close()
