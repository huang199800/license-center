import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from pathlib import Path

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from .db import audit, connect, dump, transaction
from .models import Activate, CodeBatch, Login, OfflineIssue, Plan, Product, Reauth, Redeem, Refresh, Renew, Status
from .security import Vault, check_totp, password_check, sha

log = logging.getLogger('license-center')


class Fault(Exception):
    def __init__(self, code, status=403):
        self.code, self.status = code, status


def fail(code, status=403):
    raise Fault(code, status)


def bearer(value):
    if not value or not value.startswith('Bearer ') or len(value) > 300:
        fail('AUTH_REQUIRED', 401)
    return value[7:]


def create_app(data_dir=None, clock=None):
    root = Path(data_dir or os.environ.get('LC_DATA', 'data'))
    db = root / 'center.db'
    vault = Vault(root / 'vault.json')
    # Startup never silently creates an empty database after a failed mount.
    if not db.is_file():
        raise RuntimeError('Run python -m center.cli init first')
    with connect(db) as c:
        if c.execute('PRAGMA user_version').fetchone()[0] != 1:
            raise RuntimeError('SCHEMA_MISMATCH: run explicit migration')
    now = clock or (lambda: int(time.time()))
    app = FastAPI(title='通用授权中心', version='1.0.0', docs_url='/docs')
    app.state.db, app.state.vault, app.state.now = db, vault, now

    @app.exception_handler(Fault)
    async def fault_handler(request, exc):
        return JSONResponse({'error': {'code': exc.code}}, status_code=exc.status)

    @app.middleware('http')
    async def guard(request, call_next):
        started = time.monotonic()
        if request.url.path.startswith('/v1/'):
            # Uvicorn proxy headers are disabled in supplied launch commands.
            ip = request.client.host if request.client else 'unknown'
            category = 'admin' if request.url.path.startswith('/v1/admin') else 'public'
            bucket = sha(ip + category)
            with transaction(db) as c:
                window = now() // 60
                c.execute('INSERT INTO rate_limits VALUES(?,1,?) ON CONFLICT(bucket) DO UPDATE SET '
                          'count=CASE WHEN window=excluded.window THEN count+1 ELSE 1 END, window=excluded.window',
                          (bucket, window))
                count = c.execute('SELECT count FROM rate_limits WHERE bucket=?', (bucket,)).fetchone()[0]
                c.execute('DELETE FROM rate_limits WHERE window<?', (window - 2,))
            limit = 30 if request.url.path.endswith('/login') else (120 if category == 'admin' else 300)
            if count > limit:
                return JSONResponse({'error': {'code': 'RATE_LIMIT'}}, status_code=429, headers={'Retry-After': '60'})
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Frame-Options'] = 'DENY'
        if request.url.path == '/':
            response.headers['Content-Security-Policy'] = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        # No bodies, headers, tokens, or query strings in application logs.
        log.info(dump({'event': 'request', 'method': request.method, 'route': request.scope.get('route').path if request.scope.get('route') else 'unmatched',
                       'status': response.status_code, 'ms': round((time.monotonic()-started)*1000, 2)}))
        return response

    def admin(authorization: str | None = Header(default=None)):
        token = bearer(authorization)
        with transaction(db) as c:
            row = c.execute('SELECT a.*,s.reauth_at,s.digest FROM sessions s JOIN admins a USING(username) '
                            'WHERE s.digest=? AND s.expires_at>?', (sha(token), now())).fetchone()
        if not row:
            fail('ADMIN_SESSION_EXPIRED', 401)
        return dict(row)

    def permitted(a, product=None, write=False, owner=False):
        if owner and a['role'] != 'owner':
            fail('ROLE_DENIED')
        if write and a['role'] == 'viewer':
            fail('ROLE_DENIED')
        if product and a['role'] != 'owner' and product not in json.loads(a['products']):
            fail('PRODUCT_DENIED')

    def step_up(c, a):
        row = c.execute('SELECT reauth_at FROM sessions WHERE digest=?', (a['digest'],)).fetchone()
        if not row or row[0] <= 0 or now() - row[0] > 120:
            fail('REAUTH_REQUIRED', 401)
        c.execute('UPDATE sessions SET reauth_at=0 WHERE digest=?', (a['digest'],))

    def get_license(c, lid, product, secret=None):
        lic = c.execute('SELECT * FROM licenses WHERE id=? AND product=?', (lid, product)).fetchone()
        if not lic or (secret is not None and not hmac.compare_digest(lic['secret_hash'], sha(secret))):
            fail('LICENSE_AUTH_FAILED', 401)
        return dict(lic)

    def usable(lic):
        if lic['status'] != 'active':
            fail('LICENSE_' + lic['status'].upper())
        if lic['starts_at'] > now():
            fail('LICENSE_NOT_YET_VALID')
        if not lic['perpetual'] and lic['expires_at'] <= now():
            fail('LICENSE_EXPIRED')

    def code_row(c, code, product, kind):
        row = c.execute('SELECT * FROM codes WHERE digest=? AND product=?', (vault.digest_code(code), product)).fetchone()
        if not row or row['disabled'] or row['kind'] not in kind:
            fail('CODE_INVALID', 400)
        if row['redeem_before'] is not None and row['redeem_before'] <= now():
            fail('CODE_REDEEM_EXPIRED', 400)
        if row['uses'] >= row['max_uses']:
            fail('CODE_EXHAUSTED', 409)
        return dict(row)

    def idem(c, scope, key, payload, operation):
        if not key or not 16 <= len(key) <= 128:
            fail('IDEMPOTENCY_KEY_REQUIRED', 400)
        digest = sha(dump(payload))
        row = c.execute('SELECT * FROM idempotency WHERE scope=? AND key=?', (scope, key)).fetchone()
        if row:
            if row['request_hash'] != digest:
                fail('IDEMPOTENCY_CONFLICT', 409)
            return vault.open(row['response'])
        result = operation()
        c.execute('INSERT INTO idempotency VALUES(?,?,?,?,?)', (scope, key, digest, vault.seal(result), now()))
        return result

    def credential(c, lic, activation):
        usable(lic)
        spec = json.loads(lic['snapshot'])
        if spec['policy'] == 'offline':
            fail('OFFLINE_REQUIRES_ADMIN_ISSUE')
        end = now() + spec['token_ttl']
        if not lic['perpetual']:
            end = min(end, lic['expires_at'])
        online = c.execute('SELECT count(*) FROM instances WHERE license=? AND id<>? AND lease_until>?',
                           (lic['id'], activation['id'], now())).fetchone()[0]
        if online >= spec['max_online']:
            fail('ONLINE_LIMIT', 409)
        # Lease and signed token expire together: a partition cannot free a slot early.
        c.execute('UPDATE instances SET lease_until=?,token_until=? WHERE id=?', (end, end, activation['id']))
        claims = {'iss': vault.data['issuer'], 'aud': lic['product'], 'sub': lic['id'], 'act': activation['id'],
                  'inst': activation['instance_hash'], 'features': spec['features'], 'quotas': spec['quotas'],
                  'iat': now(), 'nbf': now(), 'exp': end, 'license_exp': lic['expires_at'],
                  'perpetual': bool(lic['perpetual']), 'jti': secrets.token_hex(16), 'ver': lic['version'],
                  'status': 'active', 'policy': spec['policy'], 'upgrade_until': lic['upgrade_until'],
                  'support_until': lic['support_until']}
        return {'token': vault.sign(claims), 'expires_at': end, 'server_time': now(),
                'refresh_interval': spec['refresh_interval'], 'license_id': lic['id'], 'activation_id': activation['id']}

    def activate_instance(c, lic, instance):
        usable(lic)
        spec = json.loads(lic['snapshot'])
        hashed = sha(instance)
        existing = c.execute('SELECT * FROM instances WHERE license=? AND instance_hash=?', (lic['id'], hashed)).fetchone()
        if existing and existing['active']:
            fail('INSTANCE_ALREADY_ACTIVE_USE_SAVED_CREDENTIALS', 409)
        occupied = c.execute('SELECT count(*) FROM instances WHERE license=? AND (active=1 OR token_until>?)',
                             (lic['id'], now())).fetchone()[0]
        if occupied >= spec['max_devices']:
            fail('DEVICE_LIMIT', 409)
        if lic['last_unbind'] and now() < lic['last_unbind'] + spec['rebind_cooldown']:
            fail('REBIND_COOLDOWN', 409)
        secret = secrets.token_urlsafe(32)
        aid = existing['id'] if existing else secrets.token_hex(16)
        if existing:
            c.execute('UPDATE instances SET active=1,secret_hash=?,lease_until=0,token_until=0 WHERE id=?', (sha(secret), aid))
        else:
            c.execute('INSERT INTO instances VALUES(?,?,?,?,1,?,0,0)', (aid, lic['id'], hashed, sha(secret), now()))
        result = credential(c, lic, {'id': aid, 'instance_hash': hashed})
        result['activation_secret'] = secret
        audit(c, now(), lic['id'], 'instance.activate', lic['product'], aid)
        return result

    def instance_auth(c, body, authorization):
        row = c.execute('SELECT * FROM instances WHERE id=? AND active=1', (body.activation_id,)).fetchone()
        if not row or not hmac.compare_digest(row['secret_hash'], sha(bearer(authorization))):
            fail('ACTIVATION_AUTH_FAILED', 401)
        lic = get_license(c, row['license'], body.product)
        return dict(row), lic

    @app.get('/health/live')
    def live():
        return {'status': 'ok'}

    @app.get('/health/ready')
    def ready():
        with transaction(db) as c:
            c.execute('SELECT 1 FROM products LIMIT 1')
        return {'status': 'ready', 'schema': 1}

    @app.get('/v1/public-keys')
    def public_keys():
        return {'issuer': vault.data['issuer'], 'keys': vault.public(), 'active': vault.data['active']}

    @app.post('/v1/redeem')
    def redeem(body: Redeem, idempotency_key: str | None = Header(default=None)):
        with transaction(db) as c:
            def op():
                code = code_row(c, body.code, body.product, ['new'])
                spec = json.loads(code['snapshot'])
                start = code['starts_at'] if code['starts_at'] is not None else now()
                # A future administrative start is allowed, but no credential is issued early.
                if start > now():
                    fail('LICENSE_NOT_YET_VALID')
                lid, secret = secrets.token_hex(16), secrets.token_urlsafe(32)
                expiry = None if spec['perpetual'] else start + spec['days'] * 86400
                upgrade = start + spec['upgrade_days']*86400 if spec['upgrade_days'] else None
                support = start + spec['support_days']*86400 if spec['support_days'] else None
                c.execute('INSERT INTO licenses(id,product,customer,secret_hash,snapshot,status,starts_at,expires_at,perpetual,upgrade_until,support_until) '
                          'VALUES(?,?,?,?,?,\'active\',?,?,?,?,?)',
                          (lid, body.product, body.customer, sha(secret), code['snapshot'], start, expiry, int(spec['perpetual']), upgrade, support))
                lic = get_license(c, lid, body.product)
                result = activate_instance(c, lic, body.instance)
                c.execute('UPDATE codes SET uses=uses+1 WHERE id=?', (code['id'],))
                c.execute('INSERT INTO redemptions(code,license,at,kind) VALUES(?,?,?,?)', (code['id'], lid, now(), 'new'))
                audit(c, now(), lid, 'code.redeem', body.product, code['id'])
                return {**result, 'license_secret': secret}
            return idem(c, 'redeem:' + vault.digest_code(body.code), idempotency_key, body.model_dump(), op)

    @app.post('/v1/activate')
    def activate(body: Activate, authorization: str | None = Header(default=None), idempotency_key: str | None = Header(default=None)):
        secret = bearer(authorization)
        with transaction(db) as c:
            lic = get_license(c, body.license_id, body.product, secret)
            usable(lic)
            return idem(c, 'activate:' + sha(secret), idempotency_key, body.model_dump(), lambda: activate_instance(c, lic, body.instance))

    @app.post('/v1/renew')
    def renew(body: Renew, authorization: str | None = Header(default=None), idempotency_key: str | None = Header(default=None)):
        secret = bearer(authorization)
        with transaction(db) as c:
            lic = get_license(c, body.license_id, body.product, secret)
            if lic['status'] != 'active':
                fail('LICENSE_' + lic['status'].upper())
            def op():
                code = code_row(c, body.code, body.product, ['renew', 'upgrade'])
                spec, old = json.loads(code['snapshot']), json.loads(lic['snapshot'])
                if code['kind'] == 'renew':
                    if lic['perpetual'] and not spec['perpetual']:
                        fail('PERPETUAL_CANNOT_DOWNGRADE', 400)
                    expiry = None if spec['perpetual'] else max(lic['expires_at'], now()) + spec['days']*86400
                    # Renewal changes duration only, never silently removes existing features/binding policy.
                    old['perpetual'], old['days'] = spec['perpetual'], spec['days']
                    c.execute('UPDATE licenses SET expires_at=?,perpetual=?,snapshot=?,version=version+1 WHERE id=?',
                              (expiry, int(spec['perpetual']), dump(old), lic['id']))
                else:
                    old['features'] = sorted(set(old['features'] + spec['features']))
                    for k, v in spec['quotas'].items():
                        old['quotas'][k] = max(old['quotas'].get(k, 0), v)
                    c.execute('UPDATE licenses SET snapshot=?,version=version+1 WHERE id=?', (dump(old), lic['id']))
                c.execute('UPDATE codes SET uses=uses+1 WHERE id=?', (code['id'],))
                c.execute('INSERT INTO redemptions(code,license,at,kind) VALUES(?,?,?,?)', (code['id'], lic['id'], now(), code['kind']))
                audit(c, now(), lic['id'], 'license.' + code['kind'], body.product, code['id'])
                updated = get_license(c, lic['id'], body.product)
                return {'license_id': lic['id'], 'expires_at': updated['expires_at'], 'perpetual': bool(updated['perpetual']), 'version': updated['version']}
            return idem(c, 'renew:' + sha(secret), idempotency_key, body.model_dump(), op)

    @app.post('/v1/refresh')
    def refresh(body: Refresh, authorization: str | None = Header(default=None)):
        with transaction(db) as c:
            inst, lic = instance_auth(c, body, authorization)
            return credential(c, lic, inst)

    @app.post('/v1/check')
    def online_check(body: Refresh, authorization: str | None = Header(default=None)):
        # Strict-online callers must invoke on each protected operation. No offline fallback.
        with transaction(db) as c:
            inst, lic = instance_auth(c, body, authorization)
            usable(lic)
            if inst['lease_until'] <= now():
                return credential(c, lic, inst)
            return {'status': 'active', 'version': lic['version'], 'server_time': now()}

    @app.post('/v1/deactivate')
    def deactivate(body: Refresh, authorization: str | None = Header(default=None)):
        with transaction(db) as c:
            inst, lic = instance_auth(c, body, authorization)
            spec = json.loads(lic['snapshot'])
            if lic['rebind_count'] >= spec['rebind_limit']:
                fail('REBIND_LIMIT')
            c.execute('UPDATE instances SET active=0 WHERE id=?', (inst['id'],))
            c.execute('UPDATE licenses SET rebind_count=rebind_count+1,last_unbind=? WHERE id=?', (now(), lic['id']))
            audit(c, now(), lic['id'], 'instance.deactivate', lic['product'], inst['id'])
            return {'status': 'deactivated', 'old_credential_valid_until': inst['token_until'],
                    'new_binding_not_before': max(inst['token_until'], now()+spec['rebind_cooldown'])}

    @app.post('/v1/admin/login')
    def login(body: Login):
        with transaction(db) as c:
            a = c.execute('SELECT * FROM admins WHERE username=?', (body.username,)).fetchone()
            if not a or not password_check(body.password, a['password']):
                # Same expensive hash for unknown names to reduce username timing disclosure.
                if not a:
                    password_check(body.password, 'AAAAAAAAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
                audit(c, now(), 'anonymous', 'admin.login_failed')
                # Commit failure audit before returning (raising would roll it back).
                return JSONResponse({'error': {'code': 'ADMIN_AUTH_FAILED'}}, status_code=401)
            counter = check_totp(vault.open(a['totp']), body.otp, now(), a['last_counter'])
            if counter is None:
                audit(c, now(), body.username, 'admin.login_failed')
                return JSONResponse({'error': {'code': 'ADMIN_AUTH_FAILED'}}, status_code=401)
            token = secrets.token_urlsafe(32)
            c.execute('UPDATE admins SET last_counter=? WHERE username=?', (counter, body.username))
            c.execute('DELETE FROM sessions WHERE expires_at<=?', (now(),))
            c.execute('INSERT INTO sessions VALUES(?,?,?,0)', (sha(token), body.username, now()+3600))
            audit(c, now(), body.username, 'admin.login')
            return {'access_token': token, 'expires_in': 3600, 'role': a['role']}

    @app.post('/v1/admin/reauth')
    def reauth(body: Reauth, a=Depends(admin)):
        with transaction(db) as c:
            current = c.execute('SELECT * FROM admins WHERE username=?', (a['username'],)).fetchone()
            counter = check_totp(vault.open(current['totp']), body.otp, now(), current['last_counter'])
            if counter is None:
                fail('OTP_INVALID_OR_REPLAYED', 401)
            c.execute('UPDATE admins SET last_counter=? WHERE username=?', (counter, a['username']))
            c.execute('UPDATE sessions SET reauth_at=? WHERE digest=?', (now(), a['digest']))
            audit(c, now(), a['username'], 'admin.reauth')
        return {'valid_for_seconds': 120, 'uses': 1}

    @app.post('/v1/admin/logout')
    def logout(a=Depends(admin)):
        with transaction(db) as c:
            c.execute('DELETE FROM sessions WHERE digest=?', (a['digest'],))
        return {'status': 'ok'}

    @app.post('/v1/admin/products')
    def product(body: Product, a=Depends(admin)):
        permitted(a, owner=True)
        with transaction(db) as c:
            c.execute('INSERT INTO products VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,version=excluded.version',
                      (body.id, body.name, body.version))
            audit(c, now(), a['username'], 'product.save', body.id, body.id)
        return body

    @app.post('/v1/admin/plans')
    def plan(body: Plan, a=Depends(admin)):
        permitted(a, body.product, write=True)
        with transaction(db) as c:
            existing = c.execute('SELECT product FROM plans WHERE id=?', (body.id,)).fetchone()
            if existing and existing[0] != body.product:
                fail('PLAN_PRODUCT_IMMUTABLE', 409)
            if not c.execute('SELECT 1 FROM products WHERE id=?', (body.product,)).fetchone():
                fail('PRODUCT_NOT_FOUND', 404)
            c.execute('INSERT INTO plans VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET spec=excluded.spec', (body.id, body.product, dump(body.model_dump())))
            audit(c, now(), a['username'], 'plan.save', body.product, body.id)
        return body

    @app.post('/v1/admin/codes')
    def codes(body: CodeBatch, a=Depends(admin)):
        with transaction(db) as c:
            plan = c.execute('SELECT * FROM plans WHERE id=?', (body.plan,)).fetchone()
            if not plan:
                fail('PLAN_NOT_FOUND', 404)
            permitted(a, plan['product'], write=True)
            step_up(c, a)
            if json.loads(plan['spec'])['policy'] == 'offline':
                fail('OFFLINE_CODE_NOT_SUPPORTED', 400)
            results = []
            for _ in range(body.count):
                code = 'LC1-' + secrets.token_urlsafe(24)
                cid = secrets.token_hex(16)
                c.execute('INSERT INTO codes(id,digest,prefix,product,snapshot,kind,max_uses,redeem_before,starts_at,note) '
                          'VALUES(?,?,?,?,?,?,?,?,?,?)', (cid, vault.digest_code(code), code[:9], plan['product'], plan['spec'], body.kind,
                                                       body.max_uses, body.redeem_before, body.starts_at, body.note))
                results.append({'id': cid, 'code': code})
            audit(c, now(), a['username'], 'codes.generate_once', plan['product'], detail={'count': body.count, 'kind': body.kind})
            return {'delivery_once': results, 'warning': '完整兑换码只返回这一次，请立即安全交付。'}

    @app.post('/v1/admin/codes/{code_id}/disable')
    def disable_code(code_id: str, a=Depends(admin)):
        with transaction(db) as c:
            row = c.execute('SELECT product FROM codes WHERE id=?', (code_id,)).fetchone()
            if not row:
                fail('CODE_NOT_FOUND', 404)
            permitted(a, row[0], write=True)
            c.execute('UPDATE codes SET disabled=1 WHERE id=?', (code_id,))
            audit(c, now(), a['username'], 'code.disable', row[0], code_id)
        return {'status': 'disabled'}

    @app.post('/v1/admin/offline')
    def issue_offline(body: OfflineIssue, a=Depends(admin), idempotency_key: str | None = Header(default=None)):
        with transaction(db) as c:
            plan = c.execute('SELECT * FROM plans WHERE id=?', (body.plan,)).fetchone()
            if not plan:
                fail('PLAN_NOT_FOUND', 404)
            permitted(a, plan['product'], write=True)
            spec = json.loads(plan['spec'])
            if spec['policy'] != 'offline':
                fail('OFFLINE_PLAN_REQUIRED', 400)
            def op():
                step_up(c, a)
                lid, aid = secrets.token_hex(16), secrets.token_hex(16)
                expiry = None if spec['perpetual'] else now() + spec['days']*86400
                end = min(now()+spec['offline_max'], expiry) if expiry else now()+spec['offline_max']
                upgrade = now()+spec['upgrade_days']*86400 if spec['upgrade_days'] else None
                support = now()+spec['support_days']*86400 if spec['support_days'] else None
                # Offline delivery deliberately includes no API refresh credentials.
                c.execute('INSERT INTO licenses(id,product,customer,secret_hash,snapshot,status,starts_at,expires_at,perpetual,upgrade_until,support_until) '
                          'VALUES(?,?,?,?,?,\'active\',?,?,?,?,?)',
                          (lid, plan['product'], body.customer, sha(secrets.token_urlsafe(32)), plan['spec'], now(), expiry, int(spec['perpetual']), upgrade, support))
                c.execute('INSERT INTO instances VALUES(?,?,?,?,1,?,?,?)', (aid,lid,sha(body.instance),sha(secrets.token_urlsafe(32)),now(),end,end))
                token = vault.sign({'iss': vault.data['issuer'], 'aud':plan['product'], 'sub':lid, 'act':aid,
                                    'inst':sha(body.instance), 'features':spec['features'], 'quotas':spec['quotas'],
                                    'iat':now(), 'nbf':now(), 'exp':end, 'license_exp':expiry, 'perpetual':spec['perpetual'],
                                    'jti':secrets.token_hex(16), 'ver':1, 'status':'active', 'policy':'offline',
                                    'upgrade_until':upgrade,'support_until':support})
                audit(c,now(),a['username'],'offline.issue',plan['product'],lid,{'reason':body.reason,'credential_until':end})
                return {'token':token,'server_time':now(),'expires_at':end,'license_id':lid,'activation_id':aid,
                        'warning':'离线文件不能实时撤销、控制真实并发或抵抗本地管理员修改时间；到期后需重新采购或人工处置。'}
            return idem(c,'offline:'+a['username'],idempotency_key,body.model_dump(),op)

    @app.post('/v1/admin/licenses/{license_id}/status')
    def license_status(license_id: str, body: Status, a=Depends(admin)):
        with transaction(db) as c:
            row = c.execute('SELECT * FROM licenses WHERE id=?', (license_id,)).fetchone()
            if not row:
                fail('LICENSE_NOT_FOUND', 404)
            permitted(a, row['product'], write=True)
            step_up(c, a)
            c.execute('UPDATE licenses SET status=?,version=version+1 WHERE id=?', (body.status, license_id))
            bound = c.execute('SELECT max(token_until) FROM instances WHERE license=?', (license_id,)).fetchone()[0]
            audit(c, now(), a['username'], 'license.status', row['product'], license_id, {'from': row['status'], **body.model_dump()})
        return {'status': body.status, 'cached_credential_boundary': bound, 'pause_clock': 'continues'}

    @app.post('/v1/admin/instances/{activation_id}/release')
    def force_release(activation_id: str, body: Status, a=Depends(admin)):
        with transaction(db) as c:
            inst = c.execute('SELECT * FROM instances WHERE id=?', (activation_id,)).fetchone()
            if not inst:
                fail('INSTANCE_NOT_FOUND', 404)
            lic = c.execute('SELECT * FROM licenses WHERE id=?', (inst['license'],)).fetchone()
            permitted(a, lic['product'], write=True)
            step_up(c, a)
            c.execute('UPDATE instances SET active=0 WHERE id=?', (activation_id,))
            audit(c, now(), a['username'], 'instance.admin_release', lic['product'], activation_id, {'reason': body.reason})
        return {'status': 'released', 'old_credential_valid_until': inst['token_until']}

    @app.get('/v1/admin/inventory')
    def inventory(product: str | None = None, limit: int = 100, a=Depends(admin)):
        permitted(a, product)
        limit = min(max(limit, 1), 500)
        allowed = None if a['role'] == 'owner' else json.loads(a['products'])
        def filter_rows(rows):
            return [dict(r) for r in rows if (product is None or r['product'] == product) and (allowed is None or r['product'] in allowed)][:limit]
        with transaction(db) as c:
            # Product filtering is done in SQL for large license/code/audit tables.
            scope = [product] if product else allowed
            where = '' if scope is None else (' WHERE product IN (' + ','.join('?' for _ in scope) + ')' if scope else ' WHERE 0')
            args = scope or []
            products = [dict(r) for r in c.execute('SELECT * FROM products') if (not product or r['id'] == product) and (allowed is None or r['id'] in allowed)]
            plans = filter_rows(c.execute('SELECT * FROM plans'))
            licenses = [dict(r) for r in c.execute('SELECT id,product,customer,snapshot,status,starts_at,expires_at,perpetual,version,upgrade_until,support_until FROM licenses' + where + ' ORDER BY rowid DESC LIMIT ?', [*args, limit])]
            codes = [dict(r) for r in c.execute('SELECT id,prefix,product,kind,max_uses,uses,redeem_before,disabled,note FROM codes' + where + ' ORDER BY rowid DESC LIMIT ?', [*args, limit])]
            events = [dict(r) for r in c.execute('SELECT * FROM audit' + where + ' ORDER BY id DESC LIMIT ?', [*args, limit])]
            instances = [dict(r) for r in c.execute('SELECT i.id,i.license,l.product,i.active,i.created_at,i.lease_until,i.token_until FROM instances i JOIN licenses l ON l.id=i.license' + where.replace('product', 'l.product') + ' ORDER BY i.created_at DESC LIMIT ?', [*args, limit])]
        return {'products': products, 'plans': plans, 'licenses': licenses, 'codes': codes, 'instances': instances,
                'audit': events, 'keys': {'active': vault.data['active'], 'trusted_kids': list(vault.public())},
                'server_time': now(), 'limit': limit}

    @app.get('/v1/admin/metrics')
    def metrics(a=Depends(admin)):
        permitted(a, owner=True)
        with transaction(db) as c:
            leases = c.execute('SELECT count(*) FROM instances WHERE lease_until>?', (now(),)).fetchone()[0]
            licenses = c.execute('SELECT count(*) FROM licenses').fetchone()[0]
        return {'active_leases': leases, 'licenses': licenses, 'schema': 1}

    @app.get('/', response_class=HTMLResponse)
    def home():
        return (Path(__file__).parent / 'static/index.html').read_text(encoding='utf-8')

    @app.get('/admin.js')
    def js():
        return Response((Path(__file__).parent / 'static/admin.js').read_text(encoding='utf-8'), media_type='application/javascript')

    @app.get('/admin.css')
    def css():
        return Response((Path(__file__).parent / 'static/admin.css').read_text(encoding='utf-8'), media_type='text/css')

    return app
