CREATE TABLE products(id TEXT PRIMARY KEY, name TEXT NOT NULL, version TEXT NOT NULL);
CREATE TABLE plans(id TEXT PRIMARY KEY, product TEXT NOT NULL REFERENCES products(id), spec TEXT NOT NULL);
CREATE TABLE codes(id TEXT PRIMARY KEY, digest TEXT UNIQUE NOT NULL, prefix TEXT NOT NULL,
 product TEXT NOT NULL REFERENCES products(id), snapshot TEXT NOT NULL, kind TEXT NOT NULL,
 max_uses INTEGER NOT NULL CHECK(max_uses>0), uses INTEGER NOT NULL DEFAULT 0,
 redeem_before INTEGER, starts_at INTEGER, disabled INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL);
CREATE TABLE licenses(id TEXT PRIMARY KEY, product TEXT NOT NULL REFERENCES products(id), customer TEXT NOT NULL,
 secret_hash TEXT NOT NULL, snapshot TEXT NOT NULL, status TEXT NOT NULL, starts_at INTEGER NOT NULL,
 expires_at INTEGER, perpetual INTEGER NOT NULL, version INTEGER NOT NULL DEFAULT 1,
 rebind_count INTEGER NOT NULL DEFAULT 0, last_unbind INTEGER NOT NULL DEFAULT 0,
 upgrade_until INTEGER, support_until INTEGER);
CREATE TABLE instances(id TEXT PRIMARY KEY, license TEXT NOT NULL REFERENCES licenses(id),
 instance_hash TEXT NOT NULL, secret_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
 created_at INTEGER NOT NULL, lease_until INTEGER NOT NULL, token_until INTEGER NOT NULL,
 UNIQUE(license,instance_hash));
CREATE TABLE idempotency(scope TEXT NOT NULL, key TEXT NOT NULL, request_hash TEXT NOT NULL,
 response TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY(scope,key));
CREATE TABLE redemptions(id INTEGER PRIMARY KEY, code TEXT NOT NULL REFERENCES codes(id),
 license TEXT NOT NULL REFERENCES licenses(id), at INTEGER NOT NULL, kind TEXT NOT NULL);
CREATE TABLE admins(username TEXT PRIMARY KEY, password TEXT NOT NULL, totp TEXT NOT NULL,
 role TEXT NOT NULL, products TEXT NOT NULL, last_counter INTEGER NOT NULL DEFAULT -1);
CREATE TABLE sessions(digest TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES admins(username),
 expires_at INTEGER NOT NULL, reauth_at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE audit(id INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
 product TEXT, target TEXT, detail TEXT NOT NULL);
CREATE TABLE rate_limits(bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, window INTEGER NOT NULL);
CREATE INDEX instances_license ON instances(license,active,lease_until);
CREATE INDEX licenses_product ON licenses(product,status);
CREATE INDEX codes_product ON codes(product);
CREATE INDEX audit_product ON audit(product,id);
