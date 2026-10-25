import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { LicenseClient, verifyToken } from "./client.mjs";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const keys = {
  key: publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("base64url"),
};
const now = Math.floor(Date.now() / 1000),
  instance = "stable-instance-0001";
const options = { keys, issuer: "urn:test", product: "demo", instance, now };
const claims = {
  iss: "urn:test",
  aud: "demo",
  sub: "license",
  act: "activation",
  inst: createHash("sha256").update(instance).digest("hex"),
  features: ["basic"],
  quotas: { users: 2 },
  iat: now,
  nbf: now,
  exp: now + 900,
  license_exp: now + 86400,
  perpetual: false,
  jti: "jti",
  ver: 1,
  status: "active",
  policy: "periodic",
};
function token(p = claims, h = { alg: "EdDSA", typ: "JWT", kid: "key" }) {
  const msg =
    Buffer.from(JSON.stringify(h)).toString("base64url") +
    "." +
    Buffer.from(JSON.stringify(p)).toString("base64url");
  return (
    msg + "." + sign(null, Buffer.from(msg), privateKey).toString("base64url")
  );
}
test("valid Ed25519 credential", () =>
  assert.equal(verifyToken(token(), options).sub, "license"));
for (const [name, change, code] of [
  ["product", { aud: "other" }, "TOKEN_AUDIENCE"],
  ["instance", { inst: "bad" }, "TOKEN_INSTANCE"],
  ["expiry", { exp: now - 1 }, "TOKEN_TIME_INVALID"],
  ["future", { nbf: now + 10 }, "TOKEN_TIME_INVALID"],
  ["type", { iat: "today" }, "TOKEN_INVALID"],
  ["perpetual", { perpetual: true }, "TOKEN_INVALID"],
  ["quota", { quotas: { users: -1 } }, "TOKEN_INVALID"],
])
  test("reject " + name, () =>
    assert.throws(() => verifyToken(token({ ...claims, ...change }), options), {
      code,
    }),
  );
test("unknown key", () =>
  assert.throws(
    () =>
      verifyToken(
        token(claims, { alg: "EdDSA", typ: "JWT", kid: "unknown" }),
        options,
      ),
    { code: "TOKEN_UNKNOWN_KEY" },
  ));
test("no algorithm confusion", () =>
  assert.throws(
    () =>
      verifyToken(
        token(claims, { alg: "HS256", typ: "JWT", kid: "key" }),
        options,
      ),
    { code: "TOKEN_ALGORITHM" },
  ));
test("no key URL trust", () =>
  assert.throws(
    () =>
      verifyToken(
        token(claims, {
          alg: "EdDSA",
          typ: "JWT",
          kid: "key",
          jku: "https://attacker.invalid",
        }),
        options,
      ),
    { code: "TOKEN_ALGORITHM" },
  ));
test("signature tamper", () => {
  const parts = token().split(".");
  parts[1] = Buffer.from(
    JSON.stringify({ ...claims, features: ["all"] }),
  ).toString("base64url");
  assert.throws(() => verifyToken(parts.join("."), options), {
    code: "TOKEN_INVALID",
  });
});
test("expired token", () =>
  assert.throws(() => verifyToken(token(), { ...options, now: now + 901 }), {
    code: "TOKEN_EXPIRED",
  }));
test("SDK cache, offline file, feature and quota", async () => {
  const dir = mkdtempSync(join(tmpdir(), "lc-node-"));
  try {
    const c = new LicenseClient({
      url: "https://unused.invalid",
      product: "demo",
      issuer: "urn:test",
      keys,
      cache: join(dir, "cache.json"),
    }).initialize(instance);
    const file = join(dir, "offline.json");
    writeFileSync(
      file,
      JSON.stringify({
        token: token({ ...claims, policy: "offline" }),
        server_time: now,
      }),
    );
    assert.equal(c.installOffline(file).status, "active");
    assert.equal(await c.requireFeature("basic"), true);
    await assert.rejects(() => c.requireFeature("other"), {
      code: "FEATURE_DENIED",
    });
    assert.equal(await c.checkQuota("users", 1), true);
    await assert.rejects(() => c.checkQuota("users", 2), {
      code: "QUOTA_EXCEEDED",
    });
    c.data.seen_time = now + 100;
    await assert.rejects(() => c.requireFeature("basic"), {
      code: "CLOCK_ROLLBACK",
    });
    c.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
test("signed identities override untrusted response metadata", () => {
  const dir = mkdtempSync(join(tmpdir(), "lc-node-"));
  try {
    const c = new LicenseClient({
      url: "https://unused.invalid",
      product: "demo",
      issuer: "urn:test",
      keys,
      cache: join(dir, "cache.json"),
    }).initialize(instance);
    c.accept({
      token: token(),
      instance: "evil",
      product: "evil",
      server_time: 9999999999,
    });
    assert.equal(c.data.instance, instance);
    assert.equal(c.data.product, "demo");
    assert.ok(c.data.seen_time < 9999999999);
    assert.throws(() => c.accept({ token: "bad" }));
    assert.equal(c.getLicenseStatus().status, "not_activated");
    c.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
