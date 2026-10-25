import {
  createHash,
  createPublicKey,
  verify,
  randomUUID,
  randomBytes,
} from "node:crypto";
import {
  readFileSync,
  writeFileSync,
  renameSync,
  mkdirSync,
  existsSync,
  unlinkSync,
} from "node:fs";
import { dirname } from "node:path";

export class LicenseError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}
const sha = (value) => createHash("sha256").update(value).digest("hex");
const decode = (s) => Buffer.from(s, "base64url");
const deny = (code) => {
  throw new LicenseError(code);
};

export function verifyToken(
  token,
  { keys, issuer, product, instance, now = Math.floor(Date.now() / 1000) },
) {
  try {
    if (typeof token !== "string" || token.length > 65536)
      deny("TOKEN_INVALID");
    const parts = token.split(".");
    if (parts.length !== 3) deny("TOKEN_INVALID");
    const [head, body, sig] = parts,
      h = JSON.parse(decode(head)),
      p = JSON.parse(decode(body));
    if (
      Object.keys(h).sort().join(",") !== "alg,kid,typ" ||
      h.alg !== "EdDSA" ||
      h.typ !== "JWT"
    )
      deny("TOKEN_ALGORITHM");
    if (!Object.hasOwn(keys, h.kid)) deny("TOKEN_UNKNOWN_KEY");
    const raw = decode(keys[h.kid]);
    if (raw.length !== 32) deny("TOKEN_INVALID");
    const key = createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]),
      type: "spki",
      format: "der",
    });
    if (!verify(null, Buffer.from(head + "." + body), key, decode(sig)))
      deny("TOKEN_INVALID");
    const required = [
      "iss",
      "aud",
      "sub",
      "act",
      "inst",
      "features",
      "quotas",
      "iat",
      "nbf",
      "exp",
      "license_exp",
      "perpetual",
      "jti",
      "ver",
      "status",
      "policy",
    ];
    if (required.some((k) => !Object.hasOwn(p, k))) deny("TOKEN_INVALID");
    if (
      ["iss", "aud", "sub", "act", "inst", "jti"].some(
        (k) => typeof p[k] !== "string" || !p[k],
      )
    )
      deny("TOKEN_INVALID");
    if (["iat", "nbf", "exp", "ver"].some((k) => !Number.isSafeInteger(p[k])))
      deny("TOKEN_INVALID");
    if (p.iss !== issuer || p.aud !== product) deny("TOKEN_AUDIENCE");
    if (p.inst !== sha(instance)) deny("TOKEN_INSTANCE");
    if (!(p.iat <= p.nbf && p.nbf < p.exp) || p.iat > now || p.nbf > now)
      deny("TOKEN_TIME_INVALID");
    if (
      typeof p.perpetual !== "boolean" ||
      p.status !== "active" ||
      !["periodic", "online", "offline"].includes(p.policy)
    )
      deny("TOKEN_INVALID");
    if (p.perpetual) {
      if (p.license_exp !== null) deny("TOKEN_INVALID");
    } else {
      if (!Number.isSafeInteger(p.license_exp) || p.exp > p.license_exp)
        deny("TOKEN_INVALID");
      if (now >= p.license_exp) deny("LICENSE_EXPIRED");
    }
    if (now >= p.exp) deny("TOKEN_EXPIRED");
    if (
      !Array.isArray(p.features) ||
      p.features.some((x) => typeof x !== "string")
    )
      deny("TOKEN_INVALID");
    if (
      !p.quotas ||
      typeof p.quotas !== "object" ||
      Array.isArray(p.quotas) ||
      Object.values(p.quotas).some((x) => !Number.isSafeInteger(x) || x < 0)
    )
      deny("TOKEN_INVALID");
    return p;
  } catch (e) {
    if (e instanceof LicenseError) throw e;
    deny("TOKEN_INVALID");
  }
}

function atomic(path, data) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = path + "." + randomBytes(8).toString("hex");
  try {
    writeFileSync(tmp, JSON.stringify(data), {
      mode: 0o600,
      flag: "wx",
      flush: true,
    });
    renameSync(tmp, path);
  } finally {
    if (existsSync(tmp)) unlinkSync(tmp);
  }
}

export class LicenseClient {
  constructor({
    url,
    product,
    issuer,
    keys,
    cache,
    allowHttp = false,
    timeout = 5000,
  }) {
    const u = new URL(url);
    if (u.protocol !== "https:" && !(allowHttp && u.protocol === "http:"))
      throw Error("HTTPS required");
    if (u.username || u.password || u.search || u.hash)
      throw Error("Invalid center URL");
    Object.assign(this, {
      url: url.replace(/\/$/, ""),
      product,
      issuer,
      keys,
      cache,
      timeout,
      data: {},
      wall: Date.now() / 1000,
      mono: process.hrtime.bigint(),
      timer: null,
      closed: false,
    });
  }
  initialize(instance) {
    if (existsSync(this.cache)) {
      try {
        this.data = JSON.parse(readFileSync(this.cache, "utf8"));
      } catch {
        deny("CACHE_INVALID");
      }
      if (
        this.data.product !== this.product ||
        this.data.issuer !== this.issuer
      )
        deny("CACHE_SCOPE");
      if (instance && instance !== this.data.instance) deny("CACHE_INSTANCE");
      if (this.data.token)
        try {
          this.claims();
        } catch (e) {
          if (!["TOKEN_EXPIRED", "LICENSE_EXPIRED"].includes(e.code)) throw e;
        }
    } else {
      this.data = {
        product: this.product,
        issuer: this.issuer,
        instance: instance || randomUUID(),
      };
      this.save();
    }
    return this;
  }
  save() {
    atomic(this.cache, this.data);
  }
  time() {
    const now = Date.now() / 1000,
      expected = this.wall + Number(process.hrtime.bigint() - this.mono) / 1e9;
    if (now < expected - 5 || now < (this.data.seen_time || 0) - 5)
      deny("CLOCK_ROLLBACK");
    this.data.seen_time = Math.max(now, this.data.seen_time || 0);
    return Math.floor(now);
  }
  claims() {
    return verifyToken(this.data.token, {
      keys: this.keys,
      issuer: this.issuer,
      product: this.product,
      instance: this.data.instance,
      now: this.time(),
    });
  }
  async call(endpoint, body, secret, key) {
    const headers = { "Content-Type": "application/json" };
    if (secret) headers.Authorization = "Bearer " + secret;
    if (key) headers["Idempotency-Key"] = key;
    let response;
    try {
      response = await fetch(this.url + "/v1/" + endpoint, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        redirect: "error",
        signal: AbortSignal.timeout(this.timeout),
      });
    } catch {
      deny("NETWORK_UNAVAILABLE");
    }
    if (response.status >= 500) deny("CENTER_UNAVAILABLE");
    if (response.status === 429) deny("RATE_LIMIT");
    let result;
    try {
      result = await response.json();
    } catch {
      deny("PROTOCOL_INVALID");
    }
    if (!response.ok) {
      const code = result.error?.code || "REQUEST_INVALID";
      if (
        [
          "LICENSE_REVOKED",
          "LICENSE_PAUSED",
          "ACTIVATION_AUTH_FAILED",
          "LICENSE_EXPIRED",
        ].includes(code)
      ) {
        delete this.data.token;
        this.save();
      }
      deny(code);
    }
    return result;
  }
  accept(r) {
    let p, interval;
    try {
      p = verifyToken(r.token, {
        keys: this.keys,
        issuer: this.issuer,
        product: this.product,
        instance: this.data.instance,
        now: this.time(),
      });
      interval = r.refresh_interval ?? 300;
      if (!Number.isSafeInteger(interval) || interval < 1 || interval > 86400)
        deny("PROTOCOL_INVALID");
      for (const [field, claim] of [
        ["license_id", "sub"],
        ["activation_id", "act"],
      ])
        if (Object.hasOwn(r, field) && r[field] !== p[claim])
          deny("PROTOCOL_INVALID");
      for (const field of ["license_secret", "activation_secret"])
        if (
          Object.hasOwn(r, field) &&
          (typeof r[field] !== "string" ||
            r[field].length < 32 ||
            r[field].length > 200)
        )
          deny("PROTOCOL_INVALID");
    } catch (e) {
      delete this.data.token;
      this.save();
      if (e instanceof LicenseError) throw e;
      deny("PROTOCOL_INVALID");
    }
    for (const field of ["token", "license_secret", "activation_secret"])
      if (Object.hasOwn(r, field)) this.data[field] = r[field];
    Object.assign(this.data, {
      license_id: p.sub,
      activation_id: p.act,
      expires_at: p.exp,
      refresh_interval: interval,
      seen_time: Math.max(this.data.seen_time || 0, p.iat),
    });
    this.save();
    return this.getLicenseStatus();
  }
  async activate(code, customer, { idempotencyKey } = {}) {
    const body = {
        product: this.product,
        code,
        customer,
        instance: this.data.instance,
      },
      fingerprint = sha(JSON.stringify(body));
    if (this.data.pending_fingerprint !== fingerprint) {
      this.data.pending_key = idempotencyKey || randomUUID();
      this.data.pending_fingerprint = fingerprint;
      this.save();
    }
    const result = this.accept(
      await this.call("redeem", body, undefined, this.data.pending_key),
    );
    delete this.data.pending_key;
    delete this.data.pending_fingerprint;
    this.save();
    return result;
  }
  async activateExisting(licenseId, licenseSecret, { idempotencyKey }) {
    const result = await this.call(
      "activate",
      {
        product: this.product,
        license_id: licenseId,
        instance: this.data.instance,
      },
      licenseSecret,
      idempotencyKey,
    );
    this.data.license_secret = licenseSecret;
    return this.accept(result);
  }
  async refresh() {
    if (!this.data.activation_secret) deny("NOT_ACTIVATED");
    return this.accept(
      await this.call(
        "refresh",
        { product: this.product, activation_id: this.data.activation_id },
        this.data.activation_secret,
      ),
    );
  }
  async renew(code, { idempotencyKey }) {
    const r = await this.call(
      "renew",
      { product: this.product, license_id: this.data.license_id, code },
      this.data.license_secret,
      idempotencyKey,
    );
    await this.refresh();
    return r;
  }
  getLicenseStatus() {
    if (!this.data.token) return { status: "not_activated" };
    try {
      const p = this.claims();
      return {
        status: "active",
        license_id: p.sub,
        expires_at: p.license_exp,
        credential_expires_at: p.exp,
        perpetual: p.perpetual,
        features: p.features,
        quotas: p.quotas,
      };
    } catch (e) {
      return { status: "denied", error: e.code };
    }
  }
  async authorize() {
    let p = this.claims();
    if (p.policy === "online") {
      const r = await this.call(
        "check",
        { product: this.product, activation_id: this.data.activation_id },
        this.data.activation_secret,
      );
      if (r.token) {
        this.accept(r);
        p = this.claims();
      }
      if ((r.version ?? p.ver) !== p.ver) {
        await this.refresh();
        p = this.claims();
      }
    }
    return p;
  }
  async requireFeature(feature) {
    if (!(await this.authorize()).features.includes(feature))
      deny("FEATURE_DENIED");
    return true;
  }
  async checkQuota(name, current, additional = 1) {
    if (
      !Number.isSafeInteger(current) ||
      !Number.isSafeInteger(additional) ||
      current < 0 ||
      additional < 0
    )
      throw Error("Invalid quota count");
    const q = (await this.authorize()).quotas;
    if (!Object.hasOwn(q, name) || current + additional > q[name])
      deny("QUOTA_EXCEEDED");
    return true;
  }
  async deactivate() {
    const r = await this.call(
      "deactivate",
      { product: this.product, activation_id: this.data.activation_id },
      this.data.activation_secret,
    );
    delete this.data.token;
    delete this.data.activation_secret;
    this.save();
    return r;
  }
  installOffline(path) {
    let r;
    try {
      r = JSON.parse(readFileSync(path, "utf8"));
    } catch {
      deny("OFFLINE_FILE_INVALID");
    }
    const p = verifyToken(r.token, {
      keys: this.keys,
      issuer: this.issuer,
      product: this.product,
      instance: this.data.instance,
      now: this.time(),
    });
    if (p.policy !== "offline") deny("OFFLINE_POLICY_REQUIRED");
    delete this.data.activation_secret;
    delete this.data.license_secret;
    return this.accept(r);
  }
  startBackgroundRefresh() {
    if (this.timer) return;
    try {
      if (this.data.token && this.claims().policy === "offline") return;
    } catch (e) {
      if (!["TOKEN_EXPIRED", "LICENSE_EXPIRED"].includes(e.code)) throw e;
    }
    this.closed = false;
    let failures = 0;
    const loop = () => {
      if (this.closed) return;
      const seconds = failures
        ? Math.min(60, 2 ** Math.min(failures, 6))
        : this.data.refresh_interval || 300;
      this.timer = setTimeout(
        async () => {
          this.timer = null;
          try {
            await this.refresh();
            failures = 0;
          } catch (e) {
            failures++;
            if (
              ![
                "NETWORK_UNAVAILABLE",
                "CENTER_UNAVAILABLE",
                "RATE_LIMIT",
              ].includes(e.code)
            ) {
              delete this.data.token;
              this.save();
              this.closed = true;
            }
          }
          loop();
        },
        seconds * 1000 * (0.8 + Math.random() * 0.4),
      );
      this.timer.unref();
    };
    loop();
  }
  close() {
    this.closed = true;
    clearTimeout(this.timer);
    this.timer = null;
  }
}
