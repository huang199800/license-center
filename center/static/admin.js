"use strict";
let accessToken = "",
  state = {},
  delivery = [];
const $ = (id) => document.getElementById(id);
const labels = {
  active: "有效",
  paused: "暂停",
  revoked: "已撤销",
  new: "新授权",
  renew: "续费",
  upgrade: "升级",
  periodic: "周期联网",
  online: "严格在线",
  offline: "离线",
};
const errors = {
  REAUTH_REQUIRED: "需要再次验证",
  OTP_INVALID_OR_REPLAYED: "动态验证码无效或已使用，请等待下一枚",
  ADMIN_AUTH_FAILED: "账号、密码或验证码不正确",
  ROLE_DENIED: "当前角色无此权限",
  PRODUCT_DENIED: "无权操作此产品",
  RATE_LIMIT: "请求过多，请稍后重试",
};
function notice(text, bad = false) {
  $("notice").textContent = text;
  $("notice").classList.toggle("error", bad);
}
async function api(path, body) {
  const r = await fetch("/v1/admin/" + path, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      "Content-Type": "application/json",
      ...(accessToken ? { Authorization: "Bearer " + accessToken } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await r.json();
  if (!r.ok)
    throw Error(
      errors[data.error?.code] ||
        data.error?.code ||
        JSON.stringify(data.detail) ||
        "请求失败",
    );
  return data;
}
function safe(action) {
  return async (e) => {
    e?.preventDefault();
    try {
      await action(e);
    } catch (err) {
      notice(err.message, true);
    }
  };
}
function date(x) {
  return x === null || x === undefined
    ? "—"
    : new Date(x * 1000).toLocaleString();
}
function table(id, headers, rows) {
  const table = document.createElement("table"),
    thead = document.createElement("thead"),
    hr = document.createElement("tr");
  for (const h of headers) {
    const th = document.createElement("th");
    th.textContent = h;
    hr.append(th);
  }
  thead.append(hr);
  table.append(thead);
  const tbody = document.createElement("tbody");
  if (!rows.length) {
    const tr = document.createElement("tr"),
      td = document.createElement("td");
    td.colSpan = headers.length;
    td.textContent = "暂无记录";
    tr.append(td);
    tbody.append(tr);
  }
  for (const row of rows) {
    const tr = document.createElement("tr");
    for (const value of row) {
      const td = document.createElement("td");
      if (value instanceof Node) td.append(value);
      else td.textContent = String(value ?? "—");
      tr.append(td);
    }
    tbody.append(tr);
  }
  table.append(tbody);
  $(id).replaceChildren(table);
}
function button(text, action, danger = false) {
  const b = document.createElement("button");
  b.textContent = text;
  if (danger) b.className = "danger";
  b.addEventListener("click", safe(action));
  return b;
}
function actions(...buttons) {
  const div = document.createElement("div");
  div.append(...buttons);
  return div;
}
async function stepup() {
  const d = $("stepup");
  $("stepup-otp").value = "";
  const choice = await new Promise((resolve) => {
    d.addEventListener("close", () => resolve(d.returnValue), { once: true });
    d.showModal();
  });
  if (choice !== "confirm") throw Error("已取消");
  await api("reauth", { otp: $("stepup-otp").value });
}
async function load() {
  const scope = $("scope").value;
  state = await api(
    "inventory?limit=500" +
      (scope ? "&product=" + encodeURIComponent(scope) : ""),
  );
  const previous = scope;
  const opt = document.createElement("option");
  opt.value = "";
  opt.textContent = "全部可见产品";
  $("scope").replaceChildren(opt);
  for (const p of state.products) {
    const o = document.createElement("option");
    o.value = p.id;
    o.textContent = p.name + " / " + p.id;
    $("scope").append(o);
  }
  $("scope").value = previous;
  render();
  notice(
    "已连接 · " +
      date(state.server_time) +
      " · " +
      Intl.DateTimeFormat().resolvedOptions().timeZone,
  );
}
function render() {
  const cards = [
    ["许可证（当前页）", state.licenses.length],
    [
      "有效状态",
      state.licenses.filter(
        (l) =>
          l.status === "active" &&
          (l.perpetual || l.expires_at > state.server_time),
      ).length,
    ],
    [
      "租约占用",
      state.instances.filter((i) => i.lease_until > state.server_time).length,
    ],
    ["可见产品", state.products.length],
  ];
  $("stats").replaceChildren();
  for (const [label, n] of cards) {
    const d = document.createElement("div");
    d.className = "stat";
    const s = document.createElement("span"),
      b = document.createElement("b");
    s.textContent = label;
    b.textContent = n;
    d.append(s, b);
    $("stats").append(d);
  }
  renderLicenses();
  table(
    "products-table",
    ["标识", "名称", "当前版本"],
    state.products.map((p) => [p.id, p.name, p.version]),
  );
  table(
    "plans-table",
    [
      "套餐",
      "产品",
      "使用权",
      "功能 / 配额",
      "设备 / 在线",
      "联网策略",
      "操作",
    ],
    state.plans.map((p) => {
      const s = JSON.parse(p.spec);
      return [
        s.name,
        p.product,
        s.perpetual ? "永久" : s.days + " 天",
        s.features.join(", ") + " / " + JSON.stringify(s.quotas),
        s.max_devices + " / " + s.max_online,
        (labels[s.policy] || s.policy) +
          " / 刷新 " + s.refresh_interval + "秒 / 凭证 " + s.token_ttl +
          "秒 / 最大离线 " + s.offline_max + "秒",
        button("载入编辑", () => {
          $("plan-json").value = JSON.stringify(s, null, 2);
        }),
      ];
    }),
  );
  $("code-plan").replaceChildren();
  for (const p of state.plans) {
    const s = JSON.parse(p.spec),
      o = document.createElement("option");
    o.value = p.id;
    o.textContent = p.product + " / " + s.name;
    $("code-plan").append(o);
  }
  table(
    "codes-table",
    ["短前缀", "产品", "用途", "已兑 / 上限", "兑换截止", "备注", "操作"],
    state.codes.map((c) => [
      c.prefix + "…",
      c.product,
      labels[c.kind],
      c.uses + " / " + c.max_uses,
      date(c.redeem_before),
      c.note,
      c.disabled
        ? "已停用"
        : button("停用", async () => {
            await api("codes/" + c.id + "/disable", {});
            await load();
          }),
    ]),
  );
  table(
    "instances-table",
    ["实例", "许可证 / 产品", "绑定", "租约截止", "旧凭证截止", "操作"],
    state.instances.map((i) => [
      i.id,
      i.license + " / " + i.product,
      i.active ? "已绑定" : "已释放",
      date(i.lease_until),
      date(i.token_until),
      i.active
        ? button(
            "受控释放",
            async () => {
              const reason = prompt("填写迁移或恢复原因（至少3字符）");
              if (!reason) return;
              await stepup();
              const r = await api("instances/" + i.id + "/release", {
                status: "paused",
                reason,
              });
              await load();
              notice(
                "已释放；旧凭证有效边界：" + date(r.old_credential_valid_until),
              );
            },
            true,
          )
        : "—",
    ]),
  );
  table(
    "audit-table",
    ["时间", "操作者", "事件", "产品 / 对象", "详情"],
    state.audit.map((a) => [
      date(a.at),
      a.actor,
      a.action,
      (a.product || "全局") + " / " + (a.target || "—"),
      a.detail,
    ]),
  );
  $("key-status").textContent = JSON.stringify(state.keys, null, 2);
}
function renderLicenses() {
  const q = $("search").value.toLowerCase();
  table(
    "licenses-table",
    ["客户", "产品 / 许可证", "状态", "使用到期", "版本 / 权益", "操作"],
    state.licenses
      .filter((l) => (l.customer + l.id).toLowerCase().includes(q))
      .map((l) => {
        const s = JSON.parse(l.snapshot);
        return [
          l.customer,
          l.product + " / " + l.id,
          labels[l.status] +
            (!l.perpetual && l.expires_at <= state.server_time
              ? " · 已到期"
              : ""),
          (l.perpetual ? "永久使用权" : date(l.expires_at)) +
            "；升级权：" + (l.upgrade_until ? date(l.upgrade_until) : "未授予") +
            "；技术支持：" + (l.support_until ? date(l.support_until) : "未授予") +
            "；策略：" + labels[s.policy] + "；离线窗口 " +
            (s.policy === "offline" ? s.offline_max : s.token_ttl) + "秒",
          l.version + " / " + s.features.join(", "),
          actions(
            ...[
              ["暂停", "paused"],
              ["恢复", "active"],
              ["撤销", "revoked"],
            ].map(([text, status]) =>
              button(
                text,
                async () => {
                  const reason = prompt(
                    text + "原因（至少3字符）；暂停仍继续计时",
                  );
                  if (!reason) return;
                  await stepup();
                  const r = await api("licenses/" + l.id + "/status", {
                    status,
                    reason,
                  });
                  await load();
                  notice(
                    text +
                      "已记录；缓存凭证预计最晚失效：" +
                      date(r.cached_credential_boundary),
                  );
                },
                status === "revoked",
              ),
            ),
          ),
        ];
      }),
  );
}
$("login").addEventListener(
  "submit",
  safe(async (e) => {
    const body = Object.fromEntries(new FormData(e.target)),
      r = await api("login", body);
    accessToken = r.access_token;
    e.target.reset();
    $("login-panel").hidden = true;
    $("workspace").hidden = false;
    await load();
  }),
);
$("logout").addEventListener(
  "click",
  safe(async () => {
    if (accessToken) await api("logout", {});
    accessToken = "";
    state = {};
    delivery = [];
    $("delivery-text").textContent = "";
    $("workspace").hidden = true;
    $("login-panel").hidden = false;
    notice("已退出");
  }),
);
$("reload").addEventListener("click", safe(load));
$("scope").addEventListener("change", safe(load));
$("search").addEventListener("input", renderLicenses);
$("nav").addEventListener("click", (e) => {
  const name = e.target.dataset.tab;
  if (!name) return;
  document.querySelectorAll(".tab").forEach((s) => (s.hidden = s.id !== name));
  document
    .querySelectorAll("nav button")
    .forEach((b) => b.classList.toggle("selected", b === e.target));
  $("title").textContent = e.target.textContent;
});
$("product-form").addEventListener(
  "submit",
  safe(async (e) => {
    await api("products", Object.fromEntries(new FormData(e.target)));
    await load();
  }),
);
$("plan-json").value = JSON.stringify(
  {
    id: "demo-month",
    product: "demo",
    name: "月卡",
    days: 30,
    features: ["basic", "export"],
    quotas: { users: 10 },
    max_devices: 1,
    max_online: 1,
    policy: "periodic",
    token_ttl: 900,
    refresh_interval: 300,
    offline_max: 900,
  },
  null,
  2,
);
$("plan-form").addEventListener(
  "submit",
  safe(async () => {
    await api("plans", JSON.parse($("plan-json").value));
    await load();
  }),
);
$("code-form").addEventListener(
  "submit",
  safe(async (e) => {
    const body = Object.fromEntries(new FormData(e.target));
    body.count = Number(body.count);
    body.max_uses = Number(body.max_uses);
    for (const field of ["redeem_before", "starts_at"])
      body[field] = body[field]
        ? Math.floor(new Date(body[field]).getTime() / 1000)
        : null;
    await stepup();
    const r = await api("codes", body);
    delivery = r.delivery_once;
    $("delivery-text").textContent = delivery
      .map((v) => v.id + "  " + v.code)
      .join("\n");
    $("delivery").hidden = false;
    await load();
    notice(r.warning);
  }),
);
$("download").addEventListener("click", () => {
  const blob = new Blob(
      ["id,code\r\n" + delivery.map((r) => r.id + "," + r.code).join("\r\n")],
      { type: "text/csv;charset=utf-8" },
    ),
    url = URL.createObjectURL(blob),
    a = document.createElement("a");
  a.href = url;
  a.download = "license-codes.csv";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
$("clear-delivery").addEventListener("click", () => {
  delivery = [];
  $("delivery-text").textContent = "";
  $("delivery").hidden = true;
});
