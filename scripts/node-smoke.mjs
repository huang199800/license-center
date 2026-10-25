import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { LicenseClient } from "../sdk-node/client.mjs";
const config = JSON.parse(readFileSync(process.argv[2], "utf8"));
const client = new LicenseClient(config).initialize();
try {
  assert.equal(
    (await client.activate(config.code, "node-deployment-drill")).status,
    "active",
  );
  assert.equal(await client.requireFeature("basic"), true);
  assert.equal((await client.refresh()).status, "active");
} finally {
  client.close();
}
