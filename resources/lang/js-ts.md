# JavaScript / TypeScript Security PoC Adapter

## 1. Target Resolution & Isolation
- Read `process.env.VERISEC_TARGET_ROOT` (`ROOT` in `baseline`, `S/sandbox-fix` in `remediation`) and import targets via `pathToFileURL(...)` (ESM/TS) or `require(path.join(TARGET_ROOT, ...))` (CJS).
- Use `node --test` (`node:test` + `node:assert/strict`) or project `jest`/`vitest` in offline mode; wrap `http`/`https`/`fetch` or test Express/Fastify handlers in-process without opening external ports (`supertest(app)` or direct `req/res` mocks).

## 2. Node Built-in Test Runner Template (`S/pocs/poc_sec1.mjs`)
```javascript
import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { pathToFileURL } from "node:url";

const targetRoot = process.env.VERISEC_TARGET_ROOT || path.resolve(".");
const mod = await import(pathToFileURL(path.join(targetRoot, "src/routes.mjs")).href);

test("test_control_authorized_owner_can_access", async () => {
  const res = await mod.getInvoice({ id: "user-a", role: "member" }, "INV-101");
  assert.equal(res.ownerId, "user-a");
});

test("test_unauthorized_cross_account_idor_blocked", async () => {
  await assert.rejects(
    () => mod.getInvoice({ id: "user-b", role: "member" }, "INV-101"),
    /forbidden|permission|unauthorized/i
  );
});
```

## 3. Concurrency (`RACE_DOUBLE_SPEND`)
Use `await Promise.all(Array.from({ length: 10 }, () => mod.redeemVoucher(user, "PROMO-1")))` and assert `succeeded.length === 1`.
