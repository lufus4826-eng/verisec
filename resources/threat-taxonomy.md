# VeriSec Threat Taxonomy (Business-Logic & Authorization Flaws)

Load during **Phase 2**. Focus on logic defects static grep/SAST tools miss, pairing every hypothesis with an **Authorized Control** case and an **Isolated Breach PoC**.

---

## 1. `IDOR_BOLA` — Insecure Direct Object Reference / Broken Object Level Authorization
- **Pattern:** Endpoint/service accepts an object ID (`invoice_id`, `order_id`, `account_id`, `user_id`, `doc_id`, `file_id`) and queries/returns/modifies the record directly without enforcing `record.owner_id == caller.id` (or `record.tenant_id == caller.tenant_id` unless caller is privileged admin).
- **Why Static SAST Misses It:** Authentication middleware passes (`caller` IS logged in!), and SQL queries are parameterized (no SQLi), yet User B can read or mutate User A's records.
- **PoC Design:**
  - *Authorized Control:* User A requests `invoice_A` (`owner_id=A`) -> succeeds with expected record.
  - *Breach Invariant:* User B requests `invoice_A` -> assert `PermissionError` / HTTP `403` / `404`. Unpatched code returns `invoice_A` -> `BREACH_CONFIRMED`.
- **Minimal Remediation:** Enforce ownership/tenant check at query or boundary (`if record["owner_id"] != caller["id"] and caller.get("role") != "admin": raise PermissionError(...)`). Never break admin or owner access!

---

## 2. `MISSING_AUTH_GUARD` — Unprotected / Orphaned Sensitive Endpoints
- **Pattern:** An API route or handler lacks authentication/role guards (`@require_auth`, `@require_role("admin")`, `Depends(...)`, middleware) that sibling endpoints enforce — common on `/export`, `/admin`, `/internal`, `/audit`, `/purge`, `/debug`, or newly added endpoints.
- **Why Static SAST Misses It:** Syntactically valid route function; only obvious when comparing the Auth Matrix across sibling endpoints (`vs.py surface-map`).
- **PoC Design:**
  - *Authorized Control:* Admin user calls `export_all_ledgers(admin)` -> succeeds.
  - *Breach Invariant:* Unauthenticated (`None`) or regular `"member"` user calls `export_all_ledgers(member)` -> assert `PermissionError` / HTTP `401`/`403`. Unpatched code returns all tenant ledgers -> `BREACH_CONFIRMED`.
- **Minimal Remediation:** Attach the project's standard auth/role decorator or guard (`@require_role("admin")`) matching sibling endpoints.

---

## 3. `MASS_ASSIGNMENT` — Over-Posting & Privilege Escalation Binding
- **Pattern:** Endpoint binds incoming JSON/form dict directly onto a user/account/order record (`record.update(payload)`, `for k, v in payload.items(): setattr(...)`, `**payload`, `Object.assign(user, req.body)`, auto-binding structs/DTOs) without an explicit field whitelist.
- **Why Static SAST Misses It:** Updating `display_name` or `email` looks normal, but sending `"role": "admin"`, `"is_admin": True`, `"credit_limit": 999999`, `"balance": 100000`, or `"owner_id": ...` silently escalates privileges.
- **PoC Design:**
  - *Authorized Control:* Regular user updates `{"display_name": "Alice B.", "bio": "Engineer"}` -> succeeds and updates allowed fields.
  - *Breach Invariant:* Regular user sends `{"display_name": "Mallory", "role": "admin", "credit_limit": 999999}` -> assert privileged fields remain unchanged OR request is rejected, while `Control` multi-field profile updates STILL work! (Watch out for over-strict patches that reject `len(payload) > 1` and break `Control`!)
- **Minimal Remediation:** Filter incoming updates through an explicit `ALLOWED_PROFILE_FIELDS = frozenset({"display_name", "bio", ...})` whitelist (or reject unexpected privileged keys with HTTP 400/403 while allowing all valid multi-field updates).

---

## 4. `RACE_DOUBLE_SPEND` — Concurrent Check-Then-Act & Limit Bypass
- **Pattern:** Balance withdrawal, promo/voucher redemption, coupon usage, inventory checkout, or quota consumption checks a condition (`if voucher["remaining_uses"] > 0:` or `if balance >= amount:`) and mutates state (`remaining_uses -= 1`, `balance -= amount`) non-atomically without locks, atomic CAS, or `SELECT ... FOR UPDATE`.
- **Why Static SAST Misses It:** Sequential unit tests (`redeem` once) pass 100% because single-threaded logic looks right.
- **PoC Design:**
  - *Authorized Control:* Single authorized redemption on a 1-use voucher succeeds (`+amount`, `remaining_uses == 0`), and a second sequential call fails.
  - *Breach Invariant:* Launch `N=8` concurrent threads/tasks synchronized at a `threading.Barrier(N)` (or `Promise.all` / `sync.WaitGroup`) targeting a 1-use voucher or balance `100` with `N` concurrent `100` withdrawals -> assert `success_count == 1` and `final_balance >= 0`. Unpatched code allows multiple successes -> `BREACH_CONFIRMED`.
- **Minimal Remediation (Iron Rule):**
  - **Pure In-Memory Single-Process Stores:** Wrap check-and-mutate inside a `threading.Lock()` / mutex.
  - **Database / ORM / Redis-Backed Handlers (MANDATORY):** **NEVER** use an in-memory `threading.Lock()`, `asyncio.Lock()`, or `sync.Mutex` on handlers backed by SQL/NoSQL/Redis — that fails across multi-worker processes and Gate 2 automatically rejects it as `REJECTED_IN_MEMORY_LOCK_ON_DB`! Always remediate DB/cache races using **atomic conditional updates** (`UPDATE vouchers SET remaining_uses = remaining_uses - 1 WHERE code = ? AND remaining_uses > 0` checking `rowcount == 1`), `SELECT ... FOR UPDATE` inside a transaction, or Redis `SET NX` / Lua CAS scripts.
