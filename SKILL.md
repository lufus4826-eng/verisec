---
name: verisec
description: Use when asked to perform a business-logic security audit, hunt authorization flaws, test for IDOR/BOLA, missing auth middleware, mass assignment, or race-condition double-spend across Python, JS/TS, Go, Java/Kotlin, C#, or Rust with 100% network-isolated PoC execution, automatic secret redaction, and sandbox-verified patches. (ใช้เมื่อผู้ใช้ขอให้ตรวจช่องโหว่ลอจิกทางธุรกิจ สิทธิ์รั่ว ข้ามบัญชี IDOR/BOLA ลืมตัวเช็กสิทธิ์ Mass Assignment หรือ Race Condition ทำรายการซ้ำซ้อน พร้อมพิสูจน์ด้วยการจำลองคำขอในพื้นที่ปิดและยืนยันแพตช์ผ่าน Dual Gate — security audit, logic flaw, authorization bypass, IDOR, BOLA, mass assignment, race condition)
---

# VeriSec

Goal: Find business-logic and authorization vulnerabilities **empirically proven via network-isolated PoC execution** (never by regex-guessing alone). Deliver `S/sec-report.md` with Dual-Gate verified PoCs, redacted evidence, and sandbox-verified remediation diffs without modifying host source files before explicit user approval.

**Supreme Principle (Dual-Gate Architecture):** Every vulnerability and patch MUST pass **both** gates:
1. **Gate 1 — Invariant Breach Gate (`isolated-poc --phase baseline`):**
   - **Authorized Control Pass:** A legitimate authorized request (`test_control_*`) MUST succeed (`PASS`), proving the route and harness work.
   - **Unauthorized / Boundary Breach Proven:** Cross-account, unauthenticated, mass-assigned, or concurrent request breaches the security boundary (`BREACH_CONFIRMED`) on unpatched code. If unpatched code already blocks the breach (`BREACH_BLOCKED`), classify as `REFUTED_SAFE` (never a false positive).
   - **Zero Harness/Network Breakdown:** Zero `SyntaxError`/`ImportError`/`VERISEC_NET_GUARD` errors and `ran > 0`.
2. **Gate 2 — Remediation & Non-Regression Gate (`verify` on `S/sandbox-fix/`):**
   - **Breach Blocked:** The exact same PoC confirms the unauthorized action is blocked (`BREACH_BLOCKED`).
   - **100% Functional Preservation:** Both the PoC's `Authorized Control` case AND the existing project test suite (`--test-cmd`) pass 100%. Overly strict patches that break authorized users (`REJECTED_CONTROL_BROKEN`) or tests (`REJECTED_TEST_REGRESSION`) are **auto-rolled back** via `--auto-rollback`.
   - **Zero Secret Leakage:** All logs, diffs, worklogs, and report tables are automatically scrubbed via `redact-output` (`unredacted_remaining=0`).

## Default Parameters
`MIN_ROUNDS=3` (checkpoint after Round 3; continuation up to `MAX_ROUNDS=8`) | `ISOLATION=100% offline (VERISEC_NET_GUARD)` | `S=.bughunt/sec-<YYYYMMDD-HHMMSS>/` | `VS=<skill_dir>/scripts/vs.py` | **Language:** Auto-match user prompt language (Thai or English; keep standard security terms like *IDOR*, *BOLA*, *Mass Assignment*, *Race Condition*, *PoC*, *Dual Gate* in English) for chat, `S/worklog.md`, Phase 5 prompt, and `S/sec-report.md`.

## Token Efficiency Rules (Mandatory)
1. **Grep-First & Ranged Reads:** Run `vs.py surface-map` first, then `read_file` with `StartLine`/`EndLine` (`<=150` lines/call). Never dump whole source files, never re-read unchanged lines, and **never** read `S/logs/*.log` or `S/logs/*.json` directly (neither via `read_file` nor `Get-Content`/`cat`).
2. **CLI-First (`scripts/vs.py`):** Use `python "<VS>"` (`init`, `surface-map`, `isolated-poc`, `redact-output`, `verify`, `sandbox`, `log`, `summary`). Rely on `<=10`-line digests and `vs.py summary --snippets`.
3. **Batch & Turn-Fusion:** Never spend a standalone turn calling only `vs.py log` or create `S/tmp/*.md`. Fuse `vs.py log` into the next turn's PoC writes, sandbox edits, or report preparation.
4. **Lazy-Load Heavy Templates:** Read `resources/report-template-th.md` (Thai) or `resources/report-template.md` (English) **ONLY in Phase 6** (never load both!). Load ONLY the matching `resources/lang/<lang>.md`.

## Reference Files (Lazy-Load by Phase)
- `scripts/vs.py` — Zero-dependency security surface scanner, network-isolated runner, redactor & Dual-Gate CLI.
- `resources/threat-taxonomy.md` — Phase 2: 4 business-logic threat categories & PoC/remediation patterns.
- `resources/lang/00-common.md` — Phase 0–1: `VERISEC_POC:` protocol, `test_control_*` vs breach invariant rules, offline guard.
- `resources/lang/<lang>.md` — Phase 0–1: load **only** matching language (`python`, `js-ts`, `go`, `jvm`, `dotnet`, `rust`).
- `resources/report-template.md` — **Phase 6 ONLY (English)**.
- `resources/report-template-th.md` — **Phase 6 ONLY (Thai)**.

## Core Rules & Isolation (`.bughunt/`)
1. Execute the **6-Phase Workflow** (`0–1 -> 2 -> 3 -> 4 -> 5 -> 6`) sequentially; never skip Gate 1 or Gate 2 checks.
2. All agent files live strictly in `.bughunt/.cache/` and `S/` (`pocs/`, `logs/`, `tmp/`, `sandbox-fix/`, `worklog.md`, `sec-report.md`).
3. **NEVER** modify host source files, configs, dependencies, or lockfiles before explicit user approval; **NEVER** make external network calls in PoCs (`VERISEC_OFFLINE=1`); **NEVER** run `git checkout|restore|reset|clean`.
4. Physical `S/sec-report.md` is mandatory (chat summaries alone do not count).

---

## Phase 0–1 — Surface & Auth Matrix
1. **Init + Surface Scan (Single Turn):** Run chained command:
   - `python "<VS>" init --root .` -> capture `{S, SNAME, CACHE, ROOT, prior_sessions}`
   - `python "<VS>" surface-map --root . --s "$S"` (`<=35`-line ranked matrix of endpoints, attached auth guards, external inputs, and flagged risk tags: `IDOR_BOLA`, `MISSING_AUTH_GUARD`, `MASS_ASSIGNMENT`, `RACE_DOUBLE_SPEND`).
   In the same turn (or right after stack detection), load `resources/threat-taxonomy.md`, `resources/lang/00-common.md`, and ONLY matching `resources/lang/<lang>.md`.
2. **Baseline Test Check & Matrix Verification:** Inspect flagged handlers via ranged `read_file` (`<=150`L) to trace auth middleware, object ownership filters, payload binding, and concurrency locks. Run existing project tests once via `isolated-poc` or verify baseline passes, then present a concise **Surface & Auth Matrix** summary in chat (matching prompt language).

## Phase 2 — Threat Hypothesis
Formulate concrete hypotheses (`SEC-1`, `SEC-2`, ...) tied to inspected code (`path:line -> symbol`) across the 4 priority categories (`IDOR_BOLA`, `MISSING_AUTH_GUARD`, `MASS_ASSIGNMENT`, `RACE_DOUBLE_SPEND`) — plus promising guarded endpoints worth verifying to eliminate false positives (`REFUTED_SAFE`):
`SEC-{n} | Cat: <CATEGORY> | Loc: <path:line->fn> | Threat: <bypass mechanism> | Control: <authorized caller> | Breach: <attacker/concurrent request>`
- Never repeat already-logged hypotheses or claim a vulnerability without a concrete bypass path.

## Phase 3 — Safe Exploit PoC (Gate 1: Invariant Breach Gate)
1. **Fuse Log + Batch Write PoCs (One Turn):**
   - Fuse `python "<VS>" log --s "$S" --status "Phase 3 - Gate 1 PoCs" --entry "..."` with parallel `write_file` calls creating `S/pocs/poc_sec1.<ext>`, ...
   - Every PoC MUST:
     - Read `VERISEC_TARGET_ROOT` (`ROOT` in baseline, `S/sandbox-fix` in remediation).
     - Test **both** an **Authorized Control** request (`test_control_*` — MUST PASS) AND an **Unauthorized / Boundary Breach** invariant (e.g., User B reading User A's object, unprivileged user calling admin/export route, mass-assigning `"role":"admin"`, or `threading.Barrier` concurrent voucher double-spend).
     - Mock ONLY external third-party APIs (never target business logic or auth checks) and NEVER touch external network hosts (`VERISEC_NET_GUARD` enforces 100% isolation).
2. **Execute Isolated Baseline PoCs:**
   - Run `python "<VS>" isolated-poc --s "$S" --id secN --phase baseline --category <CAT> -- <cmd>` (chain hypotheses in the batch).
   - Run `python "<VS>" verify --s "$S" --id secN --gate1-only`:
     - `GATE1_BREACH_CONFIRMED` -> real vulnerability proven, advance to Phase 4.
     - `REFUTED_SAFE` -> baseline already blocked the attack; log and include in Section 4 (no patch needed).
     - `REJECTED_GATE1_HARNESS` / `CONTROL_FAILED` -> fix PoC harness up to 3 attempts (or mark `INCONCLUSIVE`).

## Phase 4 — Patch Verification (Gate 2: Remediation & Non-Regression Gate)
1. **Create Sandbox-Fix:** Run `python "<VS>" sandbox --s "$S" --mode fix`, fused with `vs.py log --status "Phase 4 - Remediation Verification" --entry "Gate 1 confirmed: ..."`.
2. **Checkpoint Before Each Patch & Verify Dual-Gate:**
   - Before patching `secN` in `S/sandbox-fix/`, snapshot via `python "<VS>" sandbox --s "$S" --mode save --id secN`.
   - Apply minimal, idiomatic remediation inside `S/sandbox-fix/` (owner/tenant check, `@require_role`/`auth` middleware, field whitelist, or lock/atomic transaction) — never over-restrict legitimate users!
   - Run Dual-Gate verification with automatic rollback:
     ```text
     python "<VS>" verify --s "$S" --id secN --auto-rollback --test-cmd "<project test cmd>"
     ```
   - Outcomes:
     - `CONFIRMED_REMEDIATED` -> Gate 1 & Gate 2 passed (`BREACH_BLOCKED`, `Control=PASS`, project suite `PASS`, 0 unredacted secrets).
     - `REJECTED_CONTROL_BROKEN` / `REJECTED_TEST_REGRESSION` / `REJECTED_INCOMPLETE_PATCH` -> `S/sandbox-fix/` is auto-restored to checkpoint; adjust patch carefully and retry (rejected attempt remains recorded in Section 4).

## Phase 5 — Checkpoint After Round 3 (or Initial Pass)
1. Write a compact interim summary (`<=25` lines) to `S/sec-report.md` (`Status: Interim Draft — Awaiting User Decision` / `สถานะรายงาน: ฉบับระหว่างทาง — รอผู้ใช้ตัดสินใจ`) fused with `vs.py log --status "Awaiting User Decision" --entry "..."` (unless user pre-authorized running autonomously to completion).
2. Present verified findings + severity breakdown and ask whether to:
   1) Continue deeper threat hunting on additional modules/rounds (up to `MAX_ROUNDS=8`).
   2) Stop and generate the comprehensive Security Advisory Report (`S/sec-report.md`).

## Phase 6 — Security Advisory Report & Cleanliness
1. **Single Fused Prep Turn:** Run one chained shell command:
   ```text
   python "<VS>" summary --s "$S" --snippets ; python "<VS>" sandbox --s "$S" --mode diff ; python "<VS>" redact-output --s "$S" --scan ; python "<VS>" sandbox --s "$S" --mode clean
   ```
   **AND** in the same turn call `read_file` on **ONLY** `resources/report-template-th.md` (Thai) or `resources/report-template.md` (English).
2. **Write `S/sec-report.md` & Log (Single Turn):** Populate the loaded template completely using `vs.py summary` tables/snippets and redacted `sandbox --mode diff` unified diffs (all 7 sections; `"None"`/`"ไม่มี"` if empty), fused with `python "<VS>" log --s "$S" --status "Phase 6 Complete" --entry "Security advisory finalized; redact-scan CLEAN; sandbox cleaned."`.
3. **Handoff:** Summarize confirmed & remediated flaws, refuted false positives, rolled-back attempts, `[REDACT-SCAN]` status, `cleanliness` status, and `S/sec-report.md` path in chat (matching prompt language), and ask which sandbox-verified patches to apply to host code.

## Post-Report Host Application (Explicit Approval Only)
Apply approved `CONFIRMED_REMEDIATED` patches to host files -> re-run project tests + `isolated-poc` confirmation -> append Section 7 `"Applied Security Patches Log"` in `S/sec-report.md`.
