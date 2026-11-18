# VeriSec Security Advisory Report Template (English — Lazy-Load in Phase 6 Only)

> **Instructions:** Copy below the divider to `S/sec-report.md`. Complete all 7 sections; write `"None"` if empty. **NEVER delete sections.** Use exact measured values from `vs.py summary --snippets`, redacted diffs from `vs.py sandbox --mode diff`, and hygiene verification from `vs.py redact-output --scan`.

---

# VeriSec Business-Logic Security Advisory

## Session Metadata
- **Session ID (`S`):** `.bughunt/<SNAME>/`
- **Project Root (`ROOT`):** `<path>`
- **Scope:** <Entire project OR module subpath>
- **Isolation & Hygiene Protocol:** 100% Outbound Network Isolation (`VERISEC_OFFLINE=1` / `VERISEC_NET_GUARD`) | Automatic Secret Redaction (`redact-output`) | Dual-Gate Empirical Verification
- **Report Status:** Final Complete

---

## 1. Executive Summary & Dual-Gate Metrics

| Metric | Value | Notes |
|---|---:|---|
| API Endpoints / Handlers Mapped | <N> | Via `vs.py surface-map` |
| Flagged Risk Candidates | <N> | `IDOR_BOLA` / `MISSING_AUTH_GUARD` / `MASS_ASSIGNMENT` / `RACE_DOUBLE_SPEND` |
| **Confirmed & Remediated Vulnerabilities** | **<N>** | Gate 1 + Gate 2 Verified in `S/sandbox-fix` |
| **Refuted Hypotheses (`REFUTED_SAFE`)** | **<N>** | Gate 1 proved baseline already blocks breach |
| **Over-Strict / Regressive Patch Rollbacks** | **<N>** | Auto-restored via `verify --auto-rollback` |
| **Secrets Automatically Masked** | **<N>** | `[REDACT-SCAN]` unredacted remaining = `0` |

---

## 2. API Surface & Authorization Matrix (`surface-map`)

| Endpoint / Handler | Location | Auth Guards | External Inputs | Risk Tags | Priority |
|---|---|---|---|---|---|
| `<symbol>` | `<file:line>` | `<guards or NONE>` | `<inputs>` | `<tags or SAFE>` | `<HIGH/MED/LOW>` |

---

## 3. Confirmed & Remediated Vulnerabilities (Gate 1 + Gate 2 Verified)

<!-- Repeat per CONFIRMED_REMEDIATED vulnerability -->

### <ID>: <Short Vulnerability Title> (`<CATEGORY>`)
- **Severity:** <Critical / High / Medium / Low>
- **Code Location:** [`<relative/path:line>`](<relative/path>) `<symbol>`
- **Root Cause & Bypass Mechanism:** <Why the business logic allowed unauthorized access or double-spend>
- **Dual-Gate Proof Summary:**
  - **Gate 1 (Baseline Breach):** Authorized Control = `PASS` | Breach Status = `BREACH_CONFIRMED` | Network Isolation = `ENFORCED`
  - **Gate 2 (Sandbox-Fix Remediation):** Breach Status = `BREACH_BLOCKED` | Authorized Control = `PASS` | Existing Project Suite = `<PASS>`
- **Isolated PoC Script:** [`<S>/pocs/<file>`](<S>/pocs/<file>)

#### Redacted PoC Evidence (Baseline vs. Remediation)
```text
<paste compact snippet from vs.py summary --snippets (never raw unredacted tokens)>
```

#### Sandbox-Verified Remediation Diff
```diff
<paste redacted unified diff from vs.py sandbox --mode diff>
```

---

## 4. Refuted Hypotheses (`REFUTED_SAFE`) & Auto-Rolled-Back Patch Attempts

> VeriSec eliminates static false positives via Gate 1 (`REFUTED_SAFE`) and automatically rolls back overly strict or regressive patches via Gate 2 (`--auto-rollback`).

| ID | Category | Outcome | Control | Breach Status | Action / Rationale |
|---|---|---|---|---|---|
| <ID OR None> | <CATEGORY> | <REFUTED_SAFE / REJECTED_CONTROL_BROKEN / REJECTED_TEST_REGRESSION> | <PASS/FAIL> | <status> | <AUTO_RESTORED / Already guarded> |

---

## 5. Secret Redaction & Network Isolation Audit
- **Network Isolation Check:** `<ENFORCED — VERISEC_OFFLINE=1 + sitecustomize socket guard, 0 external connections>`
- **Secret Scrubber Audit (`vs.py redact-output --s "$S" --scan`):** `<[REDACT-SCAN] files=N scrubbed_files=M masked=K unredacted_remaining=0 status=CLEAN>`

---

## 6. Workspace Cleanliness Log
- **Snapshot Files:** `<S>/logs/fs-before.txt`, `<S>/logs/fs-after.txt`
- **Cleanliness Verdict:** `<cleanliness: CLEAN (0 new/modified files outside .bughunt/)>`
- **Deliverables Retained:** `<S>/sec-report.md`, `<S>/worklog.md`, `<S>/pocs/`, `<S>/logs/`

---

## 7. Applied Security Patches Log
> Updated only after explicit user approval to apply sandbox-verified patches to host source files.

| Timestamp | ID | Patched File | Host Test Suite | Isolated PoC Confirmation | Status |
|---|---|---|---|---|---|
| None | - | - | - | - | Pending User Approval |
