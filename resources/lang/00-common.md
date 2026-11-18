# 00 — Common Isolated PoC Protocol, Redaction & Dual-Gate Rules

Used with `resources/lang/<lang>.md`. Resolve `<VS>` as `<skill_dir>/scripts/vs.py`. Execute commands from `ROOT`.

## 1. CLI Workflow (`scripts/vs.py`)
`vs.py` sets `VERISEC_OFFLINE=1`, `VERISEC_PHASE=baseline|remediation`, `VERISEC_TARGET_ROOT` (`ROOT` for `baseline`, `S/sandbox-fix` for `remediation`), injects Python (`PYTHONPATH` -> `sitecustomize.py`) AND Node.js (`NODE_OPTIONS=--require netguard_node.cjs`) socket/DNS/HTTP guards blocking outbound non-loopback connections, and redirects tool caches into `.bughunt/.cache/`:
- `python "<VS>" init [--root .]` -> creates `S/{pocs,logs,tmp}`, Python + Node netguards, `fs-before.txt`, `worklog.md`, prints JSON.
- `python "<VS>" surface-map [--root .] [--scope dir] [--s "$S"]` -> `<=35`-line ranked matrix of routes/handlers, auth guards, external inputs, and 4 risk categories (`IDOR_BOLA`, `MISSING_AUTH_GUARD`, `MASS_ASSIGNMENT`, `RACE_DOUBLE_SPEND`).
- `python "<VS>" isolated-poc --s "$S" --id <ID> --phase baseline|remediation --category <CAT> -- <cmd...>` -> runs in 100% network-isolated mode, scrubs raw/Base64/URL-encoded secrets, saves `S/logs/<id>_<phase>.{log,json}`, emits `<=10`-line digest.
- `python "<VS>" redact-output (--text STR | --input-file PATH | --s "$S" --register-secret VAL | --s "$S" --scan)` -> masks API keys, JWTs, Bearer headers, passwords, DB URLs, Base64/URL-encoded secrets, and registered canary secrets; `--scan` verifies `0` unredacted secrets remain in `S/`.
- `python "<VS>" verify --s "$S" --id <ID> [--gate1-only] [--auto-rollback] [--test-cmd "..."]` -> enforces Gate 1 (Baseline breach proven + Control PASS + offline) & Gate 2 (Sandbox-fix breach blocked + Control PASS + existing tests PASS + no in-memory locks on DB races + 0 secret leaks), auto-restoring checkpoint on rejection.
- `python "<VS>" sandbox --s "$S" --mode fix|save|rollback|diff|clean [--id <ID>]` -> manages `S/sandbox-fix/`, checkpoints, redacted unified diff (`<=8,000` chars), and cleanliness check.
- `python "<VS>" log --s "$S" [--status "..."] [--entry "..."]` -> redacted atomic `worklog.md` update.
- `python "<VS>" summary --s "$S" [--snippets]` -> emits redacted Markdown tables and PoC snippets.

## 2. Two Supported PoC Formats
### Mode A — Standard Test Runner (`unittest` / `pytest` / `node:test` / `jest` / `go test`)
- Name at least one positive test `test_control_*` (`Control_*` in Go/C#) testing an **authorized legitimate request** -> MUST PASS in both baseline and remediation!
- Name security invariant test(s) `test_unauthorized_*` / `test_idor_*` / `test_mass_assign_*` / `test_race_*` / `test_missing_auth_*` asserting that the attack is **blocked** — **AND ALWAYS include the `VERISEC_BREACH_PROVEN:` marker in the failure message** (e.g. `self.assertRaises(PermissionError, msg="VERISEC_BREACH_PROVEN: ...")` or `self.fail("VERISEC_BREACH_PROVEN: ...")`). Unmarked accidental test failures are rejected as `HARNESS_BROKEN` so broken tests never masquerade as proven exploits!
  - On unpatched `baseline`: `test_control_*` PASSES and invariant test FAILS with `VERISEC_BREACH_PROVEN` -> `breach_status=BREACH_CONFIRMED` (Gate 1 PASS!). If invariant test already PASSES on baseline -> `breach_status=BREACH_BLOCKED` -> `REFUTED_SAFE`!
  - On patched `remediation`: BOTH `test_control_*` and invariant test PASS -> `breach_status=BREACH_BLOCKED` (Gate 2 PASS!). If patch breaks `test_control_*` -> `REJECTED_CONTROL_BROKEN` + auto-rollback!

### Mode B — `VERISEC_POC:` Structured JSON Line (Recommended for Custom Frameworks)
For custom frameworks or concurrent harnesses, emit one JSON line prefixed with `VERISEC_POC:`:
```json
VERISEC_POC:{"id":"sec1","category":"IDOR_BOLA","control_authorized":"PASS","breach_detected":true,"network_isolated":true,"details":"User B accessed invoice INV-101 owned by User A"}
```

## 3. 100% Network Isolation & Secret Safety Rules
1. Never call real external HTTP endpoints, external DBs, or live third-party APIs in PoCs. Use loopback `127.0.0.1`, in-process app test clients (`TestClient`, `app.test_client()`, `httptest.NewRecorder`, `supertest`), or local `S/tmp/` SQLite/in-memory stores.
2. Any attempt by code/PoC to connect outside loopback (`127.0.0.1`/`localhost`/`::1`) raises `VERISEC_NET_GUARD` and fails harness validation immediately.
3. Never hardcode real production credentials; dummy test tokens (`Bearer ...`, `sk-live-...`) in responses/logs are automatically redacted by `vs.py` (`[REDACTED_TOKEN]`, `[REDACTED_KEY]`, `[REDACTED_SECRET]`).
