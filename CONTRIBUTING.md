# Contributing to VeriSec

Thank you for your interest in contributing to **VeriSec** (`verisec`)!

## Core Philosophy (Do Not Violate)

1. **Empirical Breach Proof Over Keyword Grep:** Every finding must pair a passing `Authorized Control` request (`test_control_*`) with a reproducible boundary breach (`BREACH_CONFIRMED`) on unpatched code. Baseline-blocked endpoints must resolve to `REFUTED_SAFE`.
2. **100% Outbound Network Isolation:** `scripts/vs.py isolated-poc` must block outbound connections outside loopback (`127.0.0.1`, `localhost`, `::1`) via `VERISEC_NET_GUARD` and `VERISEC_OFFLINE=1`.
3. **Automatic Secret Redaction:** Every stdout digest, `.log`, `.json`, unified diff, `worklog.md`, and `summary` output must pass through `redact_secrets()` with `unredacted_remaining=0`.
4. **Dual-Gate Remediation & Zero Host Footprint:** Patches are tested strictly inside `.bughunt/sec-*/sandbox-fix/` and automatically rolled back (`--auto-rollback`) if they break `Authorized Control` or existing project tests.
5. **Zero External Dependencies:** `scripts/vs.py` must run on **Python 3.9+ standard library only** across **Windows (PowerShell)** and **Linux/macOS (Bash)**.
6. **Token Efficiency:** Keep `SKILL.md` compact, preserve Phase 6 template lazy-loading, and cap `vs.py` CLI digests (`surface-map <= 35` lines, `isolated-poc <= 10` lines).

## How to Contribute

### 1. Adding or Improving a Language Adapter
Language adapters live in `resources/lang/<language>.md`. Every adapter must document:
- How `baseline` (`ROOT`) and `remediation` (`S/sandbox-fix/`) target code is resolved via `VERISEC_TARGET_ROOT` or `--cwd` without altering host files.
- In-process HTTP / service PoC templates separating `test_control_*` from `test_unauthorized_*` (or emitting `VERISEC_POC:{...}`).
- Language-native concurrency barrier patterns (`threading.Barrier`, `Promise.all`, `sync.WaitGroup`, `CyclicBarrier`, `std::sync::Barrier`) for `RACE_DOUBLE_SPEND`.

### 2. Improving `scripts/vs.py`
- Keep `scripts/vs.py` pure Python 3 stdlib.
- Add unit/integration tests in `tests/test_vs_cli.py` for any new `surface-map` rule, redaction pattern, or Dual-Gate edge case, and verify:
  - `python -B scripts/vs.py --help`
  - `python -B tests/test_vs_cli.py`
  - `python -B examples/vault_api_demo/run_demo.py`
- Keep `resources/report-template.md` and `resources/report-template-th.md` synchronized across all 7 sections if report schemas change.

### 3. Reporting Bugs or False Positives
Please open an issue using `.github/ISSUE_TEMPLATE/bug_report.md` with your runtime, OS, `vs.py` command, and redacted log excerpt.
