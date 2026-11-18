#!/usr/bin/env python3
"""One-command live VeriSec v1.0 E2E demo using an isolated temporary copy of vault_api_demo."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


EXAMPLE_DIR = Path(__file__).resolve().parent
REPO_ROOT = EXAMPLE_DIR.parents[1]
VS_SCRIPT = REPO_ROOT / "scripts" / "vs.py"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import vs  # noqa: E402


POC_SEC1 = '''"""SEC-1 (IDOR_BOLA): Cross-account invoice access PoC."""
import os, sys, unittest
from pathlib import Path
DEFAULT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, os.environ.get("VERISEC_TARGET_ROOT", str(DEFAULT_ROOT)))
from vault_app import routes
from vault_app.store import create_default_store

class TestSec1Idor(unittest.TestCase):
    def setUp(self):
        self.store = create_default_store()
        self.alice = self.store.users["user-a"]
        self.bob = self.store.users["user-b"]

    def test_control_owner_reads_invoice(self):
        inv = routes.get_invoice(self.store, self.alice, "INV-101")
        self.assertEqual(inv["owner_id"], "user-a")

    def test_unauthorized_bob_cannot_read_alice_invoice(self):
        try:
            leaked = routes.get_invoice(self.store, self.bob, "INV-101")
        except PermissionError:
            return
        self.fail(f"IDOR breach! Bob read Alice invoice with secret: {leaked}")

if __name__ == "__main__":
    unittest.main(verbosity=2)
'''

POC_SEC2 = '''"""SEC-2 (MISSING_AUTH_GUARD): Non-admin / anonymous ledger export PoC."""
import os, sys, unittest
from pathlib import Path
DEFAULT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, os.environ.get("VERISEC_TARGET_ROOT", str(DEFAULT_ROOT)))
from vault_app import routes
from vault_app.store import create_default_store

class TestSec2MissingAuth(unittest.TestCase):
    def setUp(self):
        self.store = create_default_store()
        self.admin = self.store.users["admin-1"]
        self.member = self.store.users["user-b"]

    def test_control_admin_can_export_ledgers(self):
        rows = routes.export_all_ledgers(self.store, self.admin)
        self.assertEqual(len(rows), 2)

    def test_unauthorized_member_and_anon_cannot_export(self):
        with self.assertRaises(PermissionError):
            routes.export_all_ledgers(self.store, self.member)
        with self.assertRaises(PermissionError):
            routes.export_all_ledgers(self.store, None)

if __name__ == "__main__":
    unittest.main(verbosity=2)
'''

POC_SEC3 = '''"""SEC-3 (MASS_ASSIGNMENT): Privilege & credit limit escalation PoC."""
import os, sys, unittest
from pathlib import Path
DEFAULT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, os.environ.get("VERISEC_TARGET_ROOT", str(DEFAULT_ROOT)))
from vault_app import routes
from vault_app.store import create_default_store

class TestSec3MassAssignment(unittest.TestCase):
    def setUp(self):
        self.store = create_default_store()
        self.alice = self.store.users["user-a"]

    def test_control_member_updates_allowed_profile_fields(self):
        res = routes.update_profile(self.store, self.alice, {"display_name": "Alice B.", "bio": "Principal"})
        self.assertEqual(res["display_name"], "Alice B.")
        self.assertEqual(res["bio"], "Principal")

    def test_unauthorized_mass_assignment_role_escalation_blocked(self):
        try:
            updated = routes.update_profile(
                self.store,
                self.alice,
                {"display_name": "Mallory", "role": "admin", "credit_limit": 999999},
            )
        except PermissionError:
            return
        self.assertNotEqual(updated["role"], "admin", "Mass Assignment escalated role to admin!")
        self.assertEqual(updated["credit_limit"], 1000)

if __name__ == "__main__":
    unittest.main(verbosity=2)
'''

POC_SEC4 = '''"""SEC-4 (RACE_DOUBLE_SPEND): Concurrent barrier voucher double-spend PoC."""
import os, sys, threading, unittest
from pathlib import Path
DEFAULT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, os.environ.get("VERISEC_TARGET_ROOT", str(DEFAULT_ROOT)))
from vault_app import routes
from vault_app.store import create_default_store

class TestSec4RaceDoubleSpend(unittest.TestCase):
    def test_control_single_authorized_redemption(self):
        store = create_default_store()
        alice = store.users["user-a"]
        bal = routes.redeem_promo_voucher(store, alice, "PROMO-100")
        self.assertEqual(bal, 200.0)
        self.assertEqual(store.vouchers["PROMO-100"]["remaining_uses"], 0)

    def test_unauthorized_concurrent_double_spend_blocked(self):
        store = create_default_store()
        alice = store.users["user-a"]
        workers = 8
        barrier = threading.Barrier(workers)
        successes = []
        lock = threading.Lock()

        def worker():
            barrier.wait(timeout=5)
            try:
                routes.redeem_promo_voucher(store, alice, "PROMO-100")
                with lock:
                    successes.append(1)
            except Exception:
                pass

        threads = [threading.Thread(target=worker) for _ in range(workers)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=5)
        self.assertEqual(len(successes), 1, f"Double-spend! Redeemed {len(successes)} times on 1-use voucher")
        self.assertEqual(store.users["user-a"]["balance"], 200.0)

if __name__ == "__main__":
    unittest.main(verbosity=2)
'''

POC_SEC5 = '''"""SEC-5 (False Positive Check): Verify transfer_funds already blocks cross-account IDOR."""
import os, sys, unittest
from pathlib import Path
DEFAULT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, os.environ.get("VERISEC_TARGET_ROOT", str(DEFAULT_ROOT)))
from vault_app import routes
from vault_app.store import create_default_store

class TestSec5SafeTransfer(unittest.TestCase):
    def setUp(self):
        self.store = create_default_store()
        self.alice = self.store.users["user-a"]
        self.bob = self.store.users["user-b"]

    def test_control_owner_can_transfer(self):
        res = routes.transfer_funds(self.store, self.alice, "ACC-A", "ACC-B", 50.0)
        self.assertEqual(res["from_balance"], 450.0)

    def test_unauthorized_bob_cannot_drain_alice_account(self):
        with self.assertRaises(PermissionError):
            routes.transfer_funds(self.store, self.bob, "ACC-A", "ACC-B", 50.0)

if __name__ == "__main__":
    unittest.main(verbosity=2)
'''


PATCHED_ROUTES_SEC1 = '''"""Business-logic route handlers (Patched SEC-1)."""

from __future__ import annotations

from functools import wraps
import time
from typing import Any, Callable, Dict, List, Optional

from vault_app.store import VaultStore


def require_auth(fn: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(fn)
    def wrapper(store: VaultStore, caller_user: Optional[Dict[str, Any]], *args: Any, **kwargs: Any) -> Any:
        if not caller_user or not caller_user.get("id"):
            raise PermissionError("401 Unauthorized: missing caller identity")
        return fn(store, caller_user, *args, **kwargs)

    return wrapper


def require_role(role: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapper(store: VaultStore, caller_user: Optional[Dict[str, Any]], *args: Any, **kwargs: Any) -> Any:
            if not caller_user or caller_user.get("role") != role:
                raise PermissionError(f"403 Forbidden: requires role={role}")
            return fn(store, caller_user, *args, **kwargs)

        return wrapper

    return decorator


@require_role("admin")
def admin_purge_logs(store: VaultStore, caller_user: Dict[str, Any]) -> int:
    """Privileged admin-only operation (properly guarded)."""
    count = len(store.audit_logs)
    store.audit_logs.clear()
    return count


@require_auth
def get_invoice(store: VaultStore, caller_user: Dict[str, Any], invoice_id: str) -> Dict[str, Any]:
    """SEC-1 FIXED: Enforce owner_id == caller_user['id'] (or admin role)."""
    inv = store.invoices.get(invoice_id)
    if inv is None:
        raise KeyError(f"Invoice not found: {invoice_id}")
    if inv["owner_id"] != caller_user["id"] and caller_user.get("role") != "admin":
        raise PermissionError("403 Forbidden: cannot access another account's invoice")
    return dict(inv)


def export_all_ledgers(store: VaultStore, caller_user: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """SEC-2 (MISSING_AUTH_GUARD): Missing @require_role('admin') unlike sibling admin_purge_logs."""
    return [dict(item) for item in store.ledgers]


@require_auth
def update_profile(store: VaultStore, caller_user: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    """SEC-3 (MASS_ASSIGNMENT): Directly updates user dict without field whitelist."""
    user = store.users[caller_user["id"]]
    user.update(payload)
    return dict(user)


@require_auth
def redeem_promo_voucher(store: VaultStore, caller_user: Dict[str, Any], code: str) -> float:
    """SEC-4 (RACE_DOUBLE_SPEND): Non-atomic check-then-act on single-use voucher."""
    voucher = store.vouchers.get(code)
    if voucher is None:
        raise KeyError(f"Voucher not found: {code}")
    if voucher["remaining_uses"] > 0:
        time.sleep(0.008)
        voucher["remaining_uses"] -= 1
        store.users[caller_user["id"]]["balance"] += voucher["amount"]
        return store.users[caller_user["id"]]["balance"]
    raise ValueError("Voucher already redeemed")


@require_auth
def transfer_funds(
    store: VaultStore,
    caller_user: Dict[str, Any],
    from_acct_id: str,
    to_acct_id: str,
    amount: float,
) -> Dict[str, float]:
    """SEC-5 (SAFE CONTROLLED ENDPOINT): Checks owner_id and executes under store.lock."""
    if amount <= 0:
        raise ValueError("Transfer amount must be positive")
    with store.lock:
        src = store.accounts[from_acct_id]
        dst = store.accounts[to_acct_id]
        if src["owner_id"] != caller_user["id"]:
            raise PermissionError("403 Forbidden: caller does not own source account")
        if src["balance"] < amount:
            raise ValueError("Insufficient balance")
        src["balance"] -= amount
        dst["balance"] += amount
        return {"from_balance": src["balance"], "to_balance": dst["balance"]}
'''


def _run(cmd: list[str], cwd: Path, check: bool = True) -> str:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out = proc.stdout + proc.stderr
    if check and proc.returncode != 0:
        raise RuntimeError(f"Command failed ({proc.returncode}): {' '.join(cmd)}\n{out}")
    return proc.stdout.strip()


def main() -> int:
    vs.configure_stdio()
    tmp = Path(tempfile.mkdtemp(prefix="verisec_demo_"))
    try:
        shutil.copytree(EXAMPLE_DIR / "vault_app", tmp / "vault_app")
        shutil.copytree(EXAMPLE_DIR / "tests", tmp / "tests")

        init_out = _run([sys.executable, "-B", str(VS_SCRIPT), "init", "--root", str(tmp)], cwd=tmp)
        meta = json.loads(init_out)
        s_rel = meta["S"]
        s_dir = tmp / s_rel

        print("=== Phase 0-1: API Surface & Auth Matrix ===")
        surf_out = _run([sys.executable, "-B", str(VS_SCRIPT), "surface-map", "--root", str(tmp), "--s", s_rel], cwd=tmp)
        print(surf_out)
        assert "flagged=4" in surf_out, surf_out

        # Write PoCs into S/pocs/
        pocs = {
            "sec1": ("IDOR_BOLA", POC_SEC1),
            "sec2": ("MISSING_AUTH_GUARD", POC_SEC2),
            "sec3": ("MASS_ASSIGNMENT", POC_SEC3),
            "sec4": ("RACE_DOUBLE_SPEND", POC_SEC4),
            "sec5": ("IDOR_BOLA", POC_SEC5),
        }
        print("\n=== Phase 3: Gate 1 (Isolated Baseline PoCs) ===")
        for pid, (cat, code) in pocs.items():
            pfile = s_dir / "pocs" / f"poc_{pid}.py"
            pfile.write_text(code, encoding="utf-8")
            poc_digest = _run(
                [sys.executable, "-B", str(VS_SCRIPT), "isolated-poc", "--s", s_rel, "--id", pid, "--phase", "baseline", "--category", cat, "--", sys.executable, str(pfile)],
                cwd=tmp,
            )
            g1_out = _run(
                [sys.executable, "-B", str(VS_SCRIPT), "verify", "--s", s_rel, "--id", pid, "--gate1-only"],
                cwd=tmp,
            )
            print(poc_digest.splitlines()[0], "|", poc_digest.splitlines()[1], "|", g1_out.splitlines()[1])

        print("\n=== Phase 4: Gate 2 (Sandbox Remediation + Over-Strict Auto-Rollback) ===")
        _run([sys.executable, "-B", str(VS_SCRIPT), "sandbox", "--s", s_rel, "--mode", "fix"], cwd=tmp)
        fix_routes = s_dir / "sandbox-fix" / "vault_app" / "routes.py"
        suite_cmd = f'"{sys.executable}" -m unittest discover -s tests'

        # SEC-1: Fix IDOR
        _run([sys.executable, "-B", str(VS_SCRIPT), "sandbox", "--s", s_rel, "--mode", "save", "--id", "sec1"], cwd=tmp)
        fix_routes.write_text(PATCHED_ROUTES_SEC1, encoding="utf-8")
        print(_run([sys.executable, "-B", str(VS_SCRIPT), "verify", "--s", s_rel, "--id", "sec1", "--auto-rollback", "--test-cmd", suite_cmd], cwd=tmp))

        # SEC-2: Fix MISSING_AUTH_GUARD
        _run([sys.executable, "-B", str(VS_SCRIPT), "sandbox", "--s", s_rel, "--mode", "save", "--id", "sec2"], cwd=tmp)
        txt = fix_routes.read_text(encoding="utf-8").replace(
            "def export_all_ledgers(store: VaultStore, caller_user: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:",
            "@require_role(\"admin\")\ndef export_all_ledgers(store: VaultStore, caller_user: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:",
        )
        fix_routes.write_text(txt, encoding="utf-8")
        print(_run([sys.executable, "-B", str(VS_SCRIPT), "verify", "--s", s_rel, "--id", "sec2", "--auto-rollback", "--test-cmd", suite_cmd], cwd=tmp))

        # SEC-3 Attempt 1: Over-strict patch rejects >1 key -> breaks Authorized Control -> AUTO_RESTORED
        _run([sys.executable, "-B", str(VS_SCRIPT), "sandbox", "--s", s_rel, "--mode", "save", "--id", "sec3"], cwd=tmp)
        bad_sec3 = fix_routes.read_text(encoding="utf-8").replace(
            "    user = store.users[caller_user[\"id\"]]\n    user.update(payload)",
            "    if len(payload) > 1:\n        raise PermissionError(\"403 overstrict\")\n    user = store.users[caller_user[\"id\"]]\n    user.update(payload)",
        )
        fix_routes.write_text(bad_sec3, encoding="utf-8")
        v3_bad = subprocess.run(
            [sys.executable, "-B", str(VS_SCRIPT), "verify", "--s", s_rel, "--id", "sec3", "--auto-rollback", "--test-cmd", suite_cmd],
            cwd=str(tmp),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        print(v3_bad.stdout.strip())
        assert "REJECTED_CONTROL_BROKEN" in v3_bad.stdout and "AUTO_RESTORED" in v3_bad.stdout

        # SEC-3 Attempt 2: Proper whitelist patch -> CONFIRMED_REMEDIATED
        good_sec3 = fix_routes.read_text(encoding="utf-8").replace(
            "    user = store.users[caller_user[\"id\"]]\n    user.update(payload)",
            "    allowed = frozenset({\"display_name\", \"bio\"})\n"
            "    forbidden = set(payload) - allowed\n"
            "    if forbidden:\n"
            "        raise PermissionError(f\"403 Forbidden fields: {sorted(forbidden)}\")\n"
            "    user = store.users[caller_user[\"id\"]]\n"
            "    for k, v in payload.items():\n"
            "        user[k] = v",
        )
        fix_routes.write_text(good_sec3, encoding="utf-8")
        print(_run([sys.executable, "-B", str(VS_SCRIPT), "verify", "--s", s_rel, "--id", "sec3", "--auto-rollback", "--test-cmd", suite_cmd], cwd=tmp))

        # SEC-4: Fix RACE_DOUBLE_SPEND with store.lock
        _run([sys.executable, "-B", str(VS_SCRIPT), "sandbox", "--s", s_rel, "--mode", "save", "--id", "sec4"], cwd=tmp)
        good_sec4 = fix_routes.read_text(encoding="utf-8").replace(
            "    voucher = store.vouchers.get(code)\n"
            "    if voucher is None:\n"
            "        raise KeyError(f\"Voucher not found: {code}\")\n"
            "    if voucher[\"remaining_uses\"] > 0:\n"
            "        time.sleep(0.008)\n"
            "        voucher[\"remaining_uses\"] -= 1\n"
            "        store.users[caller_user[\"id\"]][\"balance\"] += voucher[\"amount\"]\n"
            "        return store.users[caller_user[\"id\"]][\"balance\"]",
            "    with store.lock:\n"
            "        voucher = store.vouchers.get(code)\n"
            "        if voucher is None:\n"
            "            raise KeyError(f\"Voucher not found: {code}\")\n"
            "        if voucher[\"remaining_uses\"] > 0:\n"
            "            time.sleep(0.008)\n"
            "            voucher[\"remaining_uses\"] -= 1\n"
            "            store.users[caller_user[\"id\"]][\"balance\"] += voucher[\"amount\"]\n"
            "            return store.users[caller_user[\"id\"]][\"balance\"]",
        )
        fix_routes.write_text(good_sec4, encoding="utf-8")
        print(_run([sys.executable, "-B", str(VS_SCRIPT), "verify", "--s", s_rel, "--id", "sec4", "--auto-rollback", "--test-cmd", suite_cmd], cwd=tmp))

        print("\n=== Phase 6: Summary, Diff, Secret Scan & Cleanliness ===")
        sum_out = _run([sys.executable, "-B", str(VS_SCRIPT), "summary", "--s", s_rel, "--snippets"], cwd=tmp)
        diff_out = _run([sys.executable, "-B", str(VS_SCRIPT), "sandbox", "--s", s_rel, "--mode", "diff"], cwd=tmp)
        scan_out = _run([sys.executable, "-B", str(VS_SCRIPT), "redact-output", "--s", s_rel, "--scan"], cwd=tmp)
        clean_out = _run([sys.executable, "-B", str(VS_SCRIPT), "sandbox", "--s", s_rel, "--mode", "clean"], cwd=tmp)
        print(sum_out)
        print(scan_out)
        print(clean_out)

        # Save live sample report back to examples/vault_api_demo/sample-sec-report.md
        sample_report = (
            "# Sample VeriSec Business-Logic Security Advisory (`vault_api_demo`)\n\n"
            "> Generated by `python -B examples/vault_api_demo/run_demo.py` via `scripts/vs.py`.\n\n"
            "## 1. API Surface & Auth Matrix (`vs.py surface-map`)\n\n"
            "```text\n" + surf_out + "\n```\n\n"
            "## 2. Dual-Gate Verification Summary & Redacted Snippets (`vs.py summary --snippets`)\n\n"
            + sum_out + "\n\n"
            "## 3. Sandbox-Verified Remediation Diff (`vs.py sandbox --mode diff`)\n\n"
            "```diff\n" + diff_out + "\n```\n\n"
            "## 4. Secret Redaction & Workspace Cleanliness Audit\n\n"
            "```text\n" + scan_out + "\n" + clean_out + "\n```\n"
        )
        (EXAMPLE_DIR / "sample-sec-report.md").write_text(sample_report, encoding="utf-8")
        assert "unredacted_remaining=0 status=CLEAN" in scan_out
        assert "cleanliness: CLEAN" in clean_out
        print("\n[DEMO SUCCESS] Updated sample-sec-report.md and verified all Dual-Gate checks.")
        return 0
    finally:
        vs._remove_readonly_and_rmtree(tmp)


if __name__ == "__main__":
    raise SystemExit(main())
