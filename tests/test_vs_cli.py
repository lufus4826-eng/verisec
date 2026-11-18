#!/usr/bin/env python3
"""Automated unit & integration verification suite for VeriSec CLI (`scripts/vs.py`)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest


TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parents[0]
SCRIPTS_DIR = REPO_ROOT / "scripts"
VS_SCRIPT = SCRIPTS_DIR / "vs.py"

sys.path.insert(0, str(SCRIPTS_DIR))
import vs  # noqa: E402


def run_vs(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-B", str(VS_SCRIPT), *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


class TestVeriSecCli(unittest.TestCase):
    def setUp(self) -> None:
        vs.configure_stdio()
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="verisec_test_"))

    def tearDown(self) -> None:
        vs._remove_readonly_and_rmtree(self.tmp_dir)

    def _init_session(self) -> Path:
        proc = run_vs(["init", "--root", str(self.tmp_dir)], cwd=self.tmp_dir)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        meta = json.loads(proc.stdout.strip())
        return self.tmp_dir / meta["S"]

    def test_init_and_log_redaction(self) -> None:
        s_dir = self._init_session()
        self.assertTrue((s_dir / "pocs").is_dir())
        self.assertTrue((s_dir / "logs" / "fs-before.txt").is_file())
        self.assertTrue((s_dir / "tmp" / "netguard" / "sitecustomize.py").is_file())
        self.assertTrue((s_dir / "worklog.md").is_file())

        p_log = run_vs(
            [
                "log",
                "--s",
                str(s_dir),
                "--status",
                "Phase 3 - Running",
                "--entry",
                "SEC-1 | token=Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.sig12345678 password=TopSecret99!",
            ],
            cwd=self.tmp_dir,
        )
        self.assertEqual(p_log.returncode, 0, p_log.stderr + p_log.stdout)
        self.assertIn("redactions=2", p_log.stdout)
        wl = (s_dir / "worklog.md").read_text(encoding="utf-8")
        self.assertTrue(wl.startswith("Status: Phase 3 - Running"))
        self.assertNotIn("TopSecret99!", wl)
        self.assertNotIn("sig12345678", wl)
        self.assertIn("[REDACTED_TOKEN]", wl)
        self.assertIn("[REDACTED_SECRET]", wl)

    def test_redact_output_comprehensive(self) -> None:
        raw = (
            'Authorization: Bearer abcdef1234567890XYZ\n'
            'Authorization: Basic dXNlcjpwYXNzd29yZA==\n'
            'jwt=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYm9iIn0.deadbeef123456\n'
            '{"api_token": "sk-live-9876543210abcdef12", "client_secret": "s3cr3t_value_xyz"}\n'
            'github=ghp_1234567890abcdef1234567890\n'
            'db=postgres://admin:P4ssword!99@db.internal:5432/prod\n'
            'safe_test=test_secret_handling_ok\n'
        )
        masked, count = vs.redact_secrets(raw)
        self.assertGreaterEqual(count, 6)
        for leak in (
            "abcdef1234567890XYZ",
            "dXNlcjpwYXNzd29yZA==",
            "deadbeef123456",
            "sk-live-9876543210abcdef12",
            "s3cr3t_value_xyz",
            "ghp_1234567890abcdef1234567890",
            "P4ssword!99",
        ):
            self.assertNotIn(leak, masked)
        self.assertIn("test_secret_handling_ok", masked)

        # Idempotency check & remaining scan check
        masked2, count2 = vs.redact_secrets(masked)
        self.assertEqual(count2, 0)
        self.assertEqual(masked2, masked)
        self.assertEqual(vs.find_unredacted_secrets(masked), [])

        # Session --scan CLI test
        s_dir = self._init_session()
        leak_log = s_dir / "logs" / "leak.log"
        leak_log.write_text("X-API-Key: supersecret998877\n", encoding="utf-8")
        p_scan = run_vs(["redact-output", "--s", str(s_dir), "--scan"], cwd=self.tmp_dir)
        self.assertEqual(p_scan.returncode, 0, p_scan.stdout + p_scan.stderr)
        self.assertIn("unredacted_remaining=0 status=CLEAN", p_scan.stdout)
        self.assertNotIn("supersecret998877", leak_log.read_text(encoding="utf-8"))

    def test_surface_map_multi_lang(self) -> None:
        (self.tmp_dir / "app").mkdir()
        (self.tmp_dir / "app" / "routes.py").write_text(
            '''
def require_role(role):
    return lambda fn: fn

@require_role("admin")
def admin_purge(caller_user):
    return True

def get_invoice(caller_user, invoice_id):
    """Missing owner_id check — docstring should not suppress IDOR detection."""
    return DB["invoices"][invoice_id]

def export_all_ledgers(caller_user):
    """Missing @require_role('admin') — docstring should not suppress guard check."""
    return list(DB["ledgers"].values())

def update_profile(caller_user, payload):
    """Directly updates without whitelist — docstring must not suppress mass assignment."""
    # model keys: role, is_admin, balance
    user = DB["users"][caller_user["id"]]
    user.update(payload)
    return user

def redeem_voucher(caller_user, code):
    v = DB["vouchers"][code]
    if v["remaining_uses"] > 0:
        v["remaining_uses"] -= 1
        DB["users"][caller_user["id"]]["balance"] += v["amount"]
    return True
''',
            encoding="utf-8",
        )
        (self.tmp_dir / "app" / "server.js").write_text(
            '''
app.get("/admin/stats", requireAuth, (req, res) => res.json({ok: true}));
app.get("/api/orders/:orderId", (req, res) => {
  const row = orders.findById(req.params.orderId);
  res.json(row);
});
''',
            encoding="utf-8",
        )
        (self.tmp_dir / "tests").mkdir()
        (self.tmp_dir / "tests" / "test_ignore.py").write_text(
            "def get_fake(x_id): return store[x_id]\n", encoding="utf-8"
        )

        s_dir = self._init_session()
        proc = run_vs(["surface-map", "--root", str(self.tmp_dir), "--s", str(s_dir)], cwd=self.tmp_dir)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        self.assertLessEqual(len(lines), 35)
        self.assertIn("IDOR_BOLA", proc.stdout)
        self.assertIn("MISSING_AUTH_GUARD", proc.stdout)
        self.assertIn("MASS_ASSIGNMENT", proc.stdout)
        self.assertIn("RACE_DOUBLE_SPEND", proc.stdout)
        self.assertNotIn("test_ignore.py", proc.stdout)

    def test_isolated_poc_network_block(self) -> None:
        s_dir = self._init_session()
        poc_ext = s_dir / "pocs" / "poc_net.py"
        poc_ext.write_text(
            '''import socket, unittest
class TestNet(unittest.TestCase):
    def test_control_loopback(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        cli = socket.create_connection(("127.0.0.1", port), timeout=1)
        cli.close(); srv.close()
    def test_unauthorized_outbound_attempt(self):
        socket.create_connection(("8.8.8.8", 53), timeout=1)
if __name__ == "__main__":
    unittest.main(verbosity=2)
''',
            encoding="utf-8",
        )
        proc = run_vs(
            [
                "isolated-poc",
                "--s",
                str(s_dir),
                "--id",
                "net1",
                "--phase",
                "baseline",
                "--",
                sys.executable,
                str(poc_ext),
            ],
            cwd=self.tmp_dir,
        )
        # Must catch network isolation violation and exit with harness error (code 2)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("VIOLATION DETECTED", proc.stdout)
        self.assertIn("HARNESS_BROKEN", proc.stdout)

    def test_gate1_breach_vs_refuted_safe(self) -> None:
        (self.tmp_dir / "svc.py").write_text(
            '''
DOCS = {"D1": {"owner": "alice", "secret_key": "sk-live-secret1234567890"}}

def read_doc_vuln(user, doc_id):
    return DOCS[doc_id]

def read_doc_safe(user, doc_id):
    d = DOCS[doc_id]
    if d["owner"] != user:
        raise PermissionError("forbidden")
    return d
''',
            encoding="utf-8",
        )
        s_dir = self._init_session()
        poc_vuln = s_dir / "pocs" / "poc_vuln.py"
        poc_vuln.write_text(
            '''import os, sys, unittest
sys.path.insert(0, os.environ["VERISEC_TARGET_ROOT"])
import svc
class TestVuln(unittest.TestCase):
    def test_control_owner(self):
        self.assertEqual(svc.read_doc_vuln("alice", "D1")["owner"], "alice")
    def test_unauthorized_idor(self):
        with self.assertRaises(PermissionError):
            svc.read_doc_vuln("bob", "D1")
if __name__ == "__main__":
    unittest.main(verbosity=2)
''',
            encoding="utf-8",
        )
        poc_safe = s_dir / "pocs" / "poc_safe.py"
        poc_safe.write_text(
            '''import os, sys, unittest
sys.path.insert(0, os.environ["VERISEC_TARGET_ROOT"])
import svc
class TestSafe(unittest.TestCase):
    def test_control_owner(self):
        self.assertEqual(svc.read_doc_safe("alice", "D1")["owner"], "alice")
    def test_unauthorized_idor(self):
        with self.assertRaises(PermissionError):
            svc.read_doc_safe("bob", "D1")
if __name__ == "__main__":
    unittest.main(verbosity=2)
''',
            encoding="utf-8",
        )

        # Vulnerable -> BREACH_CONFIRMED -> GATE1_BREACH_CONFIRMED
        p1 = run_vs(["isolated-poc", "--s", str(s_dir), "--id", "sec1", "--phase", "baseline", "--", sys.executable, str(poc_vuln)], cwd=self.tmp_dir)
        self.assertEqual(p1.returncode, 0, p1.stdout)
        self.assertIn("BREACH_CONFIRMED", p1.stdout)
        v1 = run_vs(["verify", "--s", str(s_dir), "--id", "sec1", "--gate1-only"], cwd=self.tmp_dir)
        self.assertEqual(v1.returncode, 0, v1.stdout)
        self.assertIn("GATE1_BREACH_CONFIRMED", v1.stdout)

        # Safe -> BREACH_BLOCKED -> REFUTED_SAFE
        p2 = run_vs(["isolated-poc", "--s", str(s_dir), "--id", "sec2", "--phase", "baseline", "--", sys.executable, str(poc_safe)], cwd=self.tmp_dir)
        self.assertEqual(p2.returncode, 0, p2.stdout)
        self.assertIn("BREACH_BLOCKED", p2.stdout)
        v2 = run_vs(["verify", "--s", str(s_dir), "--id", "sec2", "--gate1-only"], cwd=self.tmp_dir)
        self.assertEqual(v2.returncode, 0, v2.stdout)
        self.assertIn("REFUTED_SAFE", v2.stdout)

    def test_gate2_overstrict_patch_auto_rollback(self) -> None:
        (self.tmp_dir / "profile.py").write_text(
            '''
USERS = {"alice": {"display_name": "Alice", "bio": "Old", "role": "member"}}
def update_profile(uid, payload):
    USERS[uid].update(payload)
    return USERS[uid]
''',
            encoding="utf-8",
        )
        (self.tmp_dir / "test_app.py").write_text(
            '''import unittest
import profile
class TestProfileSuite(unittest.TestCase):
    def test_bio_update(self):
        profile.USERS["alice"] = {"display_name": "Alice", "bio": "Old", "role": "member"}
        res = profile.update_profile("alice", {"bio": "New"})
        self.assertEqual(res["bio"], "New")
if __name__ == "__main__":
    unittest.main()
''',
            encoding="utf-8",
        )
        s_dir = self._init_session()
        poc = s_dir / "pocs" / "poc_mass.py"
        poc.write_text(
            '''import os, sys, unittest
sys.path.insert(0, os.environ["VERISEC_TARGET_ROOT"])
import profile
class TestMass(unittest.TestCase):
    def setUp(self):
        profile.USERS["alice"] = {"display_name": "Alice", "bio": "Old", "role": "member"}
    def test_control_authorized_multi_field_update(self):
        res = profile.update_profile("alice", {"display_name": "Alice B.", "bio": "Staff"})
        self.assertEqual(res["display_name"], "Alice B.")
        self.assertEqual(res["bio"], "Staff")
    def test_unauthorized_mass_assignment_role_blocked(self):
        with self.assertRaises(PermissionError):
            profile.update_profile("alice", {"display_name": "Mallory", "role": "admin"})
if __name__ == "__main__":
    unittest.main(verbosity=2)
''',
            encoding="utf-8",
        )

        run_vs(["isolated-poc", "--s", str(s_dir), "--id", "sec3", "--phase", "baseline", "--category", "MASS_ASSIGNMENT", "--", sys.executable, str(poc)], cwd=self.tmp_dir)
        run_vs(["sandbox", "--s", str(s_dir), "--mode", "fix"], cwd=self.tmp_dir)
        run_vs(["sandbox", "--s", str(s_dir), "--mode", "save", "--id", "sec3"], cwd=self.tmp_dir)

        fix_profile = s_dir / "sandbox-fix" / "profile.py"
        original_bytes = fix_profile.read_bytes()

        # Attempt 1: Overly strict patch rejects >1 key -> breaks test_control_authorized_multi_field_update!
        fix_profile.write_text(
            '''
USERS = {"alice": {"display_name": "Alice", "bio": "Old", "role": "member"}}
def update_profile(uid, payload):
    if len(payload) > 1:
        raise PermissionError("overstrict: only 1 field allowed")
    USERS[uid].update(payload)
    return USERS[uid]
''',
            encoding="utf-8",
        )
        v_bad = run_vs(
            [
                "verify",
                "--s",
                str(s_dir),
                "--id",
                "sec3",
                "--auto-rollback",
                "--test-cmd",
                f'"{sys.executable}" -m unittest test_app.py',
            ],
            cwd=self.tmp_dir,
        )
        self.assertNotEqual(v_bad.returncode, 0)
        self.assertIn("REJECTED_CONTROL_BROKEN", v_bad.stdout)
        self.assertIn("AUTO_RESTORED", v_bad.stdout)
        # Verify byte-for-byte rollback!
        self.assertEqual(fix_profile.read_bytes(), original_bytes)

        # Attempt 2: Blocks role AND keeps PoC control passing, but breaks host test_app.py -> REJECTED_TEST_REGRESSION
        fix_profile.write_text(
            '''
USERS = {"alice": {"display_name": "Alice", "bio": "Old", "role": "member"}}
def update_profile(uid, payload):
    if "role" in payload:
        raise PermissionError("role forbidden")
    if len(payload) == 1 and "bio" in payload:
        USERS[uid]["bio"] = "BROKEN_FOR_SUITE"
    else:
        USERS[uid].update(payload)
    return USERS[uid]
''',
            encoding="utf-8",
        )
        v_reg = run_vs(
            [
                "verify",
                "--s",
                str(s_dir),
                "--id",
                "sec3",
                "--auto-rollback",
                "--test-cmd",
                f'"{sys.executable}" -m unittest test_app.py',
            ],
            cwd=self.tmp_dir,
        )
        self.assertNotEqual(v_reg.returncode, 0)
        self.assertIn("REJECTED_TEST_REGRESSION", v_reg.stdout)
        self.assertIn("AUTO_RESTORED", v_reg.stdout)
        self.assertEqual(fix_profile.read_bytes(), original_bytes)

        # Attempt 3: Proper whitelist patch -> CONFIRMED_REMEDIATED
        fix_profile.write_text(
            '''
USERS = {"alice": {"display_name": "Alice", "bio": "Old", "role": "member"}}
ALLOWED = frozenset({"display_name", "bio"})
def update_profile(uid, payload):
    disallowed = set(payload) - ALLOWED
    if disallowed:
        raise PermissionError(f"forbidden fields: {sorted(disallowed)}")
    for k, v in payload.items():
        USERS[uid][k] = v
    return USERS[uid]
''',
            encoding="utf-8",
        )
        v_ok = run_vs(
            [
                "verify",
                "--s",
                str(s_dir),
                "--id",
                "sec3",
                "--auto-rollback",
                "--test-cmd",
                f'"{sys.executable}" -m unittest test_app.py',
            ],
            cwd=self.tmp_dir,
        )
        self.assertEqual(v_ok.returncode, 0, v_ok.stdout + v_ok.stderr)
        self.assertIn("CONFIRMED_REMEDIATED", v_ok.stdout)

    def test_both_poc_modes_json_and_unittest(self) -> None:
        (self.tmp_dir / "gate.py").write_text("ALLOW_ADMIN = True\n", encoding="utf-8")
        s_dir = self._init_session()
        poc_json = s_dir / "pocs" / "poc_json.py"
        poc_json.write_text(
            '''import json, os, sys
sys.path.insert(0, os.environ["VERISEC_TARGET_ROOT"])
import gate
print("VERISEC_POC:" + json.dumps({
    "id": "sec4",
    "category": "MISSING_AUTH_GUARD",
    "control_authorized": "PASS",
    "breach_detected": bool(gate.ALLOW_ADMIN),
    "network_isolated": True,
    "details": "Unauth user reached admin endpoint; token=Bearer jwtsecret1234567890"
}))
''',
            encoding="utf-8",
        )
        p_base = run_vs(["isolated-poc", "--s", str(s_dir), "--id", "sec4", "--phase", "baseline", "--", sys.executable, str(poc_json)], cwd=self.tmp_dir)
        self.assertEqual(p_base.returncode, 0, p_base.stdout)
        self.assertIn("BREACH_CONFIRMED", p_base.stdout)
        self.assertNotIn("jwtsecret1234567890", p_base.stdout)

        run_vs(["sandbox", "--s", str(s_dir), "--mode", "fix"], cwd=self.tmp_dir)
        (s_dir / "sandbox-fix" / "gate.py").write_text("ALLOW_ADMIN = False\n", encoding="utf-8")
        p_ver = run_vs(["verify", "--s", str(s_dir), "--id", "sec4", "--auto-rollback"], cwd=self.tmp_dir)
        self.assertEqual(p_ver.returncode, 0, p_ver.stdout)
        self.assertIn("CONFIRMED_REMEDIATED", p_ver.stdout)

        p_sum = run_vs(["summary", "--s", str(s_dir), "--snippets"], cwd=self.tmp_dir)
        self.assertEqual(p_sum.returncode, 0, p_sum.stdout)
        self.assertIn("CONFIRMED_REMEDIATED", p_sum.stdout)
        self.assertNotIn("jwtsecret1234567890", p_sum.stdout)
        self.assertIn("[REDACTED_TOKEN]", p_sum.stdout)

    def test_sandbox_diff_redaction_and_cleanliness(self) -> None:
        (self.tmp_dir / "cfg.py").write_text('API_TOKEN = "sk-live-abcdef1234567890"\n', encoding="utf-8")
        s_dir = self._init_session()
        run_vs(["sandbox", "--s", str(s_dir), "--mode", "fix"], cwd=self.tmp_dir)
        (s_dir / "sandbox-fix" / "cfg.py").write_text('API_TOKEN = os.environ["API_TOKEN"]\n', encoding="utf-8")

        p_diff = run_vs(["sandbox", "--s", str(s_dir), "--mode", "diff"], cwd=self.tmp_dir)
        self.assertEqual(p_diff.returncode, 0, p_diff.stdout)
        self.assertNotIn("abcdef1234567890", p_diff.stdout)
        self.assertIn("[REDACTED_KEY]", p_diff.stdout)

        p_clean = run_vs(["sandbox", "--s", str(s_dir), "--mode", "clean"], cwd=self.tmp_dir)
        self.assertEqual(p_clean.returncode, 0, p_clean.stdout)
        self.assertIn("cleanliness: CLEAN", p_clean.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
