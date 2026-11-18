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
        with self.assertRaises(PermissionError, msg="VERISEC_BREACH_PROVEN: bob read alice doc"):
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
        with self.assertRaises(PermissionError, msg="VERISEC_BREACH_PROVEN: role field was accepted"):
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

    def test_nodejs_netguard_blocks_external_socket(self) -> None:
        node_exe = shutil.which("node")
        if not node_exe:
            self.skipTest("node not installed on PATH")
        s_dir = self._init_session()
        poc_js = s_dir / "pocs" / "poc_node_net.mjs"
        poc_js.write_text(
            '''import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";

test("test_control_loopback_allowed", async () => {
  const srv = net.createServer((c) => c.end());
  await new Promise((res) => srv.listen(0, "127.0.0.1", res));
  const port = srv.address().port;
  await new Promise((res, rej) => {
    const cli = net.createConnection({ host: "127.0.0.1", port }, () => { cli.end(); res(); });
    cli.on("error", rej);
  });
  srv.close();
});

test("test_unauthorized_external_node_socket_blocked", async () => {
  await assert.rejects(
    async () => {
      net.createConnection({ host: "8.8.8.8", port: 53 });
    },
    /VERISEC_NET_GUARD/
  );
  // Also trigger unhandled VERISEC_NET_GUARD to ensure vs.py catches any unguarded external attempt
  net.createConnection({ host: "8.8.8.8", port: 53 });
});
''',
            encoding="utf-8",
        )
        proc = run_vs(
            ["isolated-poc", "--s", str(s_dir), "--id", "node_net", "--phase", "baseline", "--", node_exe, "--test", str(poc_js)],
            cwd=self.tmp_dir,
        )
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("VIOLATION DETECTED", proc.stdout)
        self.assertIn("HARNESS_BROKEN", proc.stdout)

    def test_ambiguous_failure_trap_rejected(self) -> None:
        (self.tmp_dir / "app_trap.py").write_text("def check(): return 'ok'\n", encoding="utf-8")
        s_dir = self._init_session()
        poc_bad = s_dir / "pocs" / "poc_ambig.py"
        poc_bad.write_text(
            '''import os, sys, unittest
sys.path.insert(0, os.environ["VERISEC_TARGET_ROOT"])
import app_trap
class TestAmbig(unittest.TestCase):
    def test_control_ok(self):
        self.assertEqual(app_trap.check(), "ok")
    def test_unauthorized_accidental_failure(self):
        self.assertEqual(1, 2, "unrelated test bug without proof marker")
if __name__ == "__main__":
    unittest.main(verbosity=2)
''',
            encoding="utf-8",
        )
        p_bad = run_vs(["isolated-poc", "--s", str(s_dir), "--id", "ambig1", "--phase", "baseline", "--", sys.executable, str(poc_bad)], cwd=self.tmp_dir)
        self.assertEqual(p_bad.returncode, 2, p_bad.stdout)
        self.assertIn("HARNESS_BROKEN", p_bad.stdout)
        self.assertIn("VERISEC_BREACH_PROVEN", p_bad.stdout)
        v_bad = run_vs(["verify", "--s", str(s_dir), "--id", "ambig1", "--gate1-only"], cwd=self.tmp_dir)
        self.assertNotEqual(v_bad.returncode, 0)
        self.assertIn("REJECTED_GATE1_HARNESS", v_bad.stdout)

    def test_encoded_and_registered_secret_redaction(self) -> None:
        import base64
        import urllib.parse

        s_dir = self._init_session()
        canary = "CanaryToken_X99_Secret"
        reg_p = run_vs(["redact-output", "--s", str(s_dir), "--register-secret", canary], cwd=self.tmp_dir)
        self.assertEqual(reg_p.returncode, 0, reg_p.stdout + reg_p.stderr)

        raw_key = "sk-live-9876543210abcdef123456"
        raw_db = "postgres://admin:P4ssword!99@db.internal/prod"
        b64_key = base64.b64encode(raw_key.encode("utf-8")).decode("ascii")
        b64_canary = base64.b64encode(canary.encode("utf-8")).decode("ascii")
        url_db = urllib.parse.quote(raw_db, safe="")
        url_canary = urllib.parse.quote(canary, safe="")

        poc_leak = s_dir / "pocs" / "poc_enc_leak.py"
        poc_leak.write_text(
            f'''import json
print("VERISEC_POC:" + json.dumps({{
    "id": "enc1",
    "category": "IDOR_BOLA",
    "control_authorized": "PASS",
    "breach_detected": True,
    "network_isolated": True,
    "details": "b64={b64_key} b64c={b64_canary} url={url_db} rawc={canary} urlc={url_canary}"
}}))
''',
            encoding="utf-8",
        )
        p_run = run_vs(["isolated-poc", "--s", str(s_dir), "--id", "enc1", "--phase", "baseline", "--", sys.executable, str(poc_leak)], cwd=self.tmp_dir)
        self.assertEqual(p_run.returncode, 0, p_run.stdout + p_run.stderr)
        for hidden in (b64_key, b64_canary, url_db, canary, url_canary):
            self.assertNotIn(hidden, p_run.stdout)
        log_txt = (s_dir / "logs" / "enc1_baseline.log").read_text(encoding="utf-8")
        for hidden in (b64_key, b64_canary, url_db, canary, url_canary):
            self.assertNotIn(hidden, log_txt)
        self.assertIn("[REDACTED_B64_SECRET]", log_txt)
        self.assertIn("[REDACTED_URLENC_SECRET]", log_txt)
        self.assertIn("[REDACTED_CUSTOM_SECRET]", log_txt)

        p_scan = run_vs(["redact-output", "--s", str(s_dir), "--scan"], cwd=self.tmp_dir)
        self.assertEqual(p_scan.returncode, 0, p_scan.stdout)
        self.assertIn("unredacted_remaining=0 status=CLEAN", p_scan.stdout)

    def test_db_race_rejects_in_memory_lock(self) -> None:
        (self.tmp_dir / "db_voucher.py").write_text(
            '''import sqlite3, time

def init_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE IF NOT EXISTS vouchers (code TEXT PRIMARY KEY, remaining INTEGER)")
    conn.execute("DELETE FROM vouchers")
    conn.execute("INSERT INTO vouchers (code, remaining) VALUES ('PROMO-DB', 1)")
    conn.commit()
    conn.close()

def redeem_db_voucher(db_path, code):
    conn = sqlite3.connect(db_path, timeout=5.0)
    cur = conn.cursor()
    row = cur.execute("SELECT remaining FROM vouchers WHERE code = ?", (code,)).fetchone()
    if row and row[0] > 0:
        time.sleep(0.02)
        cur.execute("UPDATE vouchers SET remaining = ? WHERE code = ?", (row[0] - 1, code))
        conn.commit()
        conn.close()
        return True
    conn.close()
    raise ValueError("already redeemed")
''',
            encoding="utf-8",
        )
        s_dir = self._init_session()
        poc_db = s_dir / "pocs" / "poc_db_race.py"
        poc_db.write_text(
            '''import os, sys, tempfile, threading, unittest
from pathlib import Path
sys.path.insert(0, os.environ["VERISEC_TARGET_ROOT"])
import db_voucher

class TestDbRace(unittest.TestCase):
    def test_control_single_redeem(self):
        with tempfile.TemporaryDirectory() as td:
            db = str(Path(td) / "v.db")
            db_voucher.init_db(db)
            self.assertTrue(db_voucher.redeem_db_voucher(db, "PROMO-DB"))
            with self.assertRaises(ValueError):
                db_voucher.redeem_db_voucher(db, "PROMO-DB")

    def test_unauthorized_concurrent_db_double_spend_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            db = str(Path(td) / "v.db")
            db_voucher.init_db(db)
            workers = 6
            barrier = threading.Barrier(workers)
            ok = []
            lock = threading.Lock()
            def worker():
                barrier.wait(timeout=5)
                try:
                    db_voucher.redeem_db_voucher(db, "PROMO-DB")
                    with lock:
                        ok.append(1)
                except Exception:
                    pass
            threads = [threading.Thread(target=worker) for _ in range(workers)]
            for t in threads: t.start()
            for t in threads: t.join(timeout=5)
            self.assertEqual(len(ok), 1, f"VERISEC_BREACH_PROVEN: DB double-spend {len(ok)} != 1")

if __name__ == "__main__":
    unittest.main(verbosity=2)
''',
            encoding="utf-8",
        )
        run_vs(["isolated-poc", "--s", str(s_dir), "--id", "db_race", "--phase", "baseline", "--category", "RACE_DOUBLE_SPEND", "--", sys.executable, str(poc_db)], cwd=self.tmp_dir)
        run_vs(["sandbox", "--s", str(s_dir), "--mode", "fix"], cwd=self.tmp_dir)
        run_vs(["sandbox", "--s", str(s_dir), "--mode", "save", "--id", "db_race"], cwd=self.tmp_dir)

        fix_db = s_dir / "sandbox-fix" / "db_voucher.py"
        orig_bytes = fix_db.read_bytes()

        # Attempt 1: Patch with in-memory threading.Lock on sqlite3 DB -> MUST BE REJECTED_IN_MEMORY_LOCK_ON_DB!
        fix_db.write_text(
            '''import sqlite3, threading, time
_MEM_LOCK = threading.Lock()

def init_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE IF NOT EXISTS vouchers (code TEXT PRIMARY KEY, remaining INTEGER)")
    conn.execute("DELETE FROM vouchers")
    conn.execute("INSERT INTO vouchers (code, remaining) VALUES ('PROMO-DB', 1)")
    conn.commit()
    conn.close()

def redeem_db_voucher(db_path, code):
    with _MEM_LOCK:
        conn = sqlite3.connect(db_path, timeout=5.0)
        cur = conn.cursor()
        row = cur.execute("SELECT remaining FROM vouchers WHERE code = ?", (code,)).fetchone()
        if row and row[0] > 0:
            time.sleep(0.02)
            cur.execute("UPDATE vouchers SET remaining = ? WHERE code = ?", (row[0] - 1, code))
            conn.commit()
            conn.close()
            return True
        conn.close()
        raise ValueError("already redeemed")
''',
            encoding="utf-8",
        )
        v_mem = run_vs(["verify", "--s", str(s_dir), "--id", "db_race", "--auto-rollback"], cwd=self.tmp_dir)
        self.assertNotEqual(v_mem.returncode, 0)
        self.assertIn("REJECTED_IN_MEMORY_LOCK_ON_DB", v_mem.stdout)
        self.assertIn("AUTO_RESTORED", v_mem.stdout)
        self.assertEqual(fix_db.read_bytes(), orig_bytes)

        # Attempt 2: Patch with atomic SQL UPDATE ... WHERE remaining > 0 -> CONFIRMED_REMEDIATED
        fix_db.write_text(
            '''import sqlite3

def init_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE IF NOT EXISTS vouchers (code TEXT PRIMARY KEY, remaining INTEGER)")
    conn.execute("DELETE FROM vouchers")
    conn.execute("INSERT INTO vouchers (code, remaining) VALUES ('PROMO-DB', 1)")
    conn.commit()
    conn.close()

def redeem_db_voucher(db_path, code):
    conn = sqlite3.connect(db_path, timeout=5.0)
    cur = conn.cursor()
    cur.execute("UPDATE vouchers SET remaining = remaining - 1 WHERE code = ? AND remaining > 0", (code,))
    updated = cur.rowcount
    conn.commit()
    conn.close()
    if updated == 1:
        return True
    raise ValueError("already redeemed")
''',
            encoding="utf-8",
        )
        v_sql = run_vs(["verify", "--s", str(s_dir), "--id", "db_race", "--auto-rollback"], cwd=self.tmp_dir)
        self.assertEqual(v_sql.returncode, 0, v_sql.stdout + v_sql.stderr)
        self.assertIn("CONFIRMED_REMEDIATED", v_sql.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
