"""Baseline functional unit tests for Vault API Demo."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(os.environ.get("VERISEC_TARGET_ROOT", str(Path(__file__).resolve().parents[1])))
sys.path.insert(0, str(ROOT))

from vault_app import routes  # noqa: E402
from vault_app.store import create_default_store  # noqa: E402


class TestVaultAppBaseline(unittest.TestCase):
    def setUp(self) -> None:
        self.store = create_default_store()
        self.alice = self.store.users["user-a"]
        self.admin = self.store.users["admin-1"]

    def test_owner_reads_own_invoice(self) -> None:
        inv = routes.get_invoice(self.store, self.alice, "INV-101")
        self.assertEqual(inv["amount"], 2400.0)

    def test_admin_exports_and_purges_ledgers(self) -> None:
        rows = routes.export_all_ledgers(self.store, self.admin)
        self.assertEqual(len(rows), 2)
        purged = routes.admin_purge_logs(self.store, self.admin)
        self.assertEqual(purged, 1)

    def test_member_updates_profile_fields(self) -> None:
        updated = routes.update_profile(self.store, self.alice, {"display_name": "Alice B.", "bio": "VP Finance"})
        self.assertEqual(updated["display_name"], "Alice B.")
        self.assertEqual(updated["bio"], "VP Finance")
        self.assertEqual(updated["role"], "member")

    def test_voucher_single_redemption(self) -> None:
        bal = routes.redeem_promo_voucher(self.store, self.alice, "PROMO-100")
        self.assertEqual(bal, 200.0)
        with self.assertRaises(ValueError):
            routes.redeem_promo_voucher(self.store, self.alice, "PROMO-100")

    def test_authorized_transfer_funds(self) -> None:
        res = routes.transfer_funds(self.store, self.alice, "ACC-A", "ACC-B", 100.0)
        self.assertEqual(res["from_balance"], 400.0)
        self.assertEqual(res["to_balance"], 300.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
