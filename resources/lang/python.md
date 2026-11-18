# Python Security PoC Adapter

## 1. Target Resolution & Isolation
- `vs.py` injects `S/tmp/netguard` (`sitecustomize.py` blocking non-loopback `socket`/`getaddrinfo` calls) and sets `VERISEC_TARGET_ROOT` (`ROOT` in `baseline`, `S/sandbox-fix` in `remediation`).
- Always insert `VERISEC_TARGET_ROOT` at `sys.path[0]` before importing project modules:
```python
import os, sys
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[3]
TARGET_ROOT = Path(os.environ.get("VERISEC_TARGET_ROOT", str(DEFAULT_ROOT)))
sys.path.insert(0, str(TARGET_ROOT))
```

## 2. Standard `unittest` PoC Template (`S/pocs/poc_sec1.py`)
```python
# ID: SEC-1 | Category: IDOR_BOLA | Target: vault_app/routes.py:get_invoice
import os, sys, unittest
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, os.environ.get("VERISEC_TARGET_ROOT", str(DEFAULT_ROOT)))

from vault_app.routes import get_invoice
from vault_app.store import reset_store

class TestSec1IdorBola(unittest.TestCase):
    def setUp(self):
        self.store = reset_store()
        self.alice = {"id": "user-a", "role": "member"}
        self.bob = {"id": "user-b", "role": "member"}

    def test_control_authorized_owner_can_read(self):
        inv = get_invoice(self.store, self.alice, "INV-101")
        self.assertEqual(inv["owner_id"], "user-a")

    def test_unauthorized_cross_account_idor_blocked(self):
        with self.assertRaises(PermissionError, msg="VERISEC_BREACH_PROVEN: cross-account invoice read"):
            get_invoice(self.store, self.bob, "INV-101")

if __name__ == "__main__":
    unittest.main(verbosity=2)
```

## 3. Concurrency (`RACE_DOUBLE_SPEND`) Template
```python
import threading

def run_race_redeem(fn, store, user, code, workers=8):
    barrier = threading.Barrier(workers)
    results = []
    lock = threading.Lock()
    def worker():
        barrier.wait(timeout=5)
        try:
            res = fn(store, user, code)
            with lock:
                results.append(("ok", res))
        except Exception as exc:
            with lock:
                results.append(("err", type(exc).__name__))
    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=5)
    return results
```

## 4. Running PoCs & Dual-Gate Verify
- **Gate 1 (Baseline):** `python "<VS>" isolated-poc --s "$S" --id sec1 --phase baseline --category IDOR_BOLA -- python "$S/pocs/poc_sec1.py"`
- **Gate 2 (Remediation):** `python "<VS>" verify --s "$S" --id sec1 --auto-rollback --test-cmd "python -m unittest discover -s tests -v"` (or `python -m pytest -p no:cacheprovider -q`)
