"""Business-logic route handlers for Vault API Demo (contains intentional flaws for VeriSec demo)."""

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
    """SEC-1 (IDOR_BOLA): Fetches invoice by ID without checking owner_id == caller_user['id']."""
    inv = store.invoices.get(invoice_id)
    if inv is None:
        raise KeyError(f"Invoice not found: {invoice_id}")
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
