"""In-memory data store for the Vault API Demo application."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
import threading
from typing import Any, Dict, List


@dataclass
class VaultStore:
    users: Dict[str, Dict[str, Any]]
    invoices: Dict[str, Dict[str, Any]]
    accounts: Dict[str, Dict[str, Any]]
    vouchers: Dict[str, Dict[str, Any]]
    ledgers: List[Dict[str, Any]]
    audit_logs: List[str]
    lock: threading.Lock = field(default_factory=threading.Lock)


def create_default_store() -> VaultStore:
    return VaultStore(
        users={
            "user-a": {
                "id": "user-a",
                "display_name": "Alice",
                "bio": "Finance Analyst",
                "role": "member",
                "balance": 100.0,
                "credit_limit": 1000,
            },
            "user-b": {
                "id": "user-b",
                "display_name": "Bob",
                "bio": "Operations",
                "role": "member",
                "balance": 50.0,
                "credit_limit": 500,
            },
            "admin-1": {
                "id": "admin-1",
                "display_name": "Root Admin",
                "bio": "Security Ops",
                "role": "admin",
                "balance": 0.0,
                "credit_limit": 999999,
            },
        },
        invoices={
            "INV-101": {
                "id": "INV-101",
                "owner_id": "user-a",
                "amount": 2400.0,
                "api_token": "sk-live-9876543210abcdef123456",
            },
            "INV-202": {
                "id": "INV-202",
                "owner_id": "user-b",
                "amount": 150.0,
                "api_token": "sk-live-1122334455abcdef667788",
            },
        },
        accounts={
            "ACC-A": {"id": "ACC-A", "owner_id": "user-a", "balance": 500.0},
            "ACC-B": {"id": "ACC-B", "owner_id": "user-b", "balance": 200.0},
        },
        vouchers={
            "PROMO-100": {"code": "PROMO-100", "amount": 100.0, "remaining_uses": 1},
        },
        ledgers=copy.deepcopy(
            [
                {"tenant": "user-a", "net": 2400.0, "secret_note": "settlement_key=abcd1234efgh"},
                {"tenant": "user-b", "net": 150.0, "secret_note": "settlement_key=zyxw9876vuts"},
            ]
        ),
        audit_logs=["system initialized"],
    )
