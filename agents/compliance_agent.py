"""Compliance agent: runs the AML rules for a transaction (no model involved).

`check` is used inside each investigation, so every rule hit appears in the
PRISM trace. `screen_all` scans a whole dataset, e.g. to find structuring
that never triggers the fraud alert rule.
"""
from __future__ import annotations

import pandas as pd

from core.data import LABEL_COLUMNS
from detection.compliance_rules import RuleHit, check_transaction, load_watchlist


def check(txn: dict, past: pd.DataFrame, watchlist: set[str] | None = None) -> list[RuleHit]:
    return check_transaction(txn, past, load_watchlist() if watchlist is None else watchlist)


def screen_all(transactions: pd.DataFrame, watchlist: set[str] | None = None) -> pd.DataFrame:
    """One row per rule hit across the dataset, in time order."""
    watchlist = load_watchlist() if watchlist is None else watchlist
    visible = transactions.drop(columns=[c for c in LABEL_COLUMNS if c in transactions.columns])
    visible = visible.reset_index(drop=True)
    rows = []
    for i, txn in enumerate(visible.to_dict("records")):
        if txn["type"] not in ("TRANSFER", "CASH_OUT"):
            continue
        for hit in check_transaction(txn, visible.iloc[:i], watchlist):
            rows.append({"txn_id": txn["txn_id"], "step": txn["step"], **hit.to_dict()})
    return pd.DataFrame(rows, columns=["txn_id", "step", "rule_id", "name", "severity", "evidence"])
