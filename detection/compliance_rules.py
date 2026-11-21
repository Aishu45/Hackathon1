"""AML compliance rules: deterministic checks on one transaction.

Each rule looks only at the transaction under review and the transactions
before it, and returns a RuleHit when it fires. Rules are plain code so they
give the same answer every time and are easy to audit.

All thresholds are in config/settings.py.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

import pandas as pd

from config import settings


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    name: str
    severity: str  # "high" blocks approval; "medium" is shown to the analyst
    evidence: str

    def to_dict(self) -> dict:
        return asdict(self)


def load_watchlist(path: Path | None = None) -> set[str]:
    path = path or settings.WATCHLIST_CSV
    if not Path(path).exists():
        return set()
    return set(pd.read_csv(path)["account_id"].astype(str))


def net_recent_inflow(past: pd.DataFrame, account: str, step: int, hours: int) -> float:
    """Money received minus money sent by `account` in the last `hours`."""
    window = past[past["step"] > step - hours]
    received = float(window.loc[window["nameDest"] == account, "amount"].sum())
    sent = float(window.loc[window["nameOrig"] == account, "amount"].sum())
    return received - sent


def sanctions_screening(txn: dict, past: pd.DataFrame, watchlist: set[str]) -> RuleHit | None:
    """AML-01: either party is on the sanctions watchlist."""
    matches = [p for p in (txn["nameOrig"], txn["nameDest"]) if p in watchlist]
    if matches:
        return RuleHit("AML-01", "Sanctions watchlist match", "high",
                       f"{', '.join(matches)} on the watchlist.")
    return None


def structuring(txn: dict, past: pd.DataFrame, watchlist: set[str]) -> RuleHit | None:
    """AML-02: several amounts just under the reporting threshold in a short window."""
    low = settings.REPORTING_THRESHOLD * settings.STRUCTURING_BAND
    high = settings.REPORTING_THRESHOLD
    step = int(txn["step"])
    sent = past[(past["nameOrig"] == txn["nameOrig"])
                & (past["step"] > step - settings.STRUCTURING_WINDOW_HOURS)]
    near = sent[(sent["amount"] >= low) & (sent["amount"] < high)]
    count = len(near) + (1 if low <= float(txn["amount"]) < high else 0)
    if count >= settings.STRUCTURING_MIN_COUNT:
        return RuleHit("AML-02", "Possible structuring", "high",
                       f"{count} transactions between {low:,.0f} and {high:,.0f} "
                       f"within {settings.STRUCTURING_WINDOW_HOURS}h.")
    return None


def rapid_pass_through(txn: dict, past: pd.DataFrame, watchlist: set[str]) -> RuleHit | None:
    """AML-03: money received recently is sent straight back out (mule behaviour)."""
    step = int(txn["step"])
    inflow = past[(past["nameDest"] == txn["nameOrig"])
                  & (past["step"] > step - settings.PASS_THROUGH_WINDOW_HOURS)]
    # Net of what was already sent on, so a mule's earlier cash-outs don't hide this one.
    received = net_recent_inflow(past, txn["nameOrig"], step, settings.PASS_THROUGH_WINDOW_HOURS)
    amount, balance = float(txn["amount"]), float(txn["oldbalanceOrg"])
    # Out roughly matches what just came in, and that inflow is most of the balance.
    if (received >= settings.PASS_THROUGH_MIN_AMOUNT
            and settings.PASS_THROUGH_SHARE * received <= amount <= received / settings.PASS_THROUGH_SHARE
            and received >= settings.PASS_THROUGH_BALANCE_SHARE * balance):
        return RuleHit("AML-03", "Rapid pass-through", "high",
                       f"Sends {float(txn['amount']):,.0f} out of {received:,.0f} net received "
                       f"from {inflow['nameOrig'].nunique()} sender(s) in the last "
                       f"{settings.PASS_THROUGH_WINDOW_HOURS}h.")
    return None


def unusual_amount(txn: dict, past: pd.DataFrame, watchlist: set[str]) -> RuleHit | None:
    """AML-04: amount far above the customer's normal range."""
    sent = past[past["nameOrig"] == txn["nameOrig"]]
    if len(sent) < settings.UNUSUAL_AMOUNT_MIN_HISTORY:
        return None
    median = float(sent["amount"].median())
    if median > 0 and float(txn["amount"]) >= settings.UNUSUAL_AMOUNT_MULTIPLE * median:
        return RuleHit("AML-04", "Amount far outside normal range", "medium",
                       f"{float(txn['amount']):,.0f} is {float(txn['amount']) / median:,.0f}x "
                       f"the customer's median of {median:,.0f}.")
    return None


RULES = [sanctions_screening, structuring, rapid_pass_through, unusual_amount]


def check_transaction(txn: dict, past: pd.DataFrame, watchlist: set[str]) -> list[RuleHit]:
    return [hit for rule in RULES if (hit := rule(txn, past, watchlist))]
