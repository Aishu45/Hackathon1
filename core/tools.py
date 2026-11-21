"""Investigation tools: each answers one question a fraud analyst would ask.

The tools only see transactions that happened BEFORE the one under review,
and never see the fraud labels, so the agent cannot cheat with hindsight.
"""
from __future__ import annotations

import re
from typing import Any

import pandas as pd

from core.data import LABEL_COLUMNS

ACCOUNT_ID_FORMAT = re.compile(r"[CM]\d{6,}")


def _schema(properties: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": properties, "required": required,
            "additionalProperties": False}


TOOL_DEFINITIONS = [
    {
        "name": "get_customer_history",
        "description": (
            "Past activity of the sending customer before the transaction under review: "
            "number of transactions, typical and largest amounts, transaction types, and how "
            "many times they have paid the given recipient before."
        ),
        "input_schema": _schema({
            "customer_id": {"type": "string", "description": "Sender id, e.g. C100123."},
            "recipient_id": {"type": "string", "description": "Recipient of the transaction under review."},
        }, ["customer_id", "recipient_id"]),
        "strict": True,
    },
    {
        "name": "get_recipient_profile",
        "description": (
            "Profile of the receiving account before the transaction under review: when it "
            "was first seen, how many different senders have paid it, total received, and "
            "how often it cashes money out. Fresh accounts that collect from many senders and "
            "cash out quickly are typical money mules."
        ),
        "input_schema": _schema({
            "recipient_id": {"type": "string", "description": "Recipient id, e.g. C900001 or M200010."},
        }, ["recipient_id"]),
        "strict": True,
    },
    {
        "name": "check_balance_pattern",
        "description": (
            "Balance movements of the transaction under review: what share of the sender's "
            "balance it moves, whether it empties the account, and whether the balances add up."
        ),
        "input_schema": _schema({}, []),
        "strict": True,
    },
    {
        "name": "check_velocity",
        "description": (
            "How busy the sender has been: transactions and total amount in the same hour and "
            "in the previous 24 hours, compared with their normal hourly rate."
        ),
        "input_schema": _schema({
            "customer_id": {"type": "string", "description": "Sender id."},
        }, ["customer_id"]),
        "strict": True,
    },
]

DECISION_TOOL = {
    "name": "submit_decision",
    "description": (
        "Submit the final decision for the transaction under review. Call this exactly once, "
        "after gathering evidence. This only records a recommendation; it does not move money."
    ),
    "input_schema": _schema({
        "decision": {"type": "string", "enum": ["approve", "hold", "escalate"],
                     "description": "approve = release; hold = block pending customer contact; "
                                    "escalate = send to a human analyst."},
        "risk_score": {"type": "integer", "description": "0 (safe) to 100 (certain fraud)."},
        "reasons": {"type": "array", "items": {"type": "string"},
                    "description": "Short evidence-based reasons, most important first."},
        "case_note": {"type": "string",
                      "description": "Two or three sentences an analyst can read in ten seconds."},
    }, ["decision", "risk_score", "reasons", "case_note"]),
    "strict": True,
}


class ToolBox:
    """Runs the investigation tools for one transaction under review."""

    def __init__(self, transactions: pd.DataFrame, txn_id: str):
        visible = transactions.drop(columns=[c for c in LABEL_COLUMNS if c in transactions.columns])
        matches = visible.index[visible["txn_id"] == txn_id]
        if len(matches) == 0:
            raise KeyError(f"Unknown transaction {txn_id}")
        position = visible.index.get_loc(matches[0])
        self.txn = visible.iloc[position].to_dict()
        self.past = visible.iloc[:position]  # strictly earlier rows only

    def run(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        handler = getattr(self, name, None)
        if name not in {t["name"] for t in TOOL_DEFINITIONS} or handler is None:
            raise ValueError(f"Unknown tool {name}")
        self._validate(args)
        return handler(**args)

    def _validate(self, args: dict[str, Any]) -> None:
        """Input validation and need-to-know access.

        ISO/IEC 27001:2022 A.8.3 Information access restriction, A.8.28 Secure
        coding; CIS Controls v8 Control 6 Access Control Management and
        Control 16 Application Software Security. The agent may only look up
        the two parties of the transaction under review.
        """
        parties = {self.txn["nameOrig"], self.txn["nameDest"]}
        for key, value in args.items():
            if key.endswith("_id"):
                if not isinstance(value, str) or not ACCOUNT_ID_FORMAT.fullmatch(value):
                    raise PermissionError(f"Rejected {key}: not a valid account id.")
                if value not in parties:
                    raise PermissionError(
                        f"Access denied to {value}: only the sender and recipient of the "
                        "transaction under review may be looked up.")

    def get_customer_history(self, customer_id: str, recipient_id: str) -> dict:
        sent = self.past[self.past["nameOrig"] == customer_id]
        if sent.empty:
            return {"customer_id": customer_id, "transactions": 0,
                    "note": "No earlier activity from this customer."}
        return {
            "customer_id": customer_id,
            "transactions": int(len(sent)),
            "first_seen_hour": int(sent["step"].min()),
            "median_amount": round(float(sent["amount"].median()), 2),
            "largest_amount": round(float(sent["amount"].max()), 2),
            "types": sent["type"].value_counts().to_dict(),
            "distinct_recipients": int(sent["nameDest"].nunique()),
            "previous_payments_to_this_recipient": int((sent["nameDest"] == recipient_id).sum()),
        }

    def get_recipient_profile(self, recipient_id: str) -> dict:
        received = self.past[self.past["nameDest"] == recipient_id]
        cash_outs = self.past[(self.past["nameOrig"] == recipient_id) & (self.past["type"] == "CASH_OUT")]
        current_step = int(self.txn["step"])
        if received.empty:
            return {"recipient_id": recipient_id, "payments_received": 0,
                    "note": "Recipient has never received money before (brand-new account)."}
        return {
            "recipient_id": recipient_id,
            "is_merchant": recipient_id.startswith("M"),
            "first_seen_hour": int(received["step"].min()),
            "account_age_hours": current_step - int(received["step"].min()),
            "payments_received": int(len(received)),
            "distinct_senders": int(received["nameOrig"].nunique()),
            "total_received": round(float(received["amount"].sum()), 2),
            "cash_outs": int(len(cash_outs)),
            "total_cashed_out": round(float(cash_outs["amount"].sum()), 2),
        }

    def check_balance_pattern(self) -> dict:
        t = self.txn
        old, new, amount = float(t["oldbalanceOrg"]), float(t["newbalanceOrig"]), float(t["amount"])
        return {
            "transaction_id": t["txn_id"],
            "type": t["type"],
            "amount": amount,
            "sender_balance_before": old,
            "sender_balance_after": new,
            "share_of_balance_moved": round(amount / old, 3) if old > 0 else None,
            "empties_account": old > 0 and new <= 0.01,
            "sender_balance_adds_up": abs((old - amount) - new) < 1 or (old < amount and new == 0),
        }

    def check_velocity(self, customer_id: str) -> dict:
        step = int(self.txn["step"])
        sent = self.past[self.past["nameOrig"] == customer_id]
        same_hour = sent[sent["step"] == step]
        last_day = sent[(sent["step"] > step - 24) & (sent["step"] <= step)]
        hours_active = max(step - int(sent["step"].min()) + 1, 1) if not sent.empty else 1
        return {
            "customer_id": customer_id,
            "transactions_same_hour": int(len(same_hour)),
            "transactions_last_24h": int(len(last_day)),
            "amount_last_24h": round(float(last_day["amount"].sum()), 2),
            "normal_transactions_per_hour": round(len(sent) / hours_active, 3),
        }
