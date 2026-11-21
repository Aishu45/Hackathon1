"""Anomaly detection: an explainable 0-100 risk score that needs no model.

It is a second opinion, computed independently of Claude (Claude never sees
it), so the risk agent can catch cases where the two disagree. Each signal
adds or removes points and comes with a plain-language explanation.

Like the tools, it only looks at transactions before the one under review
and never at the fraud labels.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

import pandas as pd

from detection.compliance_rules import net_recent_inflow

# Points per signal. Positive = riskier. Tune with your mentor.
WEIGHTS = {
    "drains_account": 35,
    "money_just_arrived": 40,
    "new_recipient_for_sender": 15,
    "brand_new_recipient": 15,
    "recipient_collects_from_many": 20,
    "amount_far_above_normal": 15,
    "burst_of_activity": 5,
    "established_payee": -30,
}


@dataclass(frozen=True)
class Signal:
    name: str
    points: int
    explanation: str


@dataclass
class AnomalyResult:
    score: int
    signals: list[Signal]

    def to_dict(self) -> dict:
        return {"score": self.score, "signals": [asdict(s) for s in self.signals]}


def score_transaction(txn: dict, past: pd.DataFrame) -> AnomalyResult:
    signals: list[Signal] = []

    def add(name: str, explanation: str) -> None:
        signals.append(Signal(name, WEIGHTS[name], explanation))

    step = int(txn["step"])
    amount = float(txn["amount"])
    sender, recipient = txn["nameOrig"], txn["nameDest"]
    balance = float(txn["oldbalanceOrg"])
    sent = past[past["nameOrig"] == sender]
    received = past[past["nameDest"] == recipient]

    if balance > 0 and amount >= 0.95 * balance:
        add("drains_account", f"Moves {min(amount / balance, 9.99):.0%} of the sender's balance.")

    net_in = net_recent_inflow(past, sender, step, 24)
    if net_in > 0 and 0.8 * net_in <= amount <= 1.25 * net_in and net_in >= 0.5 * balance:
        add("money_just_arrived", f"Sender received {net_in:,.0f} (net) in the last 24h and is "
                                  "moving it straight on.")

    previous = int((sent["nameDest"] == recipient).sum())
    if previous >= 3:
        add("established_payee", f"Sender has paid this recipient {previous} times before.")
    elif previous == 0 and not recipient.startswith("M"):
        add("new_recipient_for_sender", "Sender has never paid this recipient before.")

    if received.empty:
        add("brand_new_recipient", "Recipient has never received money before.")
    else:
        recent = received[received["step"] > step - 24]
        age = step - int(received["step"].min())
        if recent["nameOrig"].nunique() >= 3 and age < 48 and not recipient.startswith("M"):
            add("recipient_collects_from_many",
                f"Recipient, first seen {age}h ago, got money from "
                f"{recent['nameOrig'].nunique()} senders in 24h.")

    if len(sent) >= 5:
        median = float(sent["amount"].median())
        if median > 0 and amount >= 10 * median:
            add("amount_far_above_normal", f"Amount is {amount / median:,.0f}x the sender's median.")

    if int((sent["step"] == step).sum()) >= 2:
        add("burst_of_activity", "Several transactions from the sender in the same hour.")

    score = max(0, min(100, sum(s.points for s in signals)))
    return AnomalyResult(score, signals)
