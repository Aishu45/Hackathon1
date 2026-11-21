"""Risk agent: the final, code-enforced decision after the fraud agent recommends.

The model only recommends. These rules can make a decision more cautious
(approve -> escalate) but never less cautious, so a confused or manipulated
model still cannot release a risky payment.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from config.settings import HIGH_RISK_SCORE, HUMAN_REVIEW_AMOUNT

# An approval needs at least this much evidence.
REQUIRED_FOR_APPROVAL = {"get_customer_history", "get_recipient_profile"}

VALID_DECISIONS = {"approve", "hold", "escalate"}


@dataclass
class PolicyResult:
    decision: str
    overrides: list[str] = field(default_factory=list)


def apply_policy(proposed: dict | None, amount: float, tools_called: set[str],
                 tool_errors: int) -> PolicyResult:
    """Return the final decision and the reasons for any override."""
    if not proposed or proposed.get("decision") not in VALID_DECISIONS:
        return PolicyResult("escalate", ["No valid decision from the agent; a human must review."])

    decision = proposed["decision"]
    overrides: list[str] = []

    if decision == "approve":
        missing = REQUIRED_FOR_APPROVAL - tools_called
        if missing:
            overrides.append(f"Approval without checking {', '.join(sorted(missing))}.")
        if tool_errors:
            overrides.append(f"{tool_errors} tool call(s) failed, so the evidence is incomplete.")
        if int(proposed.get("risk_score", 0)) >= HIGH_RISK_SCORE:
            overrides.append("Approval contradicts the agent's own high risk score.")

    if amount >= HUMAN_REVIEW_AMOUNT and decision != "escalate":
        overrides.append(f"Amount {amount:,.0f} is at or above the human-review limit "
                         f"of {HUMAN_REVIEW_AMOUNT:,.0f}.")

    return PolicyResult("escalate" if overrides else decision, overrides)
