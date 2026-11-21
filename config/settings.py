"""All tunable thresholds in one place. Ask your finance mentor for real values.

Each can be overridden with an environment variable of the same name.
"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
TRANSACTIONS_CSV = DATA_DIR / "sample_transactions.csv"
TEST_CASES_CSV = DATA_DIR / "test_cases.csv"


def _num(name: str, default: float) -> float:
    value = os.environ.get(name, "").strip()  # a blank line in .env means "use the default"
    return float(value) if value else float(default)


# Claude model for the fraud agent.
MODEL = os.environ.get("FRAUD_AGENT_MODEL", "").strip() or "claude-opus-5-5"
MAX_AGENT_TURNS = int(_num("MAX_AGENT_TURNS", 8))

# Alert rule: what gets flagged for investigation in the first place.
ALERT_AMOUNT = _num("ALERT_AMOUNT", 200_000)

# Risk agent: at or above this amount a human always decides.
HUMAN_REVIEW_AMOUNT = _num("HUMAN_REVIEW_AMOUNT", 1_000_000)

# Risk agent: an approval with a risk score at or above this is contradictory.
HIGH_RISK_SCORE = int(_num("HIGH_RISK_SCORE", 70))

# Risk agent: if Claude approves but the model-free anomaly score is at or
# above this, the two disagree and a human decides.
ANOMALY_ESCALATE_SCORE = int(_num("ANOMALY_ESCALATE_SCORE", 40))

# --- AML compliance rules (detection/compliance_rules.py) ---
WATCHLIST_CSV = DATA_DIR / "watchlist.csv"  # synthetic sanctions list
REPORTING_THRESHOLD = _num("REPORTING_THRESHOLD", 10_000)  # amount that triggers a report
STRUCTURING_BAND = _num("STRUCTURING_BAND", 0.9)  # "just under" = 90-100% of the threshold
STRUCTURING_MIN_COUNT = int(_num("STRUCTURING_MIN_COUNT", 3))
STRUCTURING_WINDOW_HOURS = int(_num("STRUCTURING_WINDOW_HOURS", 24))
PASS_THROUGH_SHARE = _num("PASS_THROUGH_SHARE", 0.8)  # outflow within 80%-125% of recent inflow
PASS_THROUGH_WINDOW_HOURS = int(_num("PASS_THROUGH_WINDOW_HOURS", 24))
PASS_THROUGH_MIN_AMOUNT = _num("PASS_THROUGH_MIN_AMOUNT", 10_000)
PASS_THROUGH_BALANCE_SHARE = _num("PASS_THROUGH_BALANCE_SHARE", 0.5)  # recent inflow is most of the balance
UNUSUAL_AMOUNT_MULTIPLE = _num("UNUSUAL_AMOUNT_MULTIPLE", 20)  # x the customer's median
UNUSUAL_AMOUNT_MIN_HISTORY = int(_num("UNUSUAL_AMOUNT_MIN_HISTORY", 5))

# --- Security controls (detection/security_controls.py) ---
# Replace account ids with stable pseudonyms in everything sent to PRISM.
MASK_IDENTIFIERS = os.environ.get("MASK_IDENTIFIERS", "true").lower() != "false"
MASK_SALT = os.environ.get("MASK_SALT", "").strip() or "change-me-in-production"
# Stop an investigation that makes more tool calls than this.
MAX_TOOL_CALLS = int(_num("MAX_TOOL_CALLS", 12))
AUDIT_LOG = Path(os.environ.get("AUDIT_LOG", ROOT / "audit_log.jsonl"))
