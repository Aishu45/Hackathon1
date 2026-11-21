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
    return float(os.environ.get(name, default))


# Claude model for the fraud agent.
MODEL = os.environ.get("FRAUD_AGENT_MODEL", "claude-opus-5-5")
MAX_AGENT_TURNS = int(_num("MAX_AGENT_TURNS", 8))

# Alert rule: what gets flagged for investigation in the first place.
ALERT_AMOUNT = _num("ALERT_AMOUNT", 200_000)

# Risk agent: at or above this amount a human always decides.
HUMAN_REVIEW_AMOUNT = _num("HUMAN_REVIEW_AMOUNT", 1_000_000)

# Risk agent: an approval with a risk score at or above this is contradictory.
HIGH_RISK_SCORE = int(_num("HIGH_RISK_SCORE", 70))
