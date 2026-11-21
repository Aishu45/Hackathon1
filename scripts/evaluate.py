"""Run the agent on the test cases and score it against the answer key.

Usage:
    python scripts/evaluate.py            # all test cases
    python scripts/evaluate.py T0000385   # one case

Scoring: fraud is caught when the final decision is hold or escalate; a false
alarm is cleared when it is approved. Results go to results/latest.json.
Each case is one PRISM session, so you can open its trace in PRISM.
"""
import json
import sys
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from fraud_agent import tracing  # noqa: E402
from fraud_agent.agent import investigate  # noqa: E402
from fraud_agent.data import build_alerts  # noqa: E402


def main() -> None:
    df = pd.read_csv(ROOT / "data" / "transactions.csv")
    cases = pd.read_csv(ROOT / "data" / "test_cases.csv")
    if len(sys.argv) > 1:
        cases = cases[cases["txn_id"].isin(sys.argv[1:])]

    rows = []
    try:
        for txn_id, is_fraud in cases[["txn_id", "isFraud"]].itertuples(index=False):
            result = investigate(df, txn_id)
            caught = result["decision"] in ("hold", "escalate")
            correct = caught if is_fraud else result["decision"] == "approve"
            rows.append({**result, "is_fraud": int(is_fraud), "correct": correct})
            print(f"{txn_id}  truth={'FRAUD' if is_fraud else 'legit':5}  "
                  f"decision={result['decision']:8}  risk={result['risk_score']}  "
                  f"{'OK ' if correct else 'MISS'}  session={result['session_id']}")
            if result["error"]:
                print(f"    note: {result['error']}")
    finally:
        tracing.close()

    fraud = [r for r in rows if r["is_fraud"]]
    legit = [r for r in rows if not r["is_fraud"]]
    alerts = build_alerts(df)
    print()
    print(f"Fraud caught:        {sum(r['correct'] for r in fraud)}/{len(fraud)}")
    print(f"False alarms cleared: {sum(r['correct'] for r in legit)}/{len(legit)}")
    print(f"Baseline rule: flags all {len(alerts)} alerts for review, "
          f"{1 - alerts['isFraud'].mean():.0%} of them false alarms.")

    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    (out / "latest.json").write_text(json.dumps(rows, indent=2, default=str))


if __name__ == "__main__":
    main()
