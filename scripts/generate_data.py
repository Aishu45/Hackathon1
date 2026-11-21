"""Create data/sample_transactions.csv (synthetic, PaySim format) and data/test_cases.csv.

Usage:
    python scripts/generate_data.py                 # synthetic data
    python scripts/generate_data.py data/paysim.csv # real PaySim download instead
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd  # noqa: E402

from config.settings import DATA_DIR as DATA  # noqa: E402
from config.settings import TRANSACTIONS_CSV  # noqa: E402
from core.data import build_alerts, generate_synthetic, load_transactions  # noqa: E402


def main() -> None:
    DATA.mkdir(exist_ok=True)
    if len(sys.argv) > 1:
        df = load_transactions(sys.argv[1])
    else:
        raw = generate_synthetic()
        raw.to_csv(DATA / "raw.csv", index=False)
        df = load_transactions(DATA / "raw.csv")
        (DATA / "raw.csv").unlink()
    df.to_csv(TRANSACTIONS_CSV, index=False)

    alerts = build_alerts(df)
    fraud = alerts[alerts["isFraud"] == 1].sample(min(5, int(alerts["isFraud"].sum())), random_state=1)
    legit = alerts[alerts["isFraud"] == 0].sample(min(5, int((alerts["isFraud"] == 0).sum())), random_state=1)
    cases = pd.concat([fraud, legit]).sort_values("step")
    cases[["txn_id", "isFraud"]].to_csv(DATA / "test_cases.csv", index=False)

    print(f"{len(df):,} transactions, {len(alerts):,} alerts, "
          f"{alerts['isFraud'].mean():.0%} of alerts are fraud")
    print(f"Test cases: {len(fraud)} fraud + {len(legit)} false alarms -> data/test_cases.csv")


if __name__ == "__main__":
    main()
