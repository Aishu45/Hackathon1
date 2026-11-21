"""Print the strategy decision model for every scenario in config/scenarios/.

Usage:
    python scripts/strategy_report.py            # all scenarios
    python scripts/strategy_report.py --prism    # also log each run to PRISM
"""
import sys
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from config.settings import TRANSACTIONS_CSV  # noqa: E402
from core import tracing  # noqa: E402
from planning.strategy_model import best, build, load_scenarios  # noqa: E402


def main() -> None:
    df = pd.read_csv(TRANSACTIONS_CSV)
    try:
        for key, sc in load_scenarios().items():
            out = build(df, sc.get("overrides"))
            print(f"\n=== {sc['name']} ===\n{sc.get('description', '')}")
            for r in out["results"]:
                mark = " <- best" if out["explanation"] and r is best(out["results"]) else ""
                print(f"  {r.label.split(':')[0]:12} total {r.value('total_cost'):>12,.0f}   "
                      f"analysts {r.value('analysts_needed'):>3.0f}   "
                      f"fraud caught {r.value('catch_rate'):>4.0%}{mark}")
            for line in out["explanation"]:
                print(f"  - {line}")
            for f in out["flags"]:
                print(f"  [{f.level}] {f.message}")
            if "--prism" in sys.argv:
                sid = tracing.log_strategy_run(sc["name"], out["inputs"], out["results"],
                                               out["flags"], out["explanation"])
                print(f"  PRISM session: {sid or 'not sent (no PRISM key)'}")
    finally:
        tracing.close()


if __name__ == "__main__":
    main()
