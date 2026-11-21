"""Run all 26 account-takeover test cases and report risk, criticality and business impact.

Usage:
    python scripts/run_ato_tests.py                    # before and after all fixes
    python scripts/run_ato_tests.py --fixes ATO-06,ATO-09,ATO-14
    python scripts/run_ato_tests.py --prism            # also log both runs to PRISM
    python scripts/run_ato_tests.py --explain ATO-09   # Claude explains one result (needs a model key)

Writes results/ato_report_before.csv and results/ato_report_after.csv.
"""
import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from ato.catalog import BY_ID  # noqa: E402
from ato.runner import ALL_FIXES, run_tests  # noqa: E402
from core import tracing  # noqa: E402

COLS = ["id", "title", "inherent_score", "inherent_criticality", "outcome", "residual_score",
        "residual_criticality", "inherent_annual_loss", "residual_annual_loss"]


def show(label: str, result) -> None:
    s = result.summary
    print(f"\n=== {label} ===")
    print(result.report[COLS].to_string(index=False))
    print(f"Prevented {s['prevented']}, detected {s['detected']}, missed {s['missed']} of {s['tests']}. "
          f"Critical risks {s['critical_before']} -> {s['critical_after']}. "
          f"Annual exposure {s['inherent_annual_loss']:,} -> {s['residual_annual_loss']:,}.")
    print(f"False positives on normal activity: {result.false_positives}")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--fixes", default="all", help="'all', 'none' or comma-separated test-case ids")
    p.add_argument("--prism", action="store_true")
    p.add_argument("--explain", default="")
    p.add_argument("--seed", type=int, default=7)
    args = p.parse_args()
    fixes = ALL_FIXES if args.fixes == "all" else set() if args.fixes == "none" else {
        f.strip() for f in args.fixes.split(",") if f.strip()}
    unknown = fixes - set(BY_ID)
    if unknown:
        sys.exit(f"Unknown test case ids: {sorted(unknown)}")

    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    try:
        before = run_tests(set(), seed=args.seed)
        show("Before fixes (detection only)", before)
        before.report.drop(columns=["trace"]).to_csv(out / "ato_report_before.csv", index=False)
        after = run_tests(fixes, seed=args.seed)
        show(f"After fixes ({len(fixes)} switched on)", after)
        after.report.drop(columns=["trace"]).to_csv(out / "ato_report_after.csv", index=False)

        if args.prism:
            for label, r in (("before fixes", before), (f"after {len(fixes)} fixes", after)):
                sid = tracing.log_ato_run(label, r.report, r.summary)
                print(f"PRISM session ({label}): {sid or 'not sent (no PRISM key)'}")
        if args.explain:
            from ato.explain import explain
            row = before.report.set_index("id").loc[args.explain].to_dict() | {"id": args.explain}
            events = before.events[before.events["test_case"] == args.explain]
            print(f"\n=== AI explanation: {args.explain} ===\n{explain(row, events)}")
    finally:
        tracing.close()


if __name__ == "__main__":
    main()
