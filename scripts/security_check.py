"""Print the security control report (ISO/IEC 27001:2022 and CIS Controls v8 mapping).

Usage:  python scripts/security_check.py
Exits with status 1 if any control fails, so it can run in CI.
"""
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from detection.security_controls import FAIL, run_checks  # noqa: E402


def main() -> int:
    rows = run_checks()
    for r in rows:
        print(f"[{r['status']}] {r['control']} {r['title']}")
        print(f"       ISO/IEC 27001: {r['iso27001']}")
        print(f"       CIS v8:        {r['cis_v8']}")
        print(f"       Where:         {r['implemented_in']}")
        print(f"       {r['detail']}\n")
    failed = [r for r in rows if r["status"] == FAIL]
    print(f"{len(rows) - len(failed)}/{len(rows)} controls without failures.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
