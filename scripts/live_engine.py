"""Run the live engine on its own (the dashboard's Live monitor page can also start it).

Usage:
    python scripts/live_engine.py                 # 60x speed, PRISM on if a key is set
    python scripts/live_engine.py --speed 120 --auto-explain

Then open the dashboard's Live monitor page, or send commands from Python:
    from ato.live import send_command; send_command("live/live.db", "launch_attack", "ATO-09")
"""
import argparse
import os
import signal
import sys
import threading
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from ato.live import LiveEngine, sim_clock  # noqa: E402
from core import tracing  # noqa: E402

DB = ROOT / "live" / "live.db"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--speed", type=float, default=60.0, help="simulated minutes per real minute")
    p.add_argument("--auto-explain", action="store_true", help="Claude explains Critical alerts (billed)")
    p.add_argument("--seed", type=int, default=7)
    args = p.parse_args()
    DB.parent.mkdir(exist_ok=True)
    engine = LiveEngine(DB, seed=args.seed, speed=args.speed, auto_explain=args.auto_explain,
                        prism=bool(os.environ.get("PRISMTRACE_API_KEY")))
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    print(f"Live engine running at {args.speed:g}x from {sim_clock(engine.now)}; database {DB}. Ctrl+C to stop.")
    try:
        engine.run(stop)
    finally:
        tracing.close()


if __name__ == "__main__":
    main()
