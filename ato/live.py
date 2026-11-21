"""Live engine: streams customer activity in real time, runs attacks on demand,
and detects them as they happen.

    engine = LiveEngine("live.db")
    engine.run(stop_event)          # or call step() / detect_tick() yourself

The clock runs faster than real time (default 60x: one real second is one
simulated minute) so attacks that take hours play out in minutes; long ones
(e.g. warming up a payee over 3 days) can be fast-forwarded.

Everything is shared through a small SQLite database, so the dashboard (or any
other process) can read the live stream and send commands:

    events    the activity stream, with sequence numbers
    alerts    detections, with criticality, blocked or not, PRISM session, AI explanation
    commands  launch an attack, set fixes, fast-forward, explain an alert
    state     clock, fixes, heartbeat
"""
from __future__ import annotations

import heapq
import json
import sqlite3
import threading
import time
from itertools import count
from pathlib import Path

import pandas as pd

from ato.catalog import BY_ID
from ato.detection import detect
from ato.ml import score_sessions
from ato.scoring import score
from ato.world import ATTACKS, COLUMNS, DAY, NO_VICTIM_ARG, World

BLOCKED_EVENTS = {"payment_held", "payment_rejected", "stepup_fail", "session_rejected", "otp_lock",
                  "mfa_denied", "api_denied", "agent_refused", "text_flagged", "alert_suppressed"}

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS events ({", ".join(f'"{c}"' for c in COLUMNS)});
CREATE INDEX IF NOT EXISTS events_t ON events(t);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY, created REAL, sim_t REAL, rule TEXT, title TEXT, message TEXT,
    score INTEGER, criticality TEXT, blocked INTEGER, ml INTEGER, evidence TEXT,
    prism_session TEXT, explanation TEXT);
CREATE TABLE IF NOT EXISTS commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT, created REAL, kind TEXT, arg TEXT, done INTEGER DEFAULT 0,
    result TEXT);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    con = sqlite3.connect(str(path), timeout=10, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(SCHEMA)
    return con


def send_command(path: str | Path, kind: str, arg: str = "") -> None:
    """Used by the dashboard: launch_attack <id>, set_fixes <json list>, fast_forward <minutes>,
    explain <alert id>, set_auto_explain <0|1>."""
    con = connect(path)
    con.execute("INSERT INTO commands (created, kind, arg) VALUES (?, ?, ?)", (time.time(), kind, arg))
    con.commit()
    con.close()


def read_state(path: str | Path) -> dict:
    con = connect(path)
    rows = dict(con.execute("SELECT key, value FROM state").fetchall())
    con.close()
    return rows


def sim_clock(t: float) -> str:
    day, minute = divmod(int(t), DAY)
    return f"Day {day + 1} {minute // 60:02d}:{minute % 60:02d}"


class LiveEngine:
    def __init__(self, db_path: str | Path, seed: int = 7, n_users: int = 300, speed: float = 60.0,
                 warmup_days: int = 2, window_days: float = 4, prism: bool = True,
                 auto_explain: bool = False, reset: bool = True):
        self.db_path = str(db_path)
        if reset:
            for suffix in ("", "-wal", "-shm"):
                Path(self.db_path + suffix).unlink(missing_ok=True)
        self.con = connect(self.db_path)
        self.w = World(seed=seed, n_users=n_users, days=0)
        self.registry = self.w.registry()
        self.known_users = set(self.w.users)
        self.speed, self.window = speed, window_days * DAY
        self.prism, self.auto_explain = prism, auto_explain
        self.fixes: set[str] = set()
        self.used: set[str] = set()
        self.heap: list = []
        self._tie = count()
        self._taken = 0  # events of self.w already moved into the heap
        self.seq = 0
        self.scheduled_day = -1
        self.now = warmup_days * DAY  # history before "now" gives detectors a baseline
        self.alert_ids: set[str] = set()
        self._schedule_until(self.now)
        self.release()
        self._save_state()

    # ------------------------------------------------------------ the stream
    def _schedule_until(self, t: float) -> None:
        while self.scheduled_day <= int(t // DAY):
            self.scheduled_day += 1
            self.w.generate_day(self.scheduled_day)

    def release(self) -> int:
        """Write every event whose time has come to the database."""
        for row in self.w.events[self._taken:]:
            heapq.heappush(self.heap, (row["t"], next(self._tie), row))
        self._taken = len(self.w.events)
        out = []
        while self.heap and self.heap[0][0] <= self.now:
            _, _, row = heapq.heappop(self.heap)
            if row.get("reason") == "__deleted__":  # attacker deleted it before it was numbered
                continue
            self.seq += 1
            if row.get("reason") == "__gap__":  # deleted after numbering: leaves a gap
                continue
            out.append({**row, "seq": self.seq})
        if out:
            pd.DataFrame(out, columns=COLUMNS).to_sql("events", self.con, if_exists="append", index=False)
        return len(out)

    def advance(self, minutes: float) -> int:
        self.now += minutes
        self._schedule_until(self.now + DAY)
        return self.release()

    def launch(self, tc: str) -> None:
        attack = ATTACKS[tc]
        t = self.now + 0.5
        if tc in NO_VICTIM_ARG:
            attack(self.w, t, tc in self.fixes)
        else:
            attack(self.w, t, tc in self.fixes, self.used)

    # --------------------------------------------------------------- commands
    def process_commands(self) -> None:
        rows = self.con.execute("SELECT id, kind, arg FROM commands WHERE done = 0 ORDER BY id").fetchall()
        for cid, kind, arg in rows:
            result = "ok"
            try:
                if kind == "launch_attack" and arg in ATTACKS:
                    self.launch(arg)
                    result = f"{arg} launched at {sim_clock(self.now)}"
                elif kind == "set_fixes":
                    self.fixes = set(json.loads(arg)) & set(ATTACKS)
                elif kind == "fast_forward":
                    self.advance(float(arg))
                    self.detect_tick()
                elif kind == "explain":
                    self.explain(arg)
                elif kind == "set_auto_explain":
                    self.auto_explain = arg == "1"
                else:
                    result = f"unknown command {kind}"
            except Exception as exc:  # keep the stream alive whatever happens
                result = f"error: {exc.__class__.__name__}: {exc}"
            self.con.execute("UPDATE commands SET done = 1, result = ? WHERE id = ?", (result, cid))
        self.con.commit()
        if rows:
            self._save_state()

    # -------------------------------------------------------------- detection
    def window_frame(self) -> pd.DataFrame:
        return pd.read_sql("SELECT * FROM events WHERE t >= ? ORDER BY seq", self.con,
                           params=(self.now - self.window,))

    def detect_tick(self) -> list[dict]:
        df = self.window_frame()
        if df.empty:
            return []
        df["success"] = df["success"].astype(bool)
        new: list[dict] = []
        hits = detect(df, self.known_users, self.registry)
        sessions = score_sessions(df, self.registry, contamination=0.005) if df["session_id"].nunique() > 50 else None
        flagged = set(sessions.index[sessions["flagged"]]) if sessions is not None else set()
        for h in hits:
            ev = df.loc[h.rows]
            key = f"{h.rule}:{int(ev['seq'].min())}"
            if key in self.alert_ids:
                continue
            sids = set(ev["session_id"].dropna())
            related = df[df["session_id"].isin(sids)] if sids else ev
            blocked = bool(related["event"].isin(BLOCKED_EVENTS).any() or ev["event"].isin(BLOCKED_EVENTS).any())
            tc = BY_ID[h.rule]
            new.append({"id": key, "rule": h.rule, "title": tc.title, "message": h.message,
                        "score": tc.inherent_score, "criticality": _crit(tc.inherent_score),
                        "blocked": blocked, "ml": bool(sids & flagged), "sim_t": float(ev["t"].max()),
                        "evidence": json.dumps([int(s) for s in ev["seq"]][:200])})
        if sessions is not None:
            for sid in flagged:
                key = f"ML:{sid}"
                if key in self.alert_ids or any(sid in a["message"] for a in new):
                    continue
                ev = df[df["session_id"] == sid]
                new.append({"id": key, "rule": "ML", "title": "Unusual session (machine-learning model)",
                            "message": f"{sid} ({ev['user_id'].iloc[0]}): anomaly score "
                                       f"{sessions.loc[sid, 'anomaly_score']:.2f}",
                            "score": 6, "criticality": "Medium",
                            "blocked": bool(ev["event"].isin(BLOCKED_EVENTS).any()), "ml": True,
                            "sim_t": float(ev["t"].max()), "evidence": json.dumps([int(s) for s in ev["seq"]])})
        for a in new:
            self.alert_ids.add(a["id"])
            a["prism_session"] = self._log_to_prism(a, df) if a["rule"] != "ML" else None
            self.con.execute(
                "INSERT OR IGNORE INTO alerts (id, created, sim_t, rule, title, message, score, criticality,"
                " blocked, ml, evidence, prism_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (a["id"], time.time(), a["sim_t"], a["rule"], a["title"], a["message"], a["score"],
                 a["criticality"], int(a["blocked"]), int(a["ml"]), a["evidence"], a["prism_session"]))
        self.con.commit()
        if self.auto_explain:
            for a in new:
                if a["criticality"] == "Critical" and a["rule"] != "ML":
                    self.explain(a["id"])
        return new

    def _log_to_prism(self, alert: dict, df: pd.DataFrame) -> str | None:
        if not self.prism:
            return None
        from core import tracing
        ev = df[df["seq"].isin(json.loads(alert["evidence"]))]
        try:
            return tracing.log_live_alert(alert, BY_ID[alert["rule"]], ev)
        except Exception:  # tracing must never stop the stream
            return None

    def explain(self, alert_id: str) -> str:
        from ato.explain import explain
        row = self.con.execute("SELECT rule, blocked, ml, message, evidence FROM alerts WHERE id = ?",
                               (alert_id,)).fetchone()
        if not row or row[0] == "ML":
            return ""
        rule, blocked, ml, message, evidence = row
        succeeded = {tid: True for tid in ATTACKS} | {rule: not blocked}
        report = score(succeeded, {rule: [message]}, {rule: 1.0} if ml else {}, self.fixes)
        facts = report.set_index("id").loc[rule].to_dict() | {"id": rule}
        ev = pd.read_sql(f"SELECT * FROM events WHERE seq IN ({','.join('?' * len(json.loads(evidence)))})",
                         self.con, params=json.loads(evidence))
        try:
            text = explain(facts, ev)
        except Exception as exc:
            text = f"AI explanation unavailable ({exc.__class__.__name__}). Set NICRRON_API_KEY or ANTHROPIC_API_KEY."
        self.con.execute("UPDATE alerts SET explanation = ? WHERE id = ?", (text, alert_id))
        self.con.commit()
        return text

    # -------------------------------------------------------------- main loop
    def _save_state(self) -> None:
        state = {"now": self.now, "clock": sim_clock(self.now), "fixes": json.dumps(sorted(self.fixes)),
                 "speed": self.speed, "heartbeat": time.time(), "auto_explain": int(self.auto_explain)}
        self.con.executemany("INSERT OR REPLACE INTO state (key, value) VALUES (?, ?)",
                             [(k, str(v)) for k, v in state.items()])
        self.con.commit()

    def run(self, stop: threading.Event, tick: float = 0.5, detect_every: float = 3.0) -> None:
        last, last_detect = time.monotonic(), 0.0
        while not stop.is_set():
            now = time.monotonic()
            self.advance(self.speed * (now - last) / 60)
            last = now
            self.process_commands()
            if now - last_detect >= detect_every:
                self.detect_tick()
                last_detect = now
            self._save_state()
            stop.wait(tick)


def _crit(score: int) -> str:
    from ato.catalog import criticality
    return criticality(score)
