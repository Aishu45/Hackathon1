"""Live engine: streaming, commands, live detection, blocked attacks, log gaps."""
import json
import sqlite3

import pytest

from ato.live import LiveEngine, read_state, send_command


@pytest.fixture
def engine(tmp_path, monkeypatch):
    from core import tracing
    monkeypatch.setattr(tracing, "LOCAL_LOG", tmp_path / "traces.jsonl")
    monkeypatch.delenv("PRISMTRACE_API_KEY", raising=False)
    monkeypatch.setattr(tracing, "_client", None)
    return LiveEngine(tmp_path / "live.db", prism=False)


def rules(alerts):
    return {a["rule"] for a in alerts if a["rule"] != "ML"}


def test_history_streams_in_time_order_without_rule_alerts(engine):
    assert engine.seq > 1000
    engine.advance(120)
    df = engine.window_frame()
    assert df["t"].max() <= engine.now and df["seq"].is_monotonic_increasing
    assert rules(engine.detect_tick()) == set()


def test_launched_attack_is_detected_live_and_not_blocked(engine):
    engine.launch("ATO-06")
    engine.advance(30)
    alerts = engine.detect_tick()
    mfa = [a for a in alerts if a["rule"] == "ATO-06"]
    assert mfa and not mfa[0]["blocked"]


def test_same_attack_with_fix_is_detected_and_blocked(engine):
    engine.fixes = {"ATO-14"}
    engine.launch("ATO-14")
    engine.advance(30)
    drain = [a for a in engine.detect_tick() if a["rule"] == "ATO-14"]
    assert drain and drain[0]["blocked"]


def test_alerts_are_not_repeated(engine):
    engine.launch("ATO-17")
    engine.advance(10)
    first = rules(engine.detect_tick())
    engine.advance(10)
    assert "ATO-17" in first and "ATO-17" not in rules(engine.detect_tick())


def test_commands_from_the_dashboard(engine):
    send_command(engine.db_path, "set_fixes", json.dumps(["ATO-09"]))
    send_command(engine.db_path, "launch_attack", "ATO-09")
    send_command(engine.db_path, "fast_forward", "180")
    engine.process_commands()
    assert engine.fixes == {"ATO-09"}
    con = sqlite3.connect(engine.db_path)
    sim = [r for r in con.execute("SELECT rule, blocked FROM alerts").fetchall() if r[0] == "ATO-09"]
    assert sim and sim[0][1] == 1
    assert json.loads(read_state(engine.db_path)["fixes"]) == ["ATO-09"]


def test_log_tampering_leaves_a_gap_only_with_the_fix(engine):
    engine.launch("DR-01")
    engine.advance(240)
    assert "DR-01" not in rules(engine.detect_tick())
    engine.fixes = {"DR-01"}
    engine.launch("DR-01")
    engine.advance(240)  # the gap shows once later events arrive after the deleted ones
    assert "DR-01" in rules(engine.detect_tick())
