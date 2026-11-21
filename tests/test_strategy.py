"""Tests for the strategy decision model (Track 2)."""
import math

import pandas as pd
import pytest

from core.data import generate_synthetic, load_transactions
from planning import strategy_model as sm


@pytest.fixture(scope="module")
def df(tmp_path_factory):
    path = tmp_path_factory.mktemp("d") / "raw.csv"
    generate_synthetic().to_csv(path, index=False)
    return load_transactions(path)


def test_every_input_states_its_source_and_type(df):
    out = sm.build(df, evaluation=[])
    for inp in out["inputs"].values():
        assert inp.source in ("measured", "assumption") and inp.kind in ("financial", "non-financial")
    kinds = {i.kind for i in out["inputs"].values()}
    assert kinds == {"financial", "non-financial"}


def test_calculations_are_traceable_and_add_up(df):
    out = sm.build(df, evaluation=[])
    for r in out["results"]:
        total = r.value("staff_cost") + r.value("fraud_losses") + r.value("lost_customer_cost") + r.value("ai_cost")
        assert r.value("total_cost") == pytest.approx(total)
        assert r.value("fraud_alerts") + r.value("genuine_alerts") == pytest.approx(r.value("alerts"))
        assert all(s.formula and s.inputs for s in r.steps)


def test_manual_reviews_everything_and_ai_costs_only_in_ai_strategy(df):
    results = {r.strategy: r for r in sm.build(df, evaluation=[])["results"]}
    assert results["manual"].value("analyst_reviews") == pytest.approx(results["manual"].value("alerts"))
    assert results["manual"].value("ai_cost") == 0 and results["threshold"].value("ai_cost") == 0
    assert results["ai_assisted"].value("ai_cost") > 0


def test_ai_rates_come_from_the_evaluation_when_available(df):
    evaluation = [{"is_fraud": 1, "decision": "hold"}, {"is_fraud": 1, "decision": "approve"},
                  {"is_fraud": 0, "decision": "approve"}, {"is_fraud": 0, "decision": "escalate"}]
    inputs = sm.build(df, evaluation=evaluation)["inputs"]
    assert inputs["ai_fraud_flagged"].value == 0.5 and inputs["ai_fraud_flagged"].source == "measured"
    assert inputs["ai_genuine_cleared"].value == 0.5
    assert sm.build(df, evaluation=[])["inputs"]["ai_fraud_flagged"].source == "assumption"


def test_overrides_change_the_answer_and_are_labelled(df):
    out = sm.build(df, {"fraud_share": 0.05}, evaluation=[])
    assert out["inputs"]["fraud_share"].value == 0.05
    assert out["inputs"]["fraud_share"].source == "assumption"


@pytest.mark.parametrize("bad, message", [
    ({"churn_after_hold": 1.5}, "between 0% and 100%"),
    ({"analyst_cost_per_hour": -1}, "cannot be negative"),
    ({"analyst_hours_per_month": 0}, "cannot be zero"),
    ({"avg_fraud_loss": None}, "Missing input"),
])
def test_guardrails_block_bad_inputs(df, bad, message):
    out = sm.build(df, bad, evaluation=[])
    errors = [f.message for f in out["flags"] if f.level == "error"]
    assert any(message in e for e in errors) and out["explanation"] == []


def test_guardrails_flag_capacity_and_limitations(df):
    out = sm.build(df, {"current_analysts": 1}, evaluation=[])
    levels = [f.level for f in out["flags"]]
    assert "warning" in levels and "limitation" in levels
    assert any("backlog" in f.message for f in out["flags"])


def test_scenarios_compare_and_the_winner_can_change(df):
    scenarios = {
        "a": {"name": "Perfect scores", "overrides": {"fraud_share": 0.05}},
        "b": {"name": "Imperfect scores", "overrides": {"fraud_share": 0.05, "threshold_fraud_reviewed": 0.85,
                                                        "threshold_genuine_reviewed": 0.30}},
    }
    table = sm.compare_scenarios(df, scenarios, evaluation=[])
    winners = table[table["best"]].set_index("scenario")["strategy"]
    assert len(winners) == 2 and winners["Perfect scores"] != winners["Imperfect scores"]


def test_explanation_names_the_winner_and_its_sensitivity(df):
    out = sm.build(df, {"fraud_share": 0.05}, evaluation=[])
    winner = sm.best(out["results"]).label.split(":")[0]
    assert out["explanation"][0].startswith(winner)
    assert "±25%" in out["explanation"][-1] or "sensitive" in out["explanation"][-1]


def test_scenario_files_are_valid():
    scenarios = sm.load_scenarios()
    assert scenarios
    known = set(sm.default_inputs()) | {"fraud_share", "threshold_fraud_reviewed",
                                        "threshold_genuine_reviewed", "ai_fraud_flagged", "ai_genuine_cleared"}
    for sc in scenarios.values():
        assert sc["name"] and set(sc.get("overrides", {})) <= known


def test_no_crash_on_zero_volume(df):
    out = sm.build(df, {"monthly_transactions": 0}, evaluation=[])
    assert any(f.level == "error" for f in out["flags"])
    assert math.isnan(out["results"][0].value("catch_rate"))
