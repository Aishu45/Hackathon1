"""Account-takeover test lab: catalogue, simulation, detection, ML and scoring."""
import pytest

from ato.catalog import CATALOG, criticality
from ato.runner import ALL_FIXES, run_tests
from ato.scoring import Assumptions, score


@pytest.fixture(scope="module")
def before():
    return run_tests(set())


@pytest.fixture(scope="module")
def after():
    return run_tests(ALL_FIXES)


def test_catalogue_is_complete_and_mapped():
    assert len(CATALOG) == 26 and len({tc.id for tc in CATALOG}) == 26
    for tc in CATALOG:
        assert tc.mitre and tc.owasp and tc.iso27001.startswith("A.") and tc.fix
        assert 1 <= tc.likelihood <= 5 and 1 <= tc.impact <= 5 and tc.loss_per_incident > 0
    assert sum(criticality(tc.inherent_score) == "Critical" for tc in CATALOG) == 6


def test_every_attack_succeeds_without_its_fix(before):
    assert before.report["attack_succeeded"].all()


def test_every_attack_is_blocked_with_its_fix(after):
    assert not after.report["attack_succeeded"].any()
    assert (after.report["outcome"] == "prevented").all()


def test_each_rule_catches_its_attack(before):
    caught = before.report.set_index("id")["detected_by_rule"]
    # Without sequence-numbered logs, deleted records leave no trace: DR-01's vulnerability.
    assert caught.drop("DR-01").all() and not caught["DR-01"]
    # ...but the ML model still flags the takeover session behind it.
    assert before.report.set_index("id").loc["DR-01", "detected_by_ml"]


def test_rules_raise_no_false_alarms_on_normal_activity(before, after):
    for run in (before, after):
        assert {k: v for k, v in run.false_positives.items() if k != "ML model"} == {}


def test_ml_flags_few_normal_sessions(before):
    normal = before.sessions[before.sessions["test_case"].isna()]
    assert normal["flagged"].mean() < 0.03


@pytest.mark.parametrize("seed", [1, 2])
def test_detection_holds_on_other_datasets(seed):
    run = run_tests(set(), seed=seed)
    assert {k: v for k, v in run.false_positives.items() if k != "ML model"} == {}
    assert run.report["detected_by_rule"].sum() == 25


def test_fixes_cut_risk_and_loss(before, after):
    assert before.summary["critical_before"] == 6 and after.summary["critical_after"] == 0
    assert after.summary["residual_annual_loss"] < before.summary["residual_annual_loss"] \
        < before.summary["inherent_annual_loss"]


def test_scoring_formulas_are_traceable():
    tc = CATALOG[0]  # ATO-01: likelihood 5, impact 4, loss 40,000
    ok = {t.id: True for t in CATALOG}
    missed = score(ok, {}, {}, set()).set_index("id").loc[tc.id]
    assert missed["outcome"] == "missed" and missed["residual_score"] == 20
    assert missed["residual_annual_loss"] == 24 * 40_000
    detected = score(ok, {tc.id: ["x"]}, {}, set()).set_index("id").loc[tc.id]
    assert detected["residual_score"] == 5 * 2 and detected["residual_annual_loss"] == 24 * 40_000 * 0.3
    prevented = score({**ok, tc.id: False}, {}, {}, {tc.id}).set_index("id").loc[tc.id]
    assert prevented["residual_score"] == 2 * 4 and prevented["residual_annual_loss"] == 2 * 40_000 * 0.05
    assert any("x impact" in line for line in prevented["trace"])


def test_losses_scale_with_customers():
    ok = {t.id: True for t in CATALOG}
    small = score(ok, {}, {}, set(), Assumptions(customers=50_000))["inherent_annual_loss"].sum()
    big = score(ok, {}, {}, set(), Assumptions(customers=100_000))["inherent_annual_loss"].sum()
    assert big == pytest.approx(2 * small, rel=0.01)
