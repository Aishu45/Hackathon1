"""AML rule tests: each rule fires on its pattern and stays quiet on normal activity."""
import pandas as pd
import pytest

from agents import compliance_agent
from agents.risk_agent import REQUIRED_FOR_APPROVAL, apply_policy
from core.data import generate_synthetic, load_transactions
from detection import compliance_rules as rules

COLS = ["txn_id", "step", "type", "amount", "nameOrig", "oldbalanceOrg", "newbalanceOrig",
        "nameDest", "oldbalanceDest", "newbalanceDest"]


def frame(rows):
    return pd.DataFrame([dict(zip(COLS, r)) for r in rows])


def txn(step, kind, amount, orig, dest, bal=100_000.0, tid="TX"):
    return {"txn_id": tid, "step": step, "type": kind, "amount": amount, "nameOrig": orig,
            "oldbalanceOrg": bal, "newbalanceOrig": max(bal - amount, 0), "nameDest": dest,
            "oldbalanceDest": 0.0, "newbalanceDest": 0.0}


def test_sanctions_match_on_either_party():
    t = txn(5, "TRANSFER", 500, "C100001", "C777001")
    hit = rules.sanctions_screening(t, frame([]), {"C777001"})
    assert hit and hit.rule_id == "AML-01" and hit.severity == "high"
    assert rules.sanctions_screening(t, frame([]), {"C999999"}) is None


def test_structuring_needs_several_amounts_just_under_threshold():
    past = frame([("T1", 1, "TRANSFER", 9_500, "C100001", 1e5, 0, "C1", 0, 0),
                  ("T2", 4, "TRANSFER", 9_700, "C100001", 1e5, 0, "C2", 0, 0)])
    assert rules.structuring(txn(7, "TRANSFER", 9_800, "C100001", "C3"), past, set()).rule_id == "AML-02"
    # Same amounts spread over more than the window: no hit.
    old = past.assign(step=[1, 2])
    assert rules.structuring(txn(40, "TRANSFER", 9_800, "C100001", "C3"), old, set()) is None
    # Amounts well under the threshold are ordinary.
    small = past.assign(amount=[3_000, 4_000])
    assert rules.structuring(txn(7, "TRANSFER", 2_000, "C100001", "C3"), small, set()) is None


def test_rapid_pass_through_flags_mule_cash_out_only():
    inflow = frame([("T1", 3, "TRANSFER", 50_000, "C100009", 5e4, 0, "C900001", 0, 5e4)])
    mule = txn(3, "CASH_OUT", 50_000, "C900001", "M200001", bal=50_000)
    assert rules.rapid_pass_through(mule, inflow, set()).rule_id == "AML-03"
    # A saver moving a large, long-held balance after a small incoming payment.
    saver = txn(3, "TRANSFER", 400_000, "C900001", "C100010", bal=600_000)
    assert rules.rapid_pass_through(saver, inflow, set()) is None


def test_unusual_amount_needs_history():
    history = frame([(f"T{i}", i, "PAYMENT", 100, "C100001", 1e5, 1e5, "M1", 0, 0) for i in range(6)])
    big = txn(10, "TRANSFER", 5_000, "C100001", "C2")
    assert rules.unusual_amount(big, history, set()).severity == "medium"
    assert rules.unusual_amount(big, history.head(2), set()) is None


@pytest.fixture(scope="module")
def df(tmp_path_factory):
    path = tmp_path_factory.mktemp("d") / "raw.csv"
    generate_synthetic().to_csv(path, index=False)
    return load_transactions(path)


def test_screen_all_finds_planted_patterns_without_labels(df):
    hits = compliance_agent.screen_all(df, {"C900001", "C900004"})
    assert {"AML-01", "AML-02", "AML-03"} <= set(hits["rule_id"])
    labelled = hits.merge(df[["txn_id", "isFraud"]], on="txn_id")
    assert labelled[labelled["rule_id"] == "AML-03"]["isFraud"].mean() >= 0.8


def test_high_severity_hit_blocks_ai_approval():
    hit = rules.RuleHit("AML-02", "Possible structuring", "high", "3 transactions")
    approve = {"decision": "approve", "risk_score": 10}
    result = apply_policy(approve, 9_000, set(REQUIRED_FOR_APPROVAL), 0, [hit])
    assert result.decision == "escalate" and "AML-02" in result.overrides[0]
    medium = rules.RuleHit("AML-04", "Unusual", "medium", "x")
    assert apply_policy(approve, 9_000, set(REQUIRED_FOR_APPROVAL), 0, [medium]).decision == "approve"
