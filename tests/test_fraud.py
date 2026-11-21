"""Offline tests for the fraud agent: data, tools, risk policy, and the loop with a fake model."""
import json
from types import SimpleNamespace

import pytest

from agents import fraud_agent as agent
from agents.risk_agent import apply_policy
from config.settings import HUMAN_REVIEW_AMOUNT
from core import tracing
from core.data import build_alerts, generate_synthetic, load_transactions, split_answer_key
from core.tools import ToolBox


@pytest.fixture(scope="module")
def df(tmp_path_factory):
    path = tmp_path_factory.mktemp("d") / "raw.csv"
    generate_synthetic().to_csv(path, index=False)
    return load_transactions(path)


@pytest.fixture(autouse=True)
def local_traces(tmp_path, monkeypatch):
    monkeypatch.setattr(tracing, "LOCAL_LOG", tmp_path / "traces.jsonl")
    monkeypatch.delenv("PRISMTRACE_API_KEY", raising=False)
    monkeypatch.setattr(tracing, "_client", None)


def test_alerts_mix_fraud_and_false_alarms(df):
    alerts = build_alerts(df)
    assert 0 < alerts["isFraud"].mean() < 1


def test_agent_never_sees_labels(df):
    visible, key = split_answer_key(df)
    assert "isFraud" not in visible.columns and "isFraud" in key.columns
    txn_id = build_alerts(df)["txn_id"].iloc[0]
    tb = ToolBox(df, txn_id)
    assert "isFraud" not in tb.txn and "isFraud" not in tb.past.columns


def test_tools_only_see_the_past(df):
    txn_id = build_alerts(df)["txn_id"].iloc[-1]
    tb = ToolBox(df, txn_id)
    assert len(tb.past) == df.index[df["txn_id"] == txn_id][0]
    assert txn_id not in set(tb.past["txn_id"])


def test_fraud_goes_to_fresh_account_false_alarm_to_known_one(df):
    alerts = build_alerts(df)
    fraud = alerts[(alerts["isFraud"] == 1) & (alerts["type"] == "TRANSFER")].iloc[0]
    legit = alerts[alerts["isFraud"] == 0].iloc[-1]
    f = ToolBox(df, fraud.txn_id).get_customer_history(fraud.nameOrig, fraud.nameDest)
    l_ = ToolBox(df, legit.txn_id).get_customer_history(legit.nameOrig, legit.nameDest)
    assert f.get("previous_payments_to_this_recipient", 0) == 0
    assert l_["previous_payments_to_this_recipient"] >= 2


def test_policy_blocks_unsupported_approval():
    r = apply_policy({"decision": "approve", "risk_score": 10}, 1_000, {"check_velocity"}, 0)
    assert r.decision == "escalate" and r.overrides


def test_policy_blocks_approval_with_high_risk_or_tool_errors():
    tools = {"get_customer_history", "get_recipient_profile"}
    assert apply_policy({"decision": "approve", "risk_score": 85}, 1_000, tools, 0).decision == "escalate"
    assert apply_policy({"decision": "approve", "risk_score": 5}, 1_000, tools, 1).decision == "escalate"
    assert apply_policy({"decision": "approve", "risk_score": 5}, 1_000, tools, 0).decision == "approve"


def test_policy_escalates_large_amounts_and_missing_decisions():
    assert apply_policy({"decision": "hold", "risk_score": 90}, HUMAN_REVIEW_AMOUNT, set(), 0).decision == "escalate"
    assert apply_policy(None, 10, set(), 0).decision == "escalate"
    assert apply_policy({"decision": "release"}, 10, set(), 0).decision == "escalate"


class FakeClient:
    """Stands in for anthropic.Anthropic: calls two tools, then decides."""

    def __init__(self, decision):
        self.turn = 0
        self.decision = decision
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.turn += 1
        user = kwargs["messages"][0]["content"]
        sender = user.split("sender: ")[1].split("\n")[0]
        recipient = user.split("recipient: ")[1].strip()
        usage = SimpleNamespace(input_tokens=10, output_tokens=5)
        if self.turn == 1:
            content = [
                SimpleNamespace(type="tool_use", id="t1", name="get_customer_history",
                                input={"customer_id": sender, "recipient_id": recipient},
                                model_dump=lambda: {"type": "tool_use", "name": "get_customer_history", "input": {}}),
                SimpleNamespace(type="tool_use", id="t2", name="get_recipient_profile",
                                input={"recipient_id": recipient},
                                model_dump=lambda: {"type": "tool_use", "name": "get_recipient_profile", "input": {}}),
            ]
        else:
            decision = {"decision": self.decision, "risk_score": 20, "reasons": ["known recipient"],
                        "case_note": "Regular payee."}
            content = [SimpleNamespace(type="tool_use", id="t3", name="submit_decision", input=decision,
                                       model_dump=lambda: {"type": "tool_use", "name": "submit_decision", "input": {}})]
        return SimpleNamespace(content=content, stop_reason="tool_use", usage=usage, model="fake-model")


def test_agent_loop_records_evidence_and_decision(df):
    txn_id = build_alerts(df)["txn_id"].iloc[0]
    result = agent.investigate(df, txn_id, client=FakeClient("approve"))
    assert [e["tool"] for e in result["evidence"]] == ["get_customer_history", "get_recipient_profile"]
    assert result["agent_decision"] == "approve"
    assert result["decision"] in ("approve", "escalate")
    lines = tracing.LOCAL_LOG.read_text().strip().splitlines()
    kinds = [json.loads(line)["kind"] for line in lines]
    assert kinds == ["llm", "tool", "tool", "llm", "note", "final"]
