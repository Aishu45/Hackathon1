"""PRISM tracing for the fraud agent, plus a local copy of every step.

Every investigation is one PRISM session (one trajectory):
  - each Claude call  -> PRISMtrace.trace_llm
  - each tool call, the safety-policy check and the final decision
                      -> steps in one PRISMtrace.submit_trajectory

Settings come from the environment (see .env.example):
  PRISMTRACE_API_KEY     secret, never commit it
  PRISMTRACE_PROJECT_ID  not secret
  PRISMTRACE_HOST        not secret

Without a key the agent still runs and writes traces only to traces.jsonl.

Account ids are pseudonymised (core/masking.py) in everything sent to PRISM;
the local traces.jsonl keeps the real ids for internal debugging.
"""
from __future__ import annotations

import contextlib
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Iterator

import prismtrace
from prismtrace import PRISMtrace

from core.masking import mask

AGENT_ID = "fraud-investigator"  # stable id: PRISM rules and alerts scope to it
AGENT_NAME = "Fraud Investigation Agent"
DEFAULT_PROJECT_ID = "b64c494f-f3b2-4168-a215-175ea7f69090"
DEFAULT_HOST = "https://api.prism.blockconvey.com"
LOCAL_LOG = Path(os.environ.get("TRACE_LOG", "traces.jsonl"))

_client: PRISMtrace | None = None
_warned = False


def get_client() -> PRISMtrace | None:
    """One shared PRISM client, created on first use. None when no key is set."""
    global _client, _warned
    if _client is not None:
        return _client
    api_key = os.environ.get("PRISMTRACE_API_KEY", "").strip()
    if not api_key:
        if not _warned:
            print("PRISM: PRISMTRACE_API_KEY is not set; writing traces to "
                  f"{LOCAL_LOG} only.", file=sys.stderr)
            _warned = True
        return None
    _client = PRISMtrace(
        api_key=api_key,
        host=os.environ.get("PRISMTRACE_HOST", DEFAULT_HOST),
        project_id=os.environ.get("PRISMTRACE_PROJECT_ID", DEFAULT_PROJECT_ID),
    )
    return _client


def close() -> None:
    """Flush pending sends. Call at shutdown in long-running processes."""
    if _client is not None:
        _client.close()


def _local(record: dict) -> None:
    try:
        with LOCAL_LOG.open("a") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except OSError as exc:  # tracing must never break an investigation
        print(f"Local trace write failed: {exc}", file=sys.stderr)


def _flatten(messages: list[dict]) -> list[dict]:
    """Turn SDK message content blocks into plain role/content strings."""
    flat = []
    for m in messages:
        content = m["content"]
        if not isinstance(content, str):
            parts = []
            for block in content:
                block = block.model_dump() if hasattr(block, "model_dump") else block
                kind = block.get("type")
                if kind == "text":
                    parts.append(block["text"])
                elif kind == "tool_use":
                    parts.append(f"[tool call] {block['name']}({json.dumps(block['input'])})")
                elif kind == "tool_result":
                    parts.append(f"[tool result] {block['content']}")
            content = "\n".join(parts)
        flat.append({"role": m["role"], "content": content})
    return flat


class Investigation:
    """Collects the steps of one investigation and sends them to PRISM."""

    def __init__(self, txn_id: str, agent_id: str = AGENT_ID, agent_name: str = AGENT_NAME,
                 prefix: str = "case"):
        self.txn_id = txn_id
        self.session_id = f"{prefix}-{txn_id}-{uuid.uuid4().hex[:8]}"
        self.steps: list[dict] = []
        self.model: str | None = None
        self.agent_id, self.agent_name = agent_id, agent_name

    def llm_call(self, model: str, system: str, messages: list[dict], response: Any,
                 latency_ms: int) -> None:
        self.model = model
        output = _flatten([{"role": "assistant", "content": response.content}])[0]["content"]
        usage = response.usage
        inputs = [{"role": "system", "content": system}] + _flatten(messages)
        client = get_client()
        if client:
            client.trace_llm(
                model=model, input_messages=mask(inputs), output=mask(output), latency_ms=latency_ms,
                token_count_input=usage.input_tokens, token_count_output=usage.output_tokens,
                agent_id=self.agent_id, agent_name=self.agent_name, session_id=self.session_id,
                metadata={"transaction_id": self.txn_id, "stop_reason": response.stop_reason},
            )
        self.steps.append({"step_type": "reasoning", "label": f"Claude turn {len(self.steps) + 1}",
                           "output_summary": output[:500], "duration_ms": latency_ms,
                           "token_count": usage.input_tokens + usage.output_tokens})
        _local({"session_id": self.session_id, "kind": "llm", "model": model,
                "stop_reason": response.stop_reason, "output": output, "latency_ms": latency_ms})

    def tool_call(self, name: str, args: dict, result: Any, duration_ms: int, ok: bool) -> None:
        step = {"step_type": "tool_call", "tool_name": name, "label": name,
                "input_summary": json.dumps(args)[:500],
                "output_summary": json.dumps(result, default=str)[:1000],
                "duration_ms": duration_ms, "status": "success" if ok else "error"}
        self.steps.append(step)
        _local({"session_id": self.session_id, "kind": "tool", **step})

    def note(self, label: str, summary: str) -> None:
        """A non-tool step, such as the safety policy check."""
        self.steps.append({"step_type": "reasoning", "label": label, "output_summary": summary[:1000]})
        _local({"session_id": self.session_id, "kind": "note", "label": label, "summary": summary})

    def finish(self, result: dict) -> None:
        summary = json.dumps({k: result[k] for k in ("decision", "risk_score", "reasons")})
        self.steps.append({"step_type": "final_answer", "label": f"Decision: {result['decision']}",
                           "output_summary": summary[:1000]})
        _local({"session_id": self.session_id, "kind": "final", **result})
        client = get_client()
        if client:
            client.submit_trajectory(
                mask(self.steps), agent_name=self.agent_name, agent_id=self.agent_id,
                conversation_id=self.session_id, request_id=self.txn_id, model=self.model,
                final_status="success" if not result.get("error") else "error",
            )
            client.end_session(self.session_id, reason="investigation complete",
                               agent_id=self.agent_id, agent_name=self.agent_name)


@contextlib.contextmanager
def investigation(txn_id: str, **kwargs) -> Iterator[Investigation]:
    inv = Investigation(txn_id, **kwargs)
    with prismtrace.session(inv.session_id):
        yield inv


def timer() -> float:
    return time.perf_counter()


def elapsed_ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)


STRATEGY_AGENT_ID = "strategy-model"
STRATEGY_AGENT_NAME = "Fraud Strategy Decision Model"


def log_strategy_run(scenario: str, inputs: dict, results: list, flags: list,
                     explanation: list[str]) -> str | None:
    """Send one strategy-model run to PRISM as a trajectory, so every input,
    calculation and the recommendation can be traced there. No model is called.
    Returns the session id, or None when no PRISM key is set."""
    session_id = f"strategy-{uuid.uuid4().hex[:8]}"
    steps = [{"step_type": "reasoning", "label": f"Input: {i.label}",
              "output_summary": f"{i.value} {i.unit} ({i.source}) {i.note}"[:1000]}
             for i in inputs.values()]
    for r in results:
        for s in r.steps:
            steps.append({"step_type": "reasoning", "label": f"{r.label.split(':')[0]}: {s.name}",
                          "input_summary": json.dumps(s.inputs)[:500],
                          "output_summary": f"{s.formula} = {s.value:,.2f} {s.unit}"})
    for f in flags:
        steps.append({"step_type": "reasoning", "label": f"Guardrail ({f.level})",
                      "output_summary": f.message[:1000]})
    steps.append({"step_type": "final_answer", "label": f"Recommendation: {scenario}",
                  "output_summary": " ".join(explanation)[:1000] or "Blocked by input errors."})
    _local({"session_id": session_id, "kind": "strategy", "scenario": scenario, "steps": steps})
    client = get_client()
    if not client:
        return None
    client.submit_trajectory(mask(steps), agent_name=STRATEGY_AGENT_NAME, agent_id=STRATEGY_AGENT_ID,
                             conversation_id=session_id, request_id=session_id, model="deterministic",
                             final_status="success" if explanation else "error")
    return session_id


ATO_AGENT_ID = "ato-test-runner"
ATO_AGENT_NAME = "Account Takeover Test Runner"


def log_ato_run(label: str, report, summary: dict) -> str | None:
    """Send one account-takeover test run to PRISM as a trajectory: one step per
    test case (outcome, scores, losses and evidence), then the summary.
    Returns the session id, or None when no PRISM key is set."""
    session_id = f"ato-run-{uuid.uuid4().hex[:8]}"
    steps = []
    for r in report.to_dict("records"):
        steps.append({
            "step_type": "tool_call", "tool_name": "run_test_case", "label": f"{r['id']} {r['title']}",
            "input_summary": f"MITRE {r['mitre']}; OWASP {r['owasp']}; ISO 27001 {r['iso27001']}; "
                             f"fix {'on' if r['fix_on'] else 'off'}"[:500],
            "output_summary": (f"{r['outcome']}; risk {r['inherent_score']} -> {r['residual_score']} "
                               f"({r['residual_criticality']}); annual loss {r['inherent_annual_loss']:,} -> "
                               f"{r['residual_annual_loss']:,}; evidence: {r['evidence']}")[:1000],
            "status": "error" if r["outcome"] == "missed" else "success",
        })
    steps.append({"step_type": "final_answer", "label": f"Run summary: {label}",
                  "output_summary": json.dumps(summary)[:1000]})
    _local({"session_id": session_id, "kind": "ato_run", "label": label, "summary": summary})
    client = get_client()
    if not client:
        return None
    client.submit_trajectory(mask(steps), agent_name=ATO_AGENT_NAME, agent_id=ATO_AGENT_ID,
                             conversation_id=session_id, request_id=session_id, model="rules+isolation-forest",
                             final_status="success" if summary["missed"] == 0 else "error")
    return session_id


LIVE_AGENT_ID = "ato-live-monitor"
LIVE_AGENT_NAME = "Account Takeover Live Monitor"


def log_live_alert(alert: dict, tc, evidence) -> str | None:
    """Send one live detection to PRISM: the evidence events, then the alert.
    Account ids are masked. Returns the session id, or None when no PRISM key is set."""
    session_id = f"live-{alert['rule']}-{uuid.uuid4().hex[:8]}"
    steps = [{"step_type": "tool_call", "tool_name": "event_stream", "label": f"Event: {e['event']}",
              "input_summary": f"{e.get('user_id')} {e.get('country') or ''} {e.get('asn') or ''} "
                               f"{e.get('device_id') or ''}"[:500],
              "output_summary": f"amount {e.get('amount')}, payee {e.get('payee_id')}, "
                                f"reason {e.get('reason')}"[:500]}
             for e in evidence.head(30).to_dict("records")]
    steps.append({"step_type": "final_answer", "label": f"Alert {alert['rule']} {tc.title}",
                  "output_summary": (f"{alert['message']}. Risk {tc.inherent_score} ({alert['criticality']}); "
                                     f"{'blocked by a fix' if alert['blocked'] else 'not blocked'}. MITRE {tc.mitre}; "
                                     f"OWASP {tc.owasp}; ISO 27001 {tc.iso27001}. Fix: {tc.fix}")[:1000]})
    _local({"session_id": session_id, "kind": "live_alert", "alert": alert["id"]})
    client = get_client()
    if not client:
        return None
    client.submit_trajectory(mask(steps), agent_name=LIVE_AGENT_NAME, agent_id=LIVE_AGENT_ID,
                             conversation_id=session_id, request_id=alert["id"], model="rules+isolation-forest",
                             final_status="success" if alert["blocked"] else "error", async_send=True)
    return session_id
