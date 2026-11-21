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

    def __init__(self, txn_id: str):
        self.txn_id = txn_id
        self.session_id = f"case-{txn_id}-{uuid.uuid4().hex[:8]}"
        self.steps: list[dict] = []
        self.model: str | None = None

    def llm_call(self, model: str, system: str, messages: list[dict], response: Any,
                 latency_ms: int) -> None:
        self.model = model
        output = _flatten([{"role": "assistant", "content": response.content}])[0]["content"]
        usage = response.usage
        inputs = [{"role": "system", "content": system}] + _flatten(messages)
        client = get_client()
        if client:
            client.trace_llm(
                model=model, input_messages=inputs, output=output, latency_ms=latency_ms,
                token_count_input=usage.input_tokens, token_count_output=usage.output_tokens,
                agent_id=AGENT_ID, agent_name=AGENT_NAME, session_id=self.session_id,
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
                self.steps, agent_name=AGENT_NAME, agent_id=AGENT_ID,
                conversation_id=self.session_id, request_id=self.txn_id, model=self.model,
                final_status="success" if not result.get("error") else "error",
            )
            client.end_session(self.session_id, reason="investigation complete",
                               agent_id=AGENT_ID, agent_name=AGENT_NAME)


@contextlib.contextmanager
def investigation(txn_id: str) -> Iterator[Investigation]:
    inv = Investigation(txn_id)
    with prismtrace.session(inv.session_id):
        yield inv


def timer() -> float:
    return time.perf_counter()


def elapsed_ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)
