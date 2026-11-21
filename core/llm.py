"""Model access: Claude directly (Anthropic SDK) or through the Nicrron gateway.

The agent loop in agents/fraud_agent.py speaks the Anthropic Messages format.
For Nicrron, which only offers an OpenAI-style /chat/completions endpoint,
this module translates each request and response, so the agent code is the
same for both providers.

Choose with LLM_PROVIDER in .env: "anthropic", "nicrron", or "auto" (default:
Nicrron when NICRRON_API_KEY is set and ANTHROPIC_API_KEY is not).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

import httpx

from config import settings


@dataclass
class Block:
    """A content block with the same attributes as the Anthropic SDK's blocks."""
    type: str
    text: str | None = None
    id: str | None = None
    name: str | None = None
    input: dict = field(default_factory=dict)

    def model_dump(self) -> dict:
        if self.type == "text":
            return {"type": "text", "text": self.text}
        return {"type": "tool_use", "id": self.id, "name": self.name, "input": self.input}


@dataclass
class Usage:
    input_tokens: int
    output_tokens: int


@dataclass
class Response:
    content: list[Block]
    stop_reason: str
    usage: Usage
    model: str


FINISH_TO_STOP = {"tool_calls": "tool_use", "stop": "end_turn", "length": "max_tokens",
                  "content_filter": "refusal"}


class NicrronError(Exception):
    pass


def _to_openai_messages(system: str, messages: list[dict]) -> list[dict]:
    out: list[dict] = [{"role": "system", "content": system}]
    for m in messages:
        content = m["content"]
        if isinstance(content, str):
            out.append({"role": m["role"], "content": content})
            continue
        blocks = [b.model_dump() if hasattr(b, "model_dump") else b for b in content]
        if m["role"] == "assistant":
            text = "".join(b.get("text") or "" for b in blocks if b["type"] == "text")
            calls = [{"id": b["id"], "type": "function",
                      "function": {"name": b["name"], "arguments": json.dumps(b["input"])}}
                     for b in blocks if b["type"] == "tool_use"]
            msg: dict[str, Any] = {"role": "assistant", "content": text or None}
            if calls:
                msg["tool_calls"] = calls
            out.append(msg)
        else:
            for b in blocks:
                if b["type"] == "tool_result":
                    out.append({"role": "tool", "tool_call_id": b["tool_use_id"],
                                "content": str(b["content"])})
                elif b["type"] == "text":
                    out.append({"role": "user", "content": b["text"]})
    return out


def _to_openai_tools(tools: list[dict]) -> list[dict]:
    return [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                              "parameters": t["input_schema"]}} for t in tools]


def _from_openai(data: dict) -> Response:
    choice = data["choices"][0]
    message = choice["message"]
    blocks: list[Block] = []
    if message.get("content"):
        blocks.append(Block(type="text", text=message["content"]))
    for call in message.get("tool_calls") or []:
        try:
            args = json.loads(call["function"].get("arguments") or "{}")
        except ValueError:
            args = {"_invalid_json": call["function"].get("arguments")}
        blocks.append(Block(type="tool_use", id=call["id"], name=call["function"]["name"], input=args))
    usage = data.get("usage") or {}
    return Response(content=blocks,
                    stop_reason=FINISH_TO_STOP.get(choice.get("finish_reason"), "end_turn"),
                    usage=Usage(usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)),
                    model=data.get("model", settings.NICRRON_MODEL))


class NicrronClient:
    """Calls Claude through Nicrron's OpenAI-compatible endpoint."""

    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        self.api_key = api_key or os.environ.get("NICRRON_API_KEY", "")
        self.base_url = (base_url or settings.NICRRON_BASE_URL).rstrip("/")
        self.http = httpx.Client(timeout=300)

    def create(self, system: str, messages: list[dict], tools: list[dict]) -> Response:
        payload = {"model": settings.NICRRON_MODEL, "max_tokens": 16000,
                   "messages": _to_openai_messages(system, messages)}
        if tools:
            payload["tools"] = _to_openai_tools(tools)
        resp = self.http.post(f"{self.base_url}/chat/completions", json=payload,
                              headers={"Authorization": f"Bearer {self.api_key}"})
        if resp.status_code != 200:
            raise NicrronError(f"Nicrron returned {resp.status_code}: {resp.text[:300]}")
        return _from_openai(resp.json())


def provider() -> str:
    choice = settings.LLM_PROVIDER
    if choice in ("anthropic", "nicrron"):
        return choice
    if os.environ.get("NICRRON_API_KEY") and not os.environ.get("ANTHROPIC_API_KEY"):
        return "nicrron"
    return "anthropic"


def default_client() -> Any:
    if provider() == "nicrron":
        return NicrronClient()
    import anthropic
    return anthropic.Anthropic()


def create(client: Any, system: str, messages: list[dict], tools: list[dict]) -> Any:
    """One model turn. Returns an object with .content, .stop_reason, .usage and .model."""
    if isinstance(client, NicrronClient):
        return client.create(system, messages, tools)
    extra = {"tools": tools} if tools else {}
    return client.beta.messages.create(
        model=settings.MODEL,
        max_tokens=16000,
        system=system,
        messages=messages,
        **extra,
        output_config={"effort": "medium"},
        # If a safety classifier declines, retry on a fallback model in the same call.
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
    )
