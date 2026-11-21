"""Tests for the Nicrron adapter (Anthropic format <-> OpenAI chat format), offline."""
from core import llm


def test_history_and_tools_translate_to_openai_format():
    history = [
        {"role": "user", "content": "Review T1"},
        {"role": "assistant", "content": [llm.Block(type="text", text="Checking."),
                                          llm.Block(type="tool_use", id="t1", name="check_velocity",
                                                    input={"customer_id": "C100001"})]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "{}"}]},
    ]
    out = llm._to_openai_messages("sys", history)
    assert [m["role"] for m in out] == ["system", "user", "assistant", "tool"]
    assert out[2]["tool_calls"][0]["function"]["name"] == "check_velocity"
    assert out[3]["tool_call_id"] == "t1"
    tools = llm._to_openai_tools([{"name": "x", "description": "d", "input_schema": {"type": "object"}}])
    assert tools[0]["function"]["parameters"] == {"type": "object"}


def test_openai_response_becomes_anthropic_shape():
    data = {"model": "anthropic/claude-opus-5-5", "usage": {"prompt_tokens": 7, "completion_tokens": 3},
            "choices": [{"finish_reason": "tool_calls", "message": {"content": None, "tool_calls": [
                {"id": "toolu_1", "function": {"name": "submit_decision",
                                               "arguments": "{\"decision\": \"hold\"}"}}]}}]}
    r = llm._from_openai(data)
    assert r.stop_reason == "tool_use" and r.usage.input_tokens == 7
    assert r.content[0].type == "tool_use" and r.content[0].input == {"decision": "hold"}


def test_bad_tool_arguments_do_not_crash():
    data = {"choices": [{"finish_reason": "tool_calls", "message": {"tool_calls": [
        {"id": "a", "function": {"name": "check_velocity", "arguments": "{not json"}}]}}]}
    assert "_invalid_json" in llm._from_openai(data).content[0].input
