# Fraud Investigation Agent

Python project. Claude (Anthropic SDK, Messages API, manual tool loop in
`fraud_agent/agent.py`) investigates flagged payment transactions. Data is
PaySim-format CSV in `data/`. Run tests with `python -m pytest -q`.

Rules for this repository:
- The agent must never see the `isFraud` / `isFlaggedFraud` labels; tools only
  read transactions earlier than the one under review.
- Tools stay read-only. No tool may move money.
- `fraud_agent/guardrails.py` may only make a decision more cautious.

## PRISM tracing (do not remove)

This project sends traces to PRISM. Env vars: `PRISMTRACE_API_KEY`,
`PRISMTRACE_PROJECT_ID`, `PRISMTRACE_HOST`.

Tracing is currently wired at: fraud_agent/tracing.py, fraud_agent/agent.py, scripts/evaluate.py, app.py

**Standing rule.** Whenever you add or change an agent, chain, graph, tool,
retriever, or any entry point that calls a model, wire it to PRISM before you
finish. Unwired code is invisible in the dashboard. If you are unsure whether
something is covered, assume it is not and wire it.
