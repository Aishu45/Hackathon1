# Fraud Investigation Agent

Python project (compliance-fraud-agent). Claude (Anthropic SDK, Messages API,
manual tool loop in `agents/fraud_agent.py`) investigates flagged payment
transactions; `agents/risk_agent.py` makes the final code-enforced decision.
Thresholds live in `config/settings.py`. Data is PaySim-format CSV in `data/`.
Run tests with `python -m pytest -q`.

Rules for this repository:
- The agent must never see the `isFraud` / `isFlaggedFraud` labels; tools only
  read transactions earlier than the one under review.
- Tools stay read-only. No tool may move money.
- `agents/risk_agent.py` may only make a decision more cautious.

## PRISM tracing (do not remove)

This project sends traces to PRISM. Env vars: `PRISMTRACE_API_KEY`,
`PRISMTRACE_PROJECT_ID`, `PRISMTRACE_HOST`.

Tracing is currently wired at: core/tracing.py, agents/fraud_agent.py, agents/risk_agent.py (via the fraud agent's policy step), scripts/evaluate.py, dashboard/app.py

**Standing rule.** Whenever you add or change an agent, chain, graph, tool,
retriever, or any entry point that calls a model, wire it to PRISM before you
finish. Unwired code is invisible in the dashboard. If you are unsure whether
something is covered, assume it is not and wire it.
