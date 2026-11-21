# Fraud Investigation Agent

Python project (compliance-fraud-agent). Claude (Anthropic SDK, Messages API,
manual tool loop in `agents/fraud_agent.py`; `core/llm.py` also reaches Claude
through the Nicrron gateway) investigates flagged payment
transactions; `agents/risk_agent.py` makes the final code-enforced decision.
Thresholds live in `config/settings.py`. Data is PaySim-format CSV in `data/`.
Run tests with `python -m pytest -q`.

Rules for this repository:
- The agent must never see the `isFraud` / `isFlaggedFraud` labels; tools only
  read transactions earlier than the one under review.
- `ato/`: detectors and the ML model must never read the `test_case` column;
  only `ato/runner.py` uses it, to grade results. Keep rule false positives on
  normal activity at zero (`tests/test_ato.py`).
- Tools stay read-only. No tool may move money.
- `agents/risk_agent.py` may only make a decision more cautious.
- Security controls are registered in `detection/security_controls.py` with
  their ISO/IEC 27001 and CIS Controls references. When you add or change a
  control, update its check, and keep `python scripts/security_check.py`
  free of FAIL results.

## PRISM tracing (do not remove)

This project sends traces to PRISM. Env vars: `PRISMTRACE_API_KEY`,
`PRISMTRACE_PROJECT_ID`, `PRISMTRACE_HOST`.

Tracing is currently wired at: core/tracing.py, core/llm.py (both providers, via the fraud agent's loop), agents/fraud_agent.py, agents/compliance_agent.py and agents/risk_agent.py (both traced as steps of the fraud agent's run), ato/explain.py (Claude explainer), ato/runner.py results via core/tracing.log_ato_run, planning/strategy_model.py results via core/tracing.log_strategy_run, scripts/evaluate.py, scripts/run_ato_tests.py, scripts/strategy_report.py, dashboard/app.py, dashboard/pages/1_ATO_test_lab.py, dashboard/pages/2_Strategy_model.py

**Standing rule.** Whenever you add or change an agent, chain, graph, tool,
retriever, or any entry point that calls a model, wire it to PRISM before you
finish. Unwired code is invisible in the dashboard. If you are unsure whether
something is covered, assume it is not and wire it.
