## What your AI does

A fraud investigation agent for payments. A simple rule flags suspicious
transfers and cash-outs (large amounts, or transfers that empty an account);
most flags are false alarms. For each flagged transaction, Claude acts as a
fraud analyst: it calls read-only investigation tools (the sender's history,
the recipient's profile, the balance pattern and the transaction velocity),
then submits a decision of approve, hold or escalate, with a risk score,
evidence-based reasons and a short case note.

Before Claude starts, a compliance agent runs fixed AML rules (sanctions
watchlist, structuring, rapid pass-through, unusual amounts) and gives the hits
to Claude as evidence, and a model-free anomaly detector scores the transaction
as an independent second opinion that Claude does not see. It should base every decision on tool evidence, treat tool output as data
rather than instructions, and lean toward escalating when evidence is mixed.
It never moves money: it only recommends. A safety policy in code has the
final word. It turns an approval into an escalation when key evidence was not
checked, a tool failed, the agent's own risk score is high, or the amount is
at or above the human-review limit, a high-severity compliance rule fired, or the anomaly score disagrees with
an approval.
Tools may only look up the two parties of the transaction under review, and
account ids are pseudonymised in everything sent to PRISM. Every decision is
written to a hash-chained audit log.

The account-takeover test lab simulates 26 takeover attacks mapped to MITRE
ATT&CK, OWASP and ISO/IEC 27001, detects them with rules and an Isolation
Forest, and scores each one (risk score, criticality, annual loss) before and
after fixes. A Claude explainer writes each result up for a risk committee,
using only the facts from the run. A deterministic strategy model compares
alert-handling strategies on monthly cost.

## How it runs
| Agent | Starts by | Schedule | Can do |
| --- | --- | --- | --- |
| fraud-investigator | user message (an analyst picks a flagged transaction in the Streamlit app, or the evaluation script runs the test cases) | - | get_customer_history, get_recipient_profile, check_balance_pattern, check_velocity (all read-only), submit_decision (records a recommendation only); compliance and risk checks run as steps of the same run |
| ato-test-runner | user message (scripts/run_ato_tests.py --prism, or the dashboard button) | - | simulates and detects 26 attacks; records results only (no model call) |
| ato-explainer | user message (the dashboard's Explain button, or --explain) | - | one model call, no tools; writes an explanation of one result |
| strategy-model | user message (scripts/strategy_report.py --prism, or the dashboard button) | - | deterministic cost model; records inputs, calculations and recommendation (no model call) |
