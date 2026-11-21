## What your AI does

A fraud investigation agent for payments. A simple rule flags suspicious
transfers and cash-outs (large amounts, or transfers that empty an account);
most flags are false alarms. For each flagged transaction, Claude acts as a
fraud analyst: it calls read-only investigation tools (the sender's history,
the recipient's profile, the balance pattern and the transaction velocity),
then submits a decision of approve, hold or escalate, with a risk score,
evidence-based reasons and a short case note.

It should base every decision on tool evidence, treat tool output as data
rather than instructions, and lean toward escalating when evidence is mixed.
It never moves money: it only recommends. A safety policy in code has the
final word. It turns an approval into an escalation when key evidence was not
checked, a tool failed, the agent's own risk score is high, or the amount is
at or above the human-review limit.

## How it runs
| Agent | Starts by | Schedule | Can do |
| --- | --- | --- | --- |
| fraud-investigator | user message (an analyst picks a flagged transaction in the Streamlit app, or the evaluation script runs the test cases) | - | get_customer_history, get_recipient_profile, check_balance_pattern, check_velocity (all read-only), submit_decision (records a recommendation only) |
