# compliance-fraud-agent

Trust & Risk track. A rule flags suspicious payments, and most flags are false
alarms. This project investigates each one the way an analyst would, decides
**approve**, **hold** or **escalate**, and explains why. Every step is
traced in PRISM, so you can see exactly how each decision was made.

## Layout

```
data/          sample_transactions.csv (synthetic, PaySim format), test_cases.csv
agents/        fraud_agent.py   Claude investigates with read-only tools
               risk_agent.py    final decision, enforced in code
               compliance_agent.py   runs the AML rules
detection/     compliance_rules.py   AML rules
               security_controls.py  ISO/IEC 27001 + CIS control register and checks
               anomaly_detection.py  explainable 0-100 score, no AI
core/          data.py, tools.py, tracing.py (PRISM), masking.py, audit.py
config/        settings.py      all thresholds in one place
dashboard/     app.py           Streamlit demo
scripts/       generate_data.py, evaluate.py, security_check.py
tests/         offline tests, no keys needed
```

## How it works

1. **Data** (`core/data.py`): PaySim-format transactions. A synthetic
   generator plants account-takeover fraud (whole balance sent to a new "mule"
   account that collects from several victims and cashes out) and false alarms
   (large transfers to an account the customer has paid many times).
2. **Tools** (`core/tools.py`): read-only lookups of the sender's history, the
   recipient's profile, the balance pattern and velocity. They only see
   transactions **before** the one under review and **never** see the fraud
   labels.
3. **Fraud agent** (`agents/fraud_agent.py`): Claude (`claude-opus-5-5`)
   chooses which tools to call, then calls `submit_decision`.
4. **Risk agent** (`agents/risk_agent.py`): code, not the prompt, has the final
   word. It escalates an approval that skipped key checks, follows a failed
   tool or contradicts a high risk score, and sends every amount at or above
   `HUMAN_REVIEW_AMOUNT` to a human. Nothing in the system can move money.
5. **Tracing** (`core/tracing.py`): each investigation is one PRISM session.
   Every Claude call goes through `trace_llm`, and the tool calls, the risk
   check and the decision go in as one trajectory. A local copy goes to
   `traces.jsonl`.

## Anomaly detection (second opinion)

`detection/anomaly_detection.py` scores each transaction from 0 to 100 with
plain, explainable signals: the account is emptied, money that just arrived is
moved straight on, a new or brand-new recipient, a recipient collecting from
many senders, an unusual amount or a burst of activity. An established payee
lowers the score. Claude never sees this score, so it stays independent. If
Claude approves but the score is `ANOMALY_ESCALATE_SCORE` (40) or higher, the
risk agent escalates the case to a human. The combined risk shown is the more
cautious of the two scores.

## AML compliance rules

Deterministic rules in `detection/compliance_rules.py`; thresholds in
`config/settings.py`. A **high** hit blocks the AI from approving, so a
compliance officer must review.

| Rule | Detects | Severity |
|---|---|---|
| AML-01 | Either party on the sanctions watchlist (`data/watchlist.csv`, synthetic) | high |
| AML-02 | Structuring: 3+ amounts just under the 10,000 reporting threshold within 24h | high |
| AML-03 | Rapid pass-through: money received in the last 24h sent straight back out (mule) | high |
| AML-04 | Amount 20x or more above the customer's median | medium |

## Security controls (ISO/IEC 27001:2022 and CIS Controls v8)

Each control is implemented in code and checked by
`python scripts/security_check.py` (exit status 1 on any failure). This is a
mapping of the agent's controls to the frameworks, not a certification.

| Control | ISO/IEC 27001:2022 Annex A | CIS Controls v8 | Implemented in |
|---|---|---|---|
| SEC-01 Least-privilege agent tools (read-only; cannot move money) | A.5.15, A.8.2 | 6 | `core/tools.py` |
| SEC-02 Segregation of duties: a human approves large or flagged cases | A.5.3 | 6 | `agents/risk_agent.py` |
| SEC-03 Tamper-evident, hash-chained audit log of every decision | A.8.15, A.5.28, A.5.33 | 8 | `core/audit.py` |
| SEC-04 Account ids pseudonymised in everything sent to PRISM | A.8.11, A.8.12, A.5.34 | 3 | `core/masking.py` |
| SEC-05 Secrets only in the environment, never in the repo | A.5.17, A.8.9 | 3, 4 | `.gitignore`, `.env.example` |
| SEC-06 Input validation; tools may only look up the case's two parties | A.8.3, A.8.28 | 6, 16 | `core/tools.py` |
| SEC-07 Monitoring: tool failures, access denials and runaway loops become security events in the trace | A.8.16 | 8 | `agents/fraud_agent.py` |

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env   # then add your keys as shown below; never commit .env
```

Add the PRISM key without it appearing on screen or in your shell history:

```bash
printf "Paste your PRISM key: "; read -rs K; echo; printf 'PRISMTRACE_API_KEY=%s\n' "$K" >> .env; unset K; grep -q '^PRISMTRACE_API_KEY=' .env && echo "Saved in .env"
```

For Claude, either set `ANTHROPIC_API_KEY` in `.env` the same way, or run
`ant auth login`.

## Run

```bash
python scripts/generate_data.py      # synthetic data (or: python scripts/generate_data.py data/paysim.csv)
python scripts/evaluate.py           # 10 test cases, scored against the answer key
streamlit run dashboard/app.py       # demo page
python scripts/security_check.py     # security control report
python -m pytest -q                  # offline tests
```

Each case's PRISM session id is printed, so you can open its trace in PRISM.
