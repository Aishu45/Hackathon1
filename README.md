# Fraud Investigation Agent

Trust & Risk track. A rule flags suspicious payments, and most flags are false
alarms. This agent investigates each one the way an analyst would, decides
**approve**, **hold** or **escalate**, and explains why. Every step is
traced in PRISM, so you can see exactly how each decision was made.

## How it works

1. **Data** (`fraud_agent/data.py`): PaySim-format transactions. A synthetic
   generator plants account-takeover fraud (whole balance sent to a new "mule"
   account that collects from several victims and cashes out) and false alarms
   (large transfers to an account the customer has paid many times).
2. **Tools** (`fraud_agent/tools.py`): read-only lookups of the sender's
   history, the recipient's profile, the balance pattern and velocity. They
   only see transactions **before** the one under review and **never** see the
   fraud labels.
3. **Agent** (`fraud_agent/agent.py`): Claude (`claude-opus-5-5`) chooses
   which tools to call, then calls `submit_decision`.
4. **Safety policy** (`fraud_agent/guardrails.py`): code, not the prompt, has
   the final word. It escalates an approval that skipped key checks, follows a
   failed tool or contradicts a high risk score, and sends every amount at or
   above `HUMAN_REVIEW_AMOUNT` to a human. The agent can never move money.
5. **Tracing** (`fraud_agent/tracing.py`): each investigation is one PRISM
   session. Every Claude call goes through `trace_llm`, and the tool calls, the
   policy check and the decision go in as one trajectory. A local copy goes to
   `traces.jsonl`.

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
python scripts/make_data.py          # synthetic data (or: python scripts/make_data.py data/paysim.csv)
python scripts/evaluate.py           # 10 test cases, scored against the answer key
streamlit run app.py                 # demo page
python -m pytest -q                  # offline tests, no keys needed
```

Each case's PRISM session id is printed, so you can open its trace in PRISM.
