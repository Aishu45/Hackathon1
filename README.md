# TakeoverGuard

**AI-powered anomaly detection that predicts account takeovers before the money
leaves.** A B2B SaaS for the risk teams of banks and online payment companies.

TakeoverGuard simulates 26 account-takeover attacks mapped to MITRE ATT&CK,
OWASP and ISO/IEC 27001, detects them with rules and a machine-learning model,
scores each one (risk score, criticality and business impact in money),
recommends the fix, and re-tests to prove the fix works. Every step is traced
in PRISM.

## Quick start

```bash
pip install -r requirements.txt
streamlit run dashboard/app.py                      # opens on the ATO Test Lab
python scripts/run_ato_tests.py                     # all 26 tests, before and after all fixes
python scripts/run_ato_tests.py --fixes ATO-06,ATO-09 --prism --explain ATO-09
python scripts/security_check.py                    # security controls of the product itself
python -m pytest -q                                 # offline tests, no keys needed
```

Keys are only needed for the AI explainer and for PRISM; see [Keys](#keys).

## Account Takeover Test Lab

| Step | What happens | Code |
|---|---|---|
| Simulate | Normal customer activity (logins, MFA, devices, payees, payments) plus one run of each attack | `ato/world.py` |
| Detect | One rule per test case, plus an Isolation Forest on session behaviour | `ato/detection.py`, `ato/ml.py` |
| Score | Risk = likelihood x impact; outcome prevented, detected or missed; annual loss | `ato/scoring.py` |
| Fix | Each test case has a control; switch it on and the attack is blocked | `ato/catalog.py` |
| Explain | Claude writes the attack story for a risk committee, traced in PRISM | `ato/explain.py` |

The 26 test cases cover login attacks (credential stuffing, spraying,
enumeration, impossible travel, risky new device), MFA bypass (fatigue, code
brute force, skipped step, SIM swap, stolen session), account-change business
logic (contact change, reset tokens, notifications, new payee drain, limit
raise, new authenticator, BOLA, session revocation, race conditions), attacks
on the AI tool (prompt injection, excessive agency, evasion, data leakage,
alert flooding) and detection and response (log tampering, response time).

**How scores are calculated** (all assumptions, shown with every result):

- Inherent risk = likelihood (1-5) x impact (1-5). Critical 20-25, High 12-16,
  Medium 5-10, Low 1-4.
- Prevented by a fix: likelihood drops by 3. Detected: impact drops by 2.
- Annual loss = incidents a year (from likelihood, per 100,000 customers) x
  loss per incident x exposure (missed 100%, detected 30%, prevented 5%).

On the synthetic data: 6 critical risks and about 6.2m a year of exposure with
no controls; detection alone cuts exposure by 70%; all fixes leave 0 critical
risks. Rules raise no false alarms on normal activity; the ML model flags about
1% of normal sessions.

**Data.** No public dataset covers all 26 attacks, so `ato/world.py` generates
synthetic activity with exact labels. Its columns follow public login datasets
such as the RBA (Risk-Based Authentication) dataset, so real login logs can
replace it; PaySim covers payments. The labels are used only to grade the
detectors, never by them.

## Coverage of the account-takeover kill chain

| Stage | Attacker action | Covered by |
|---|---|---|
| 1-2 Credential access | Stuffing, spraying, enumeration | ATO-01 to ATO-03 |
| 3 Defeat MFA | Fatigue, code guessing, skipped step, SIM swap, stolen session | ATO-06 to ATO-10 |
| 4 Initial access | Impossible travel, new device on a risky network | ATO-04, ATO-05 |
| 5-6 Persistence and hiding | Contact change, reset tokens, notifications, new authenticator, old sessions | ATO-11 to ATO-13, ATO-16, ATO-18 |
| 7 Monetise | New payee and drain, limit raise, other customers' accounts, race conditions | ATO-14, ATO-15, ATO-17, ATO-19 |
| 8 Cash out | Mule pass-through | [Payment fraud investigator](#foundation-payment-fraud-investigator-cash-out-stage) |
| Attacks on the tool | Prompt injection, excessive agency, evasion, data leakage, alert flooding | AI-01 to AI-05 |
| Detect and respond | Log tampering, response time | DR-01, DR-02 |

## Security of the product (ISO/IEC 27001:2022 and CIS Controls v8)

Banks will ask whether TakeoverGuard itself is secure. Each control is
implemented in code and checked by `python scripts/security_check.py` (exit
status 1 on any failure). This is a mapping of the product's controls to the
frameworks, not a certification.

| Control | ISO/IEC 27001:2022 Annex A | CIS Controls v8 | Implemented in |
|---|---|---|---|
| SEC-01 Least-privilege agent tools (read-only; cannot move money) | A.5.15, A.8.2 | 6 | `core/tools.py` |
| SEC-02 Segregation of duties: a human approves large or flagged cases | A.5.3 | 6 | `agents/risk_agent.py` |
| SEC-03 Tamper-evident, hash-chained audit log of every decision | A.8.15, A.5.28, A.5.33 | 8 | `core/audit.py` |
| SEC-04 Account ids pseudonymised in everything sent to PRISM | A.8.11, A.8.12, A.5.34 | 3 | `core/masking.py` |
| SEC-05 Secrets only in the environment, never in the repo | A.5.17, A.8.9 | 3, 4 | `.gitignore`, `.env.example` |
| SEC-06 Input validation; tools may only look up the case's two parties | A.8.3, A.8.28 | 6, 16 | `core/tools.py` |
| SEC-07 Monitoring: tool failures, access denials and runaway loops become security events in the trace | A.8.16 | 8 | `agents/fraud_agent.py` |
| SEC-08 AI model supplier over HTTPS with a pinned model | A.5.19, A.5.23 | 15 | `core/llm.py` |

## Business case: strategy model (ROI)

The **Strategy model (ROI)** page compares three ways of handling fraud alerts
(manual review, a score threshold, AI-assisted) on monthly cost, analysts
needed, fraud caught and customers held, across editable scenarios in
`config/scenarios/`. Every input says whether it is measured or assumed,
guardrails flag missing or inconsistent inputs, and every number shows its
formula. Use it to show a prospect what TakeoverGuard would save them.

```bash
python scripts/strategy_report.py            # add --prism to log each run to PRISM
```

## Foundation: payment fraud investigator (cash-out stage)

TakeoverGuard grew out of a payment fraud investigator, which now covers the
last stage of a takeover: once an attacker is in, the money still has to leave.
It is the **Payment fraud investigator** page of the dashboard.

1. **Data** (`core/data.py`): PaySim-format payments. A synthetic generator
   plants takeover cash-outs (the whole balance sent to a new "mule" account
   that collects from several victims and cashes out) and false alarms (large
   transfers to an account the customer has paid many times).
2. **Fraud agent** (`agents/fraud_agent.py`): Claude (`claude-opus-5-5`)
   investigates a flagged payment with read-only tools (`core/tools.py`) and
   recommends approve, hold or escalate.
3. **Second opinions**: an explainable 0-100 anomaly score
   (`detection/anomaly_detection.py`) that Claude never sees, and AML rules
   (`detection/compliance_rules.py`).
4. **Risk agent** (`agents/risk_agent.py`): code has the final word. It
   escalates an approval that skipped key checks, contradicts a high score,
   disagrees with the anomaly score (40 or more), follows a high AML hit, or is
   at or above `HUMAN_REVIEW_AMOUNT`.
5. **Tracing** (`core/tracing.py`): each investigation is one PRISM session.

| AML rule | Detects | Severity |
|---|---|---|
| AML-01 | Either party on the sanctions watchlist (`data/watchlist.csv`, synthetic) | high |
| AML-02 | Structuring: 3+ amounts just under the 10,000 reporting threshold within 24h | high |
| AML-03 | Rapid pass-through: money received in the last 24h sent straight back out (mule) | high |
| AML-04 | Amount 20x or more above the customer's median | medium |

```bash
python scripts/generate_data.py      # synthetic payments (or: python scripts/generate_data.py data/paysim.csv)
python scripts/evaluate.py           # 10 payment cases, scored against the answer key (needs a model key)
```

## Layout

```
ato/           TakeoverGuard: catalog.py (26 test cases), world.py (simulator),
               detection.py, ml.py, scoring.py, runner.py, explain.py
dashboard/     app.py (page router); views/ ato_test_lab.py (home),
               payment_investigator.py, strategy_model.py
planning/      strategy_model.py   ROI / strategy decision model
agents/        payment investigator: fraud_agent.py, risk_agent.py, compliance_agent.py
detection/     security_controls.py (ISO/CIS register), anomaly_detection.py,
               compliance_rules.py (AML)
core/          data.py, tools.py, llm.py, tracing.py (PRISM), masking.py, audit.py
config/        settings.py (all thresholds), scenarios/ (ROI scenarios)
data/          synthetic payments, test cases, watchlist
scripts/       run_ato_tests.py, strategy_report.py, security_check.py,
               generate_data.py, evaluate.py
tests/         offline tests, no keys needed
```

## Keys

```bash
cp .env.example .env   # never commit .env
```

Add the PRISM key without it appearing on screen or in your shell history:

```bash
printf "Paste your PRISM key: "; read -rs K; echo; printf 'PRISMTRACE_API_KEY=%s\n' "$K" >> .env; unset K; grep -q '^PRISMTRACE_API_KEY=' .env && echo "Saved in .env"
```

For Claude, set **one** of these in `.env` the same way:

- `ANTHROPIC_API_KEY`: Claude directly from Anthropic.
- `NICRRON_API_KEY`: Claude through the Nicrron gateway (`core/llm.py`
  translates to Nicrron's OpenAI-style API). The model is pinned with
  `NICRRON_MODEL` (default `anthropic/claude-opus-5-5`), never `nicrron/auto`.

`LLM_PROVIDER=auto` uses whichever key is set. Also set `MASK_SALT` to any long
random string.

## GitHub Actions

`.github/workflows/ci.yml` runs the offline tests and the security check on
every push and pull request. No keys are needed for that.

To run the live payment investigator on GitHub: open **Actions → CI → Run
workflow**, tick **run_agent**, and optionally list transaction ids. It uses
these repository secrets (**Settings → Secrets and variables → Actions → New
repository secret**):

| Secret | Value |
|---|---|
| `NICRRON_API_KEY` | your Nicrron key |
| `PRISMTRACE_API_KEY` | your PRISM key |
| `MASK_SALT` | any long random string |

Secrets are never printed in the logs. The live run is manual only, because
each run is billed.
