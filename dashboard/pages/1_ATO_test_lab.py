"""Account Takeover Test Lab: run 26 attacks, see risk, criticality, business impact and fixes."""
import sys
from pathlib import Path

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from ato.catalog import BY_ID, CATALOG  # noqa: E402
from ato.runner import run_tests  # noqa: E402
from ato.scoring import Assumptions  # noqa: E402
from core import tracing  # noqa: E402

st.set_page_config(page_title="ATO Test Lab", layout="wide")
COLOURS = {"Critical": "#d64545", "High": "#e8913a", "Medium": "#e8c93a", "Low": "#5aa469"}


@st.cache_data(show_spinner="Simulating 26 attacks and running detection...")
def cached_run(fixes: tuple[str, ...], customers: int, seed: int):
    r = run_tests(set(fixes), seed=seed, assumptions=Assumptions(customers=customers))
    return r.report, r.summary, r.events, r.false_positives


st.title("Account Takeover Test Lab")
st.caption("Simulates 26 account-takeover attacks mapped to MITRE ATT&CK, OWASP and ISO/IEC 27001, "
           "detects them with rules and a machine-learning model, and scores each one: risk score, "
           "criticality and business impact, before and after fixes.")

with st.sidebar:
    st.header("Fixes to switch on")
    preset = st.radio("Start from", ["None", "Critical risks only", "All"], horizontal=True)
    default = {"None": [], "All": [tc.id for tc in CATALOG],
               "Critical risks only": [tc.id for tc in CATALOG if tc.inherent_score >= 20]}[preset]
    fixes = st.multiselect("Fixes", [tc.id for tc in CATALOG], default=default,
                           format_func=lambda i: f"{i} {BY_ID[i].title}", key=f"fixes-{preset}")
    st.header("Assumptions")
    customers = st.number_input("Customers", 1_000, 50_000_000, 100_000, step=10_000)
    seed = st.number_input("Random seed (new synthetic dataset)", 1, 999, 7)

before, sb, _, _ = cached_run((), customers, seed)
after, sa, events, fps = cached_run(tuple(sorted(fixes)), customers, seed)

# ------------------------------------------------------------ headline
c1, c2, c3, c4 = st.columns(4)
c1.metric("Critical risks (no controls → now)", f"{sb['critical_before']} → {sa['critical_after']}")
c2.metric("High risks remaining", sa["high_after"])
c3.metric("Annual exposure, no controls", f"£{sb['inherent_annual_loss']:,.0f}")
c4.metric("Annual exposure, now", f"£{sa['residual_annual_loss']:,.0f}",
          f"-{1 - sa['residual_annual_loss'] / max(sb['inherent_annual_loss'], 1):.0%}", delta_color="inverse")
st.caption(f"Now: {sa['prevented']} attacks prevented by fixes, {sa['detected']} detected, {sa['missed']} missed. "
           f"Detection alone (no fixes) brings exposure to £{sb['residual_annual_loss']:,.0f}. "
           f"False alarms on normal activity: rules {sum(v for k, v in fps.items() if k != 'ML model')}, "
           f"ML model {fps.get('ML model', 0)} sessions.")

# ------------------------------------------------------------ heat maps
def heat(df: pd.DataFrame, L: str, I: str):
    grid = pd.DataFrame(0, index=[5, 4, 3, 2, 1], columns=[1, 2, 3, 4, 5])
    for l_, i_ in zip(df[L], df[I]):
        grid.loc[l_, i_] += 1
    grid.index.name, grid.columns.name = "Likelihood", "Impact"

    def colour(v, l_, i_):
        crit = "Critical" if l_ * i_ >= 20 else "High" if l_ * i_ >= 12 else "Medium" if l_ * i_ >= 5 else "Low"
        return f"background-color: {COLOURS[crit]}; color: black; opacity: {1 if v else 0.35}"

    styles = pd.DataFrame([[colour(grid.loc[l_, i_], l_, i_) for i_ in grid.columns] for l_ in grid.index],
                          index=grid.index, columns=grid.columns)
    return grid.style.apply(lambda _: styles, axis=None).format(lambda v: v or "")


h1, h2 = st.columns(2)
h1.markdown("**Risk heat map: no controls (inherent)**")
h1.table(heat(after, "likelihood", "impact"))
h2.markdown("**Risk heat map: with detection and the fixes selected**")
h2.table(heat(after, "residual_likelihood", "residual_impact"))
st.caption("Rows: likelihood (5 = almost certain). Columns: impact (5 = severe). Each number is how many "
           "test cases sit in that cell; colour shows criticality (red Critical, orange High, yellow Medium, "
           "green Low).")

# ------------------------------------------------------------ results table
st.subheader("Test results")
table = after[["id", "area", "title", "mitre", "owasp", "iso27001", "inherent_score", "inherent_criticality",
               "outcome", "residual_score", "residual_criticality", "inherent_annual_loss",
               "residual_annual_loss", "fix_on"]].rename(columns={
    "id": "ID", "area": "Area", "title": "Test case", "mitre": "MITRE ATT&CK / ATLAS", "owasp": "OWASP",
    "iso27001": "ISO 27001", "inherent_score": "Risk before", "inherent_criticality": "Criticality before",
    "outcome": "Outcome", "residual_score": "Risk now", "residual_criticality": "Criticality now",
    "inherent_annual_loss": "Annual loss before (£)", "residual_annual_loss": "Annual loss now (£)",
    "fix_on": "Fix on"})


def crit_style(v):
    return f"background-color: {COLOURS.get(v, '')}; color: black" if v in COLOURS else ""


st.dataframe(table.style.map(crit_style, subset=["Criticality before", "Criticality now"])
             .format({"Annual loss before (£)": "{:,.0f}", "Annual loss now (£)": "{:,.0f}"}),
             hide_index=True, width="stretch")

# ------------------------------------------------------------ drill-down
st.subheader("Drill into a test case")
pick = st.selectbox("Test case", [tc.id for tc in CATALOG], format_func=lambda i: f"{i} {BY_ID[i].title}")
tc, row = BY_ID[pick], after.set_index("id").loc[pick].to_dict() | {"id": pick}
a, b = st.columns(2)
with a:
    st.markdown(f"**Test steps:** {tc.steps}")
    st.markdown(f"**Pass if:** {tc.pass_if}")
    st.markdown(f"**MITRE:** {tc.mitre}  \n**OWASP:** {tc.owasp}  \n**ISO/IEC 27001:** {tc.iso27001}")
    st.markdown(f"**Business impact:** {tc.business_impact}")
    st.markdown(f"**Fix:** {tc.fix} {'(on)' if row['fix_on'] else '(off)'}")
with b:
    outcome_box = {"prevented": st.success, "detected": st.warning, "missed": st.error}[row["outcome"]]
    outcome_box(f"Outcome: **{row['outcome'].upper()}**: risk {row['inherent_score']} "
                f"({row['inherent_criticality']}) → {row['residual_score']} ({row['residual_criticality']})")
    st.markdown("**How the numbers were calculated**")
    for line in row["trace"]:
        st.markdown(f"- {line}")
    st.markdown(f"**Rule evidence:** {row['evidence'] or 'no rule fired'}")
    st.markdown(f"**ML model:** {'flagged, anomaly score ' + str(row['ml_anomaly_score']) if row['detected_by_ml'] else 'not flagged'}")

attack_events = events[events["test_case"] == pick]
with st.expander(f"Attack activity ({len(attack_events)} events)"):
    st.dataframe(attack_events[["t", "user_id", "session_id", "event", "country", "asn", "device_id",
                                "amount", "balance", "payee_id", "reason", "text"]].head(200),
                 hide_index=True, width="stretch")

e1, e2 = st.columns(2)
if e1.button("Explain this result with AI"):
    from ato.explain import explain
    try:
        with st.spinner("Claude is writing the explanation..."):
            st.info(explain(row, attack_events))
        tracing.close()
    except Exception as exc:  # no model key, network, etc.
        st.error(f"AI explanation unavailable: {exc.__class__.__name__}. Set ANTHROPIC_API_KEY or NICRRON_API_KEY.")
if e2.button("Log this test run to PRISM"):
    sid = tracing.log_ato_run(f"dashboard run, {len(fixes)} fixes", after, sa)
    tracing.close()
    e2.write(f"Logged to PRISM as `{sid}`." if sid else "PRISM key not set; saved to traces.jsonl only.")

st.caption("Synthetic data with planted attacks; scores, losses and incident rates are assumptions to tune "
           "with your risk team. See ato/scoring.py for the formulas.")
