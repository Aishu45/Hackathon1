"""Streamlit demo: pick a flagged transaction, let the agent investigate it.

Run:  streamlit run dashboard/app.py
"""
import sys
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")  # before the imports below read settings

from agents.fraud_agent import investigate  # noqa: E402
from config.settings import TRANSACTIONS_CSV  # noqa: E402
from core.data import build_alerts, split_answer_key  # noqa: E402

st.set_page_config(page_title="Fraud Investigation Agent", layout="wide")


@st.cache_data
def load() -> tuple[pd.DataFrame, pd.DataFrame]:
    df = pd.read_csv(TRANSACTIONS_CSV)
    return df, build_alerts(df)


df, alerts = load()
visible_alerts, answer_key = split_answer_key(alerts)

st.title("Fraud Investigation Agent")
st.caption("Claude investigates each flagged transaction like an analyst. A code-enforced "
           "policy has the final say, and every step is traced in PRISM.")

c1, c2 = st.columns(2)
c1.metric("Flagged by the rule", len(alerts))
c2.metric("Of which false alarms", f"{1 - alerts['isFraud'].mean():.0%}")

labels = {
    r.txn_id: f"{r.txn_id} · {r.type} · {r.amount:,.0f} · {r.nameOrig} → {r.nameDest}"
    for r in visible_alerts.itertuples()
}
txn_id = st.selectbox("Flagged transaction", list(labels), format_func=labels.get)
show_truth = st.toggle("Show the answer key (for judges)", value=False)

if st.button("Investigate", type="primary"):
    with st.spinner("Investigating..."):
        result = investigate(df, txn_id)

    colour = {"approve": "green", "hold": "red", "escalate": "orange"}[result["decision"]]
    st.markdown(f"## Decision: :{colour}[{result['decision'].upper()}]  ·  "
                f"risk {result['risk_score'] if result['risk_score'] is not None else 'n/a'}/100")
    if result["policy_overrides"]:
        st.warning(f"Safety policy changed the agent's '{result['agent_decision']}' to "
                   f"'{result['decision']}'.")
    st.write(result["case_note"])
    st.markdown("**Reasons**")
    for reason in result["reasons"]:
        st.markdown(f"- {reason}")

    st.markdown("**Evidence gathered**")
    for item in result["evidence"]:
        with st.expander(item["tool"]):
            st.json(item["output"])

    st.caption(f"PRISM session: `{result['session_id']}`. Open it in PRISM to see the full trace.")
    if show_truth:
        truth = int(answer_key.set_index("txn_id").loc[txn_id, "isFraud"])
        st.info(f"Answer key: {'FRAUD' if truth else 'legitimate'}")
