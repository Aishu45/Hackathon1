"""TakeoverGuard dashboard.

Run:  streamlit run dashboard/app.py

Pages:
  ATO Test Lab                 (home) 26 account-takeover attacks: detect, score, fix, re-test
  Payment fraud investigator   Claude investigates one flagged payment (the cash-out stage)
  Strategy model (ROI)         compares alert-handling strategies on monthly cost
"""
from pathlib import Path

import streamlit as st

HERE = Path(__file__).resolve().parent

st.set_page_config(page_title="TakeoverGuard", layout="wide")
page = st.navigation({
    "TakeoverGuard": [
        st.Page(HERE / "views" / "ato_test_lab.py", title="ATO Test Lab", icon="🛡️", default=True),
    ],
    "Foundation and business case": [
        st.Page(HERE / "views" / "payment_investigator.py", title="Payment fraud investigator", icon="🔎"),
        st.Page(HERE / "views" / "strategy_model.py", title="Strategy model (ROI)", icon="📊"),
    ],
})
page.run()
