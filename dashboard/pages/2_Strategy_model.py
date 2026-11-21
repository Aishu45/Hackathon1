"""Strategy decision model page: which fraud-alert strategy costs least?"""
import sys
from pathlib import Path

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from config.settings import TRANSACTIONS_CSV  # noqa: E402
from core import tracing  # noqa: E402
from planning.strategy_model import (STRATEGIES, best, build, compare_scenarios,  # noqa: E402
                                     default_inputs, load_scenarios)

st.set_page_config(page_title="Strategy model", layout="wide")


@st.cache_data
def load() -> pd.DataFrame:
    return pd.read_csv(TRANSACTIONS_CSV)


df = load()
scenarios = load_scenarios()

st.title("Fraud alert strategy: which approach costs least?")
st.caption("Combines financial data (analyst cost, fraud losses, customer value, AI cost) with "
           "non-financial data (alert volume, catch rates, review time, customer churn) to compare "
           "three ways of handling fraud alerts. Every number below can be traced to its inputs.")

# ----------------------------------------------------------- adapt inputs
with st.sidebar:
    st.header("Scenario")
    preset_key = st.selectbox("Start from", list(scenarios), format_func=lambda k: scenarios[k]["name"])
    preset = scenarios[preset_key].get("overrides", {})
    st.caption(scenarios[preset_key].get("description", ""))

    st.header("Assumptions")
    overrides: dict[str, float] = {}
    for key, inp in default_inputs().items():
        start = float(preset.get(key, inp.value))
        if inp.unit == "share":
            overrides[key] = st.slider(inp.label, 0.0, 1.0, start, 0.01, key=f"{preset_key}-{key}")
        else:
            overrides[key] = st.number_input(f"{inp.label} ({inp.unit})", value=start, min_value=0.0,
                                             key=f"{preset_key}-{key}")
    with st.expander("Override measured rates"):
        st.caption("Leave a box ticked off to use the value measured from the data.")
        for key, label in [("fraud_share", "Share of alerts that are fraud"),
                           ("threshold_fraud_reviewed", "Threshold: fraud sent to analysts"),
                           ("threshold_genuine_reviewed", "Threshold: false alarms sent to analysts"),
                           ("ai_fraud_flagged", "AI: fraud it holds or escalates"),
                           ("ai_genuine_cleared", "AI: false alarms it clears")]:
            if st.checkbox(f"Override: {label}", value=key in preset, key=f"{preset_key}-use-{key}"):
                overrides[key] = st.slider(label, 0.0, 1.0, float(preset.get(key, 0.5)), 0.01,
                                           key=f"{preset_key}-val-{key}")

out = build(df, overrides)
inputs, results, flags = out["inputs"], out["results"], out["flags"]
errors = [f for f in flags if f.level == "error"]

# --------------------------------------------------------------- results
st.subheader("1. Recommendation")
if errors:
    for f in errors:
        st.error(f.message)
    st.stop()
winner = best(results)
st.success(f"**Best strategy: {winner.label}**")
for line in out["explanation"]:
    st.markdown(f"- {line}")

cols = st.columns(len(results))
base_cost = next(r for r in results if r.strategy == "manual").value("total_cost")
for col, r in zip(cols, results):
    delta = r.value("total_cost") - base_cost
    col.metric(r.label.split(":")[0], f"{r.value('total_cost'):,.0f} / month",
               None if r.strategy == "manual" else f"{delta:,.0f} vs manual", delta_color="inverse")
    col.caption(f"{r.value('analysts_needed'):.0f} analysts · catches {r.value('catch_rate'):.0%} of fraud "
                f"· {r.value('genuine_held'):,.0f} genuine customers held")

breakdown = pd.DataFrame({r.label.split(":")[0]: {
    "Staff": r.value("staff_cost"), "Fraud losses": r.value("fraud_losses"),
    "Lost customers": r.value("lost_customer_cost"), "AI": r.value("ai_cost")} for r in results}).T
st.bar_chart(breakdown, horizontal=True)

st.subheader("2. Guardrails")
for f in flags:
    (st.warning if f.level == "warning" else st.info)(f"**{f.level.title()}:** {f.message}")

st.subheader("3. Inputs and assumptions")
st.dataframe(pd.DataFrame([{"Input": i.label, "Value": i.value, "Unit": i.unit, "Type": i.kind,
                            "Source": i.source, "Note": i.note} for i in inputs.values()]),
             hide_index=True, width="stretch")

st.subheader("4. How each number was calculated")
for r in results:
    with st.expander(r.label):
        st.dataframe(pd.DataFrame([{"Step": s.name, "Formula": s.formula,
                                    "Inputs": ", ".join(f"{k} = {v:,}" for k, v in s.inputs.items()),
                                    "Result": f"{s.value:,.2f} {s.unit}"} for s in r.steps]),
                     hide_index=True, width="stretch")

st.subheader("5. Compare scenarios")
table = compare_scenarios(df, scenarios)
table["Best"] = table.pop("best").map({True: "✅", False: ""})
st.dataframe(table.rename(columns={"scenario": "Scenario", "strategy": "Strategy",
                                   "total_cost": "Total cost / month", "analysts_needed": "Analysts",
                                   "catch_rate": "Fraud caught", "customers_held": "Customers held"})
             .style.format({"Total cost / month": "{:,.0f}", "Fraud caught": "{:.0%}",
                            "Customers held": "{:,.0f}"}),
             hide_index=True, width="stretch")
st.caption("Add your own scenario as a JSON file in config/scenarios/.")

if st.button("Log this analysis to PRISM"):
    sid = tracing.log_strategy_run(scenarios[preset_key]["name"] + " (adjusted)", inputs, results,
                                   flags, out["explanation"])
    tracing.close()
    st.write(f"Logged to PRISM as `{sid}`." if sid else "PRISM key not set; saved to traces.jsonl only.")
