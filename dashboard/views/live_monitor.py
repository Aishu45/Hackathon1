"""Live monitor: real-time activity stream, attack launcher and live alerts."""
import json
import os
import sys
import threading
import time
from pathlib import Path

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from ato.catalog import BY_ID, CATALOG  # noqa: E402
from ato.live import LiveEngine, connect, read_state, send_command, sim_clock  # noqa: E402

DB = ROOT / "live" / "live.db"
COLOURS = {"Critical": "#d64545", "High": "#e8913a", "Medium": "#e8c93a", "Low": "#5aa469"}
CRITICAL = [tc.id for tc in CATALOG if tc.inherent_score >= 20]
SHORT = {"ATO-01": "Credential stuffing", "ATO-05": "Risky new device", "ATO-06": "MFA fatigue",
         "ATO-09": "SIM swap", "ATO-10": "Stolen session", "ATO-14": "Payee + drain"}


def engine_alive() -> bool:
    try:
        return time.time() - float(read_state(DB).get("heartbeat", 0)) < 5
    except Exception:
        return False


@st.cache_resource
def start_engine() -> tuple[LiveEngine, threading.Event]:
    """One engine per dashboard server, started on first visit."""
    DB.parent.mkdir(exist_ok=True)
    engine = LiveEngine(DB, prism=bool(os.environ.get("PRISMTRACE_API_KEY")))
    stop = threading.Event()
    threading.Thread(target=engine.run, args=(stop,), daemon=True, name="live-engine").start()
    return engine, stop


st.title("Live monitor")
st.caption("Customer activity streams in real time (1 second = 1 simulated minute). Launch an attack and "
           "watch TakeoverGuard detect it within seconds. Switch a fix on and launch it again to see it blocked. "
           "Every alert is traced to PRISM; Claude (through Nicrron or Anthropic) can explain any alert.")

if not engine_alive():
    start_engine()
    with st.spinner("Starting the live stream..."):
        for _ in range(20):
            if engine_alive():
                break
            time.sleep(0.5)

# ----------------------------------------------------------------- controls
state = read_state(DB)
c1, c2 = st.columns([3, 2])
with c1:
    st.markdown("**Launch an attack**")
    for start in range(0, len(CRITICAL), 3):
        for col, tid in zip(st.columns(3), CRITICAL[start:start + 3]):
            if col.button(f"🚨 {tid} {SHORT.get(tid, BY_ID[tid].title)}", key=f"go-{tid}", width="stretch"):
                send_command(DB, "launch_attack", tid)
                st.toast(f"{tid} {BY_ID[tid].title} launched")
    pick = st.selectbox("Any test case", [tc.id for tc in CATALOG], format_func=lambda i: f"{i} {BY_ID[i].title}",
                        label_visibility="collapsed")
    if st.button(f"Launch {pick}"):
        send_command(DB, "launch_attack", pick)
        st.toast(f"{pick} launched")
with c2:
    st.markdown("**Fixes switched on** (apply to attacks launched afterwards)")
    current = json.loads(state.get("fixes", "[]"))
    fixes = st.multiselect("Fixes", [tc.id for tc in CATALOG], default=current, label_visibility="collapsed",
                           format_func=lambda i: f"{i} {BY_ID[i].title}")
    if sorted(fixes) != sorted(current):
        send_command(DB, "set_fixes", json.dumps(fixes))
    st.markdown("**Fast-forward the clock** (for attacks that take hours or days)")
    f = st.columns(3)
    for col, (label, minutes) in zip(f, [("+1 hour", 60), ("+1 day", 1440), ("+3 days", 4320)]):
        if col.button(f"⏩ {label}", width="stretch"):
            send_command(DB, "fast_forward", str(minutes))
    auto = st.toggle("AI explains Critical alerts automatically (uses model credits)",
                     value=state.get("auto_explain") == "1")
    if auto != (state.get("auto_explain") == "1"):
        send_command(DB, "set_auto_explain", "1" if auto else "0")


# ------------------------------------------------------------- live section
@st.fragment(run_every="2s")
def live() -> None:
    con = connect(DB)
    s = dict(con.execute("SELECT key, value FROM state").fetchall())
    n_events = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    alerts = pd.read_sql("SELECT * FROM alerts ORDER BY sim_t DESC, created DESC", con)
    recent = pd.read_sql("SELECT seq, t, user_id, event, country, asn, device_id, amount, payee_id, reason "
                         "FROM events ORDER BY seq DESC LIMIT 14", con)
    con.close()

    m = st.columns(5)
    m[0].metric("Simulated clock", s.get("clock", "-"))
    m[1].metric("Events streamed", f"{n_events:,}")
    m[2].metric("Critical alerts", int((alerts["criticality"] == "Critical").sum()))
    m[3].metric("Blocked by fixes", int(alerts["blocked"].sum()))
    m[4].metric("Engine", "live" if time.time() - float(s.get("heartbeat", 0)) < 5 else "stopped")

    left, right = st.columns([2, 3])
    with left:
        st.markdown("**Live activity**")
        recent["time"] = recent["t"].map(sim_clock)
        st.dataframe(recent[["time", "user_id", "event", "country", "asn", "amount", "reason"]],
                     hide_index=True, width="stretch", height=520)
    with right:
        st.markdown(f"**Alerts** ({len(alerts)})")
        rules = alerts[alerts["rule"] != "ML"]
        show_ml = st.checkbox("Show machine-learning alerts", value=False, key="show-ml")
        feed = alerts if show_ml else rules
        if feed.empty:
            st.info("No alerts yet. Launch an attack above.")
        for a in feed.head(12).to_dict("records"):
            tc = BY_ID.get(a["rule"])
            colour = COLOURS.get(a["criticality"], "#999")
            status = "🛡️ BLOCKED by fix" if a["blocked"] else "⚠️ NOT BLOCKED"
            with st.container(border=True):
                st.markdown(f"<span style='background:{colour};color:black;padding:2px 8px;border-radius:4px'>"
                            f"{a['criticality']} {a['score']}</span> **{a['rule']} {a['title']}** · {status}"
                            f"{' · 🤖 ML' if a['ml'] else ''} · {sim_clock(a['sim_t'])}",
                            unsafe_allow_html=True)
                st.caption(a["message"])
                if tc:
                    st.caption(f"MITRE {tc.mitre} · OWASP {tc.owasp} · ISO 27001 {tc.iso27001} · Fix: {tc.fix}")
                if a["prism_session"]:
                    st.caption(f"PRISM session `{a['prism_session']}`")
                if a["explanation"]:
                    st.info(a["explanation"])
                elif tc and st.button("Explain with AI", key=f"ex-{a['id']}"):
                    send_command(DB, "explain", a["id"])
                    st.toast("Claude is writing the explanation...")


live()
