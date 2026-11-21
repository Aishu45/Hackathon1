"""Detection rules: one per test case, reading only the activity data.

Every rule returns Hits with the rows that triggered it, so each alert can be
traced back to the exact events. Rules never read the `test_case` column.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import pandas as pd

from ato.world import RISKY_ASNS

SENSITIVE = {"payment", "payment_held", "payee_added", "contact_change", "limit_change"}
INJECTION_RE = re.compile(r"ignore (?:all |previous |your )?(?:instructions|rules)|approve this|"
                          r"system prompt|you are now|disregard", re.IGNORECASE)
ACTION_RE = re.compile(r"\b(unfreeze|send|transfer|approve|release|move)\b", re.IGNORECASE)


@dataclass
class Hit:
    rule: str  # the test case it detects
    message: str
    rows: list[int] = field(default_factory=list)


def _session_start(df: pd.DataFrame) -> pd.Series:
    return df.dropna(subset=["session_id"]).groupby("session_id")["t"].min()


WARMUP_MINUTES = 2 * 1440  # first 2 days build each customer's device and network profile


def _first_seen(df: pd.DataFrame, col: str, known: set[tuple] | None = None) -> pd.Series:
    """For each row, whether this user is using this value of `col` for the first
    time. `known` holds the (user, value) pairs the bank already has on record,
    such as registered devices; nothing is flagged during the warm-up either."""
    seen: set[tuple] = set(known or ())
    out = []
    for t, user, value in zip(df["t"], df["user_id"], df[col]):
        present = value is not None and value == value
        key = (user, value)
        out.append(present and key not in seen and t >= WARMUP_MINUTES)
        if present:
            seen.add(key)
    return pd.Series(out, index=df.index)


def detect(df: pd.DataFrame, known_users: set[str], registry: dict | None = None) -> list[Hit]:
    """registry: {"devices": {(user, device)}, "asns": {(user, asn)}} the bank holds on record."""
    registry = registry or {}
    hits: list[Hit] = []
    add = lambda rule, msg, rows: hits.append(Hit(rule, msg, [int(r) for r in rows]))  # noqa: E731
    fails = df[df["event"] == "login_fail"]

    # ATO-01 credential stuffing: one IP failing on 20+ accounts in 10 minutes
    f = fails.assign(win=(fails["t"] // 10))
    for (ip, _), g in f.groupby(["ip", "win"]):
        if g["user_id"].nunique() >= 20:
            add("ATO-01", f"IP {ip}: failed logins on {g['user_id'].nunique()} accounts in 10 min", g.index)

    # ATO-02 password spraying: one network failing on 50+ accounts in a day, few tries each
    f = fails.assign(day=(fails["t"] // 1440))
    for (asn, _), g in f.groupby(["asn", "day"]):
        per_user = g.groupby("user_id").size()
        if len(per_user) >= 50 and per_user.max() <= 3:
            add("ATO-02", f"Network {asn}: 1-3 failures on each of {len(per_user)} accounts in a day", g.index)

    # ATO-03 enumeration: 30+ attempts on usernames that do not exist, from one IP in an hour
    unknown = fails[~fails["user_id"].isin(known_users)]
    u = unknown.assign(hour=(unknown["t"] // 60))
    for (ip, _), g in u.groupby(["ip", "hour"]):
        if len(g) >= 30:
            add("ATO-03", f"IP {ip}: {len(g)} attempts on non-existent usernames in an hour", g.index)

    # ATO-04 impossible travel: logins or attempts from two countries within 60 minutes
    logins = df[df["event"].isin(["login_ok", "stepup_required"]) & df["country"].notna()]
    for user, g in logins.groupby("user_id"):
        g = g.sort_values("t")
        prev = g.shift()
        jump = g[(g["country"] != prev["country"]) & ((g["t"] - prev["t"]) <= 60)]
        for i in jump.index:
            j = prev.loc[i]
            earlier = g.index[g.index.get_loc(i) - 1]
            add("ATO-04", f"{user}: {j['country']} then {g.loc[i, 'country']} within "
                          f"{g.loc[i, 't'] - j['t']:.0f} min", [earlier, i])

    # ATO-05 new device on a new network, then a sensitive action within 30 minutes
    lo = df[df["event"] == "login_ok"]
    new_dev = _first_seen(df, "device_id", registry.get("devices"))
    new_asn = _first_seen(df, "asn", registry.get("asns"))
    sens = df[df["event"].isin(SENSITIVE | {"stepup_required"})]
    for i, row in lo.iterrows():
        if new_dev[i] and (new_asn[i] or row["asn"] in RISKY_ASNS):
            later = sens[(sens["session_id"] == row["session_id"]) & (sens["t"] - row["t"] <= 30)]
            if len(later):
                add("ATO-05", f"{row['user_id']}: new device on {row['asn']}, then "
                              f"{later.iloc[0]['event']} within 30 min", [i, *later.index])

    sessions = df.dropna(subset=["session_id"]).groupby("session_id")

    for sid, g in sessions:
        ev = g["event"]
        # ATO-06 MFA fatigue: 5+ prompts in a session, or a failed number match
        prompts = g[ev == "mfa_prompt"]
        if len(prompts) >= 5 and prompts["t"].max() - prompts["t"].min() <= 10:
            add("ATO-06", f"{sid}: {len(prompts)} MFA prompts in "
                          f"{prompts['t'].max() - prompts['t'].min():.0f} min", prompts.index)
        elif (g["reason"] == "number_match_failed").any():
            add("ATO-06", f"{sid}: MFA number match failed", g.index[g["reason"] == "number_match_failed"])
        # ATO-07 one-time code brute force
        otp = g[ev == "otp_fail"]
        if len(otp) >= 5:
            add("ATO-07", f"{sid}: {len(otp)} wrong one-time codes", otp.index)
        # ATO-08 sensitive action in a session with no MFA or step-up
        if (ev == "login_ok").any() and not ev.isin(["mfa_ok", "stepup_ok"]).any():
            s = g[ev.isin(SENSITIVE)]
            if len(s):
                add("ATO-08", f"{sid}: {s.iloc[0]['event']} without MFA", s.index)
        # ATO-10 one session used from more than one device or network
        net = g.dropna(subset=["device_id"])
        if net["device_id"].nunique() > 1 or net["asn"].nunique() > 1:
            add("ATO-10", f"{sid}: used from {net['device_id'].nunique()} devices / "
                          f"{net['asn'].nunique()} networks", net.index)
        # ATO-11 contact change without step-up (or a failed step-up for one)
        for i in g.index[ev == "contact_change"]:
            if not ((ev == "stepup_ok") & (g["t"] <= g.loc[i, "t"])).any():
                add("ATO-11", f"{sid}: {g.loc[i, 'text']} changed without step-up", [i])
        bad = g[(ev == "stepup_required") & (g["reason"] == "contact_change")]
        if len(bad) and (ev == "stepup_fail").any():
            add("ATO-11", f"{sid}: failed step-up for a contact change", [*bad.index])

    # ATO-09 SIM change, then a new-device login or a large payment within 72 hours
    for i, sim in df[df["event"] == "sim_change"].iterrows():
        win = df[(df["user_id"] == sim["user_id"]) & (df["t"] > sim["t"]) & (df["t"] <= sim["t"] + 72 * 60)]
        risky = win[((win["event"] == "login_ok") & new_dev.reindex(win.index).fillna(False))
                    | (win["event"].isin(["payment", "payment_held"])
                       & (win["amount"] >= 0.5 * win["balance"]))]
        if len(risky):
            add("ATO-09", f"{sim['user_id']}: SIM changed, then {risky.iloc[0]['event']} within 72h",
                [i, *risky.index])

    # ATO-12 reset token reused or used long after it was issued
    resets = df[df["event"] == "password_reset_done"]
    for tok, g in resets.groupby("token_id"):
        if len(g) > 1 or (g["token_age_min"] > 60).any():
            add("ATO-12", f"Reset token {tok}: used {len(g)}x, oldest {g['token_age_min'].max():.0f} min", g.index)

    # ATO-13 change with no notification to the owner, or alerts switched off
    notes = df[df["event"] == "notification"]
    for i, row in df[df["event"].isin(["contact_change", "device_registered"])].iterrows():
        n = notes[(notes["user_id"] == row["user_id"]) & (notes["t"] - row["t"]).between(0, 5)]
        if n.empty:
            add("ATO-13", f"{row['user_id']}: {row['event']} with no notification", [i])
    for i in df.index[(df["event"] == "alerts_disabled") | (df["reason"] == "alert_settings")]:
        add("ATO-13", f"{df.loc[i, 'user_id']}: attempt to change alert settings", [i])

    # ATO-14 new payee, then 80%+ of the balance to it within an hour
    pays = df[df["event"].isin(["payment", "payment_held"])]
    for i, p in df[df["event"] == "payee_added"].iterrows():
        big = pays[(pays["payee_id"] == p["payee_id"]) & (pays["user_id"] == p["user_id"])
                   & (pays["t"] - p["t"]).between(0, 60) & (pays["amount"] >= 0.8 * pays["balance"])]
        if len(big):
            add("ATO-14", f"{p['user_id']}: new payee, then {big.iloc[0]['amount']:,.0f} "
                          f"({big.iloc[0]['amount'] / big.iloc[0]['balance']:.0%} of balance)", [i, *big.index])

    # ATO-15 limit raised, then a payment above the old limit within 24 hours
    for i, lc in df[df["event"] == "limit_change"].iterrows():
        over = pays[(pays["user_id"] == lc["user_id"]) & (pays["t"] - lc["t"]).between(0, 1440)
                    & (pays["amount"] > lc["balance"])]
        if len(over):
            add("ATO-15", f"{lc['user_id']}: limit raised, then {over.iloc[0]['amount']:,.0f} "
                          f"above the old limit of {lc['balance']:,.0f}", [i, *over.index])

    # ATO-16 new authenticator, then a large payment from it within 24 hours
    for i, reg in df[df["event"] == "device_registered"].iterrows():
        big = pays[(pays["user_id"] == reg["user_id"]) & (pays["device_id"] == reg["device_id"])
                   & (pays["t"] - reg["t"]).between(0, 1440) & (pays["amount"] >= 0.5 * pays["balance"])]
        if len(big):
            add("ATO-16", f"{reg['user_id']}: new authenticator, then a large payment from it", [i, *big.index])

    # ATO-17 API request for another customer's account
    other = df[df["event"].isin(["api_read", "api_denied"]) & (df["target_user"] != df["user_id"])]
    for sid, g in other.groupby("session_id"):
        add("ATO-17", f"{sid}: requested {g['target_user'].nunique()} other customers' accounts", g.index)

    # ATO-18 an older session still active after a password change
    starts = _session_start(df)
    for i, pc in df[df["event"] == "password_change"].iterrows():
        later = df[(df["user_id"] == pc["user_id"]) & (df["t"] > pc["t"]) & df["session_id"].notna()
                   & (df["session_id"] != pc["session_id"])]
        older = later[later["session_id"].map(starts) < pc["t"]]
        if len(older):
            add("ATO-18", f"{pc['user_id']}: old session used after a password change", [i, *older.index])

    # ATO-19 two payments within a second that together exceed the balance
    for user, g in pays.sort_values("t").groupby("user_id"):
        both = df[(df["user_id"] == user) & df["event"].isin(["payment", "payment_rejected"])].sort_values("t")
        prev = both.shift()
        close = both[(both["t"] - prev["t"] <= 0.02) & (both["amount"] + prev["amount"] > prev["balance"])]
        for i in close.index:
            add("ATO-19", f"{user}: two payments within a second exceeding the balance",
                [both.index[both.index.get_loc(i) - 1], i])

    # AI-01 instruction-like text in payment data
    txt = df[df["text"].fillna("").str.contains(INJECTION_RE) | (df["event"] == "text_flagged")]
    for i in txt.index:
        add("AI-01", f"{df.loc[i, 'user_id']}: instruction-like text in {df.loc[i, 'event']}", [i])

    # AI-02 request for the AI agent to take an action
    for i, r in df[df["event"] == "agent_request"].iterrows():
        if ACTION_RE.search(r["text"] or ""):
            add("AI-02", f"Action requested from the AI agent: '{r['text']}'", [i])

    # AI-03 small test payments to a payee, then a large jump
    for i, p in df[df["event"] == "payee_added"].iterrows():
        g = pays[(pays["payee_id"] == p["payee_id"]) & (pays["user_id"] == p["user_id"])
                 & (pays["t"] - p["t"]).between(0, 7 * 1440)].sort_values("t")
        small = g[g["amount"] <= 0.05 * g["balance"]]
        big = g[g["amount"] >= 0.5 * g["balance"]]
        if len(small) >= 2 and len(big) and big["t"].min() > small["t"].min():
            add("AI-03", f"{p['user_id']}: {len(small)} small test payments, then "
                         f"{big.iloc[0]['amount']:,.0f}", [i, *small.index, *big.index])

    # AI-04 AI agent asked about a customer outside the case
    for i in df.index[(df["event"] == "agent_query") & (df["target_user"] != df["user_id"])]:
        add("AI-04", f"AI agent asked about {df.loc[i, 'target_user']}, outside the case", [i])

    # AI-05 alert flood: one source sending 20+ alerts in an hour
    al = df[df["event"] == "alert"]
    al = al.assign(hour=(al["t"] // 60))
    for (src, _), g in al.groupby(["text", "hour"]):
        if len(g) >= 20:
            add("AI-05", f"Alert source {src}: {len(g)} alerts in an hour", g.index)

    # DR-01 gap in the event sequence numbers
    gaps = df.index[df["seq"].diff() > 1]
    for i in gaps:
        lo_, hi_ = max(0, i - 5), min(len(df) - 1, i + 5)
        add("DR-01", f"{int(df.loc[i, 'seq'] - df.loc[i - 1, 'seq'] - 1)} event(s) missing before "
                     f"sequence {int(df.loc[i, 'seq'])}", list(range(lo_, hi_ + 1)))

    # DR-02 confirmed takeover not frozen within 15 minutes
    frozen = df[df["event"] == "account_frozen"]
    for i, c in df[df["event"] == "attack_confirmed"].iterrows():
        f_ = frozen[(frozen["user_id"] == c["user_id"]) & (frozen["t"] >= c["t"])]
        delay = (f_["t"].min() - c["t"]) if len(f_) else None
        if delay is None or delay > 15:
            add("DR-02", f"{c['user_id']}: account frozen {'never' if delay is None else f'{delay:.0f} min'} "
                         "after the takeover was confirmed", [i, *f_.index[:1]])
    return hits
