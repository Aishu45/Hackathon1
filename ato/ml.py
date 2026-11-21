"""Machine-learning anomaly detection on sessions (unsupervised).

An Isolation Forest learns what normal sessions look like from behaviour
features alone (no labels) and flags sessions that look unusual. It is an
independent second opinion next to the rules: it can catch attack variants
no rule was written for, and the rules explain what the model cannot.
"""
from __future__ import annotations

import pandas as pd
from sklearn.ensemble import IsolationForest

from ato.detection import _first_seen
from ato.world import RISKY_ASNS

FEATURES = ["mfa_prompts", "otp_fails", "no_mfa", "new_device", "new_network", "risky_network",
            "devices_used", "max_payment_share", "payees_added", "contact_changes",
            "other_customers_read", "minutes_to_first_payment", "blocked_actions"]


def session_features(df: pd.DataFrame, registry: dict | None = None) -> pd.DataFrame:
    registry = registry or {}
    d = df.dropna(subset=["session_id"]).copy()
    d["new_device"] = _first_seen(df, "device_id", registry.get("devices")).reindex(d.index)
    d["new_network"] = _first_seen(df, "asn", registry.get("asns")).reindex(d.index)
    d["share"] = (d["amount"] / d["balance"]).where(d["event"].isin(["payment", "payment_held"]))
    g = d.groupby("session_id")
    start = g["t"].min()
    first_pay = d[d["event"] == "payment"].groupby("session_id")["t"].min()
    feats = pd.DataFrame({
        "user_id": g["user_id"].first(),
        "mfa_prompts": g["event"].apply(lambda e: (e == "mfa_prompt").sum()),
        "otp_fails": g["event"].apply(lambda e: (e == "otp_fail").sum()),
        "no_mfa": g["event"].apply(lambda e: int(not e.isin(["mfa_ok", "stepup_ok"]).any())),
        "new_device": g["new_device"].max().astype(int),
        "new_network": g["new_network"].max().astype(int),
        "risky_network": g["asn"].apply(lambda a: int(a.isin(RISKY_ASNS).any())),
        "devices_used": g["device_id"].nunique(),
        "max_payment_share": g["share"].max().fillna(0).clip(upper=2),
        "payees_added": g["event"].apply(lambda e: (e == "payee_added").sum()),
        "contact_changes": g["event"].apply(lambda e: (e == "contact_change").sum()),
        "other_customers_read": d.assign(o=(d["event"].isin(["api_read", "api_denied"])
                                            & (d["target_user"] != d["user_id"]))).groupby("session_id")["o"].sum(),
        "minutes_to_first_payment": (first_pay - start).reindex(start.index).fillna(999).clip(upper=999),
        "blocked_actions": g["success"].apply(lambda s: int((s == False).sum())),  # noqa: E712
    })
    return feats


def score_sessions(df: pd.DataFrame, registry: dict | None = None,
                   contamination: float = 0.02, seed: int = 0) -> pd.DataFrame:
    """Return session features plus `anomaly_score` (higher = more unusual) and `flagged`."""
    feats = session_features(df, registry)
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=seed)
    model.fit(feats[FEATURES])
    feats["anomaly_score"] = -model.score_samples(feats[FEATURES])
    feats["flagged"] = model.predict(feats[FEATURES]) == -1
    return feats
