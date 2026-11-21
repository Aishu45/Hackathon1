"""Run every account-takeover test case: simulate, detect (rules + ML), score.

    report, details = run_tests(fixes={"ATO-06", "ATO-09"})
"""
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from ato.catalog import CATALOG
from ato.detection import Hit, detect
from ato.ml import score_sessions
from ato.scoring import Assumptions, score, summary
from ato.world import simulate

ALL_FIXES = {tc.id for tc in CATALOG}


@dataclass
class RunResult:
    report: pd.DataFrame
    summary: dict
    events: pd.DataFrame
    hits: list[Hit]
    sessions: pd.DataFrame
    false_positives: dict[str, int]  # rule -> hits on normal activity only


def run_tests(fixes: set[str] | None = None, seed: int = 7,
              assumptions: Assumptions | None = None) -> RunResult:
    fixes = set(fixes or ())
    sim = simulate(fixes, seed=seed)
    df = sim.events
    hits = detect(df, sim.known_users, sim.registry)
    sessions = score_sessions(df, sim.registry)

    # Labels are used only here, to grade the detectors against what really happened.
    labels = df["test_case"]
    rule_hits: dict[str, list[str]] = {}
    false_positives: dict[str, int] = {}
    for h in hits:
        attacks = set(labels.loc[h.rows].dropna())
        if h.rule in attacks:
            rule_hits.setdefault(h.rule, []).append(h.message)
        elif not attacks:
            false_positives[h.rule] = false_positives.get(h.rule, 0) + 1

    session_tc = (df.dropna(subset=["session_id"]).groupby("session_id")["test_case"]
                  .agg(lambda x: x.dropna().iloc[0] if x.notna().any() else None))
    sessions["test_case"] = session_tc.reindex(sessions.index)
    flagged = sessions[sessions["flagged"] & sessions["test_case"].notna()]
    ml_hits = flagged.groupby("test_case")["anomaly_score"].max().to_dict()
    false_positives["ML model"] = int((sessions["flagged"] & sessions["test_case"].isna()).sum())

    report = score(sim.succeeded, rule_hits, ml_hits, fixes, assumptions)
    return RunResult(report, summary(report), df, hits, sessions, false_positives)
