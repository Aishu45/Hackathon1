"""Risk score, criticality and business impact for each test case, before and after fixes.

    Inherent risk  = likelihood x impact                    (from the catalogue)
    Outcome        = prevented  if the fix blocked the attack
                     detected   if it got through but a rule or the ML model flagged it
                     missed     otherwise
    Residual risk  = likelihood' x impact'
                     prevented -> likelihood drops by 3 (min 1)
                     detected  -> impact drops by 2 (min 1): caught before the money is lost
    Annual loss    = incidents per year (from likelihood) x loss per incident x exposure
                     exposure: missed 100%, detected 30%, prevented 5%

Incidents per year are per 100,000 customers and scale with the customer count.
All of these are assumptions, shown with every result so they can be challenged.
"""
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from ato.catalog import CATALOG, criticality

INCIDENTS_PER_YEAR = {1: 0.5, 2: 2, 3: 6, 4: 12, 5: 24}  # per 100,000 customers
EXPOSURE = {"missed": 1.0, "detected": 0.3, "prevented": 0.05}


@dataclass
class Assumptions:
    customers: int = 100_000
    incidents_per_year: dict | None = None
    exposure: dict | None = None

    def freq(self, likelihood: int) -> float:
        table = self.incidents_per_year or INCIDENTS_PER_YEAR
        return table[likelihood] * self.customers / 100_000

    def expo(self, outcome: str) -> float:
        return (self.exposure or EXPOSURE)[outcome]


def score(succeeded: dict[str, bool], rule_hits: dict[str, list[str]], ml_hits: dict[str, float],
          fixes: set[str], a: Assumptions | None = None) -> pd.DataFrame:
    """One row per test case, with the trace of how each number was reached."""
    a = a or Assumptions()
    rows = []
    for tc in CATALOG:
        by_rule = bool(rule_hits.get(tc.id))
        by_ml = tc.id in ml_hits
        outcome = "prevented" if not succeeded[tc.id] else ("detected" if by_rule or by_ml else "missed")
        L, I = tc.likelihood, tc.impact
        rL = max(1, L - 3) if outcome == "prevented" else L
        rI = max(1, I - 2) if (by_rule or by_ml) else I
        inherent_loss = a.freq(L) * tc.loss_per_incident
        residual_loss = a.freq(rL) * tc.loss_per_incident * a.expo(outcome)
        trace = [
            f"Inherent risk = likelihood {L} x impact {I} = {L * I} ({criticality(L * I)})",
            f"Attack {'succeeded' if succeeded[tc.id] else 'was blocked'}"
            f"{' (fix on)' if tc.id in fixes else ''}; rule {'fired' if by_rule else 'silent'}; "
            f"ML {'flagged' if by_ml else 'silent'} -> outcome {outcome}",
            f"Residual risk = {rL} x {rI} = {rL * rI} ({criticality(rL * rI)})",
            f"Inherent annual loss = {a.freq(L):g} incidents x {tc.loss_per_incident:,} = {inherent_loss:,.0f}",
            f"Residual annual loss = {a.freq(rL):g} incidents x {tc.loss_per_incident:,} x "
            f"{a.expo(outcome):.0%} exposure = {residual_loss:,.0f}",
        ]
        rows.append({
            "id": tc.id, "area": tc.area, "title": tc.title, "mitre": tc.mitre, "owasp": tc.owasp,
            "iso27001": tc.iso27001, "fix": tc.fix, "fix_on": tc.id in fixes,
            "likelihood": L, "impact": I, "inherent_score": L * I, "inherent_criticality": criticality(L * I),
            "attack_succeeded": succeeded[tc.id], "detected_by_rule": by_rule, "detected_by_ml": by_ml,
            "ml_anomaly_score": round(ml_hits.get(tc.id, 0.0), 3), "outcome": outcome,
            "residual_likelihood": rL, "residual_impact": rI, "residual_score": rL * rI,
            "residual_criticality": criticality(rL * rI),
            "inherent_annual_loss": round(inherent_loss), "residual_annual_loss": round(residual_loss),
            "business_impact": tc.business_impact, "evidence": " | ".join(rule_hits.get(tc.id, [])[:3]),
            "trace": trace,
        })
    return pd.DataFrame(rows)


def summary(report: pd.DataFrame) -> dict:
    return {
        "tests": len(report),
        "prevented": int((report["outcome"] == "prevented").sum()),
        "detected": int((report["outcome"] == "detected").sum()),
        "missed": int((report["outcome"] == "missed").sum()),
        "critical_before": int((report["inherent_criticality"] == "Critical").sum()),
        "critical_after": int((report["residual_criticality"] == "Critical").sum()),
        "high_after": int((report["residual_criticality"] == "High").sum()),
        "inherent_annual_loss": int(report["inherent_annual_loss"].sum()),
        "residual_annual_loss": int(report["residual_annual_loss"].sum()),
    }
