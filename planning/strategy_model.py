"""Strategy decision model: which fraud-alert strategy costs least per month?

Business question
    For our monthly volume of payments, which way of handling fraud alerts
    gives the lowest total cost (analyst staff + fraud losses + customers lost
    after a genuine payment is held + AI cost), and how many analysts does it
    need?

Strategies compared
    manual       analysts review every alert
    threshold    alerts with a low anomaly score (and no high AML hit) are
                 released automatically; analysts review the rest
    ai_assisted  the AI investigator looks at every alert; what it approves is
                 released, what it holds or escalates goes to an analyst

Inputs are of two kinds, and every one says where it comes from:
    measured    computed from our transactions and the AI's evaluation
    assumption  a business estimate the user can change (ask your mentor)

Every calculation is recorded as a Step (formula, inputs, result), so each
number on the dashboard can be traced back to its inputs.
"""
from __future__ import annotations

import copy
import json
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path

import pandas as pd

from config import settings

STRATEGIES = {
    "manual": "Manual: analysts review every alert",
    "threshold": "Threshold: auto-release low anomaly scores, analysts review the rest",
    "ai_assisted": "AI-assisted: AI clears false alarms, analysts review the rest",
}


@dataclass
class Input:
    key: str
    label: str
    value: float | None
    unit: str
    kind: str  # "financial" or "non-financial"
    source: str  # "measured" or "assumption"
    note: str = ""


def default_inputs() -> dict[str, Input]:
    """Business assumptions. Measured inputs are added by measure()."""
    items = [
        Input("monthly_transactions", "Payments per month", 1_000_000, "payments", "non-financial",
              "assumption", "Company volume; the sample data is scaled to this."),
        Input("analyst_cost_per_hour", "Analyst cost per hour", 45, "currency", "financial",
              "assumption", "Salary plus overheads."),
        Input("analyst_hours_per_month", "Productive hours per analyst per month", 140, "hours",
              "non-financial", "assumption"),
        Input("minutes_per_review", "Minutes for an analyst to review one alert", 15, "minutes",
              "non-financial", "assumption"),
        Input("analyst_catch_rate", "Share of fraud an analyst catches when reviewing", 0.95,
              "share", "non-financial", "assumption"),
        Input("current_analysts", "Analysts in the team today", 10, "people", "non-financial",
              "assumption"),
        Input("avg_fraud_loss", "Average loss per missed fraud", 2_500, "currency", "financial",
              "assumption", "The synthetic amounts are unrealistically large, so this is set by hand."),
        Input("customer_lifetime_value", "Value of a customer over their lifetime", 600, "currency",
              "financial", "assumption"),
        Input("churn_after_hold", "Share of genuine customers who leave after a payment is held",
              0.03, "share", "non-financial", "assumption"),
        Input("ai_cost_per_case", "AI cost per investigation", 0.40, "currency", "financial",
              "assumption", "Model calls per case; check your Nicrron or Anthropic bill."),
        Input("anomaly_threshold", "Anomaly score below which alerts are auto-released", 40,
              "score", "non-financial", "assumption", "Threshold strategy only."),
    ]
    return {i.key: i for i in items}


# ---------------------------------------------------------------- measuring


def measure(transactions: pd.DataFrame, evaluation: list[dict] | None = None,
            threshold: float = 40) -> dict[str, Input]:
    """Measure rates from the data. Labels are used here, and only here, to
    score how strategies would have performed; the agent never sees them."""
    from agents.compliance_agent import check
    from core.data import build_alerts
    from core.tools import ToolBox
    from detection.anomaly_detection import score_transaction

    alerts = build_alerts(transactions)
    rows = []
    for txn_id, is_fraud in alerts[["txn_id", "isFraud"]].itertuples(index=False):
        box = ToolBox(transactions, txn_id)
        score = score_transaction(box.txn, box.past).score
        high_aml = any(h.severity == "high" for h in check(box.txn, box.past))
        rows.append({"fraud": int(is_fraud), "score": score, "high_aml": high_aml})
    a = pd.DataFrame(rows)
    fraud, genuine = a[a["fraud"] == 1], a[a["fraud"] == 0]

    def reviewed(df: pd.DataFrame) -> float:
        return float(((df["score"] >= threshold) | df["high_aml"]).mean()) if len(df) else float("nan")

    m = {
        "alert_rate": Input("alert_rate", "Share of payments flagged as alerts",
                            len(alerts) / len(transactions), "share", "non-financial", "measured",
                            f"{len(alerts)} alerts in {len(transactions):,} payments."),
        "fraud_share": Input("fraud_share", "Share of alerts that are real fraud",
                             float(a["fraud"].mean()), "share", "non-financial", "measured",
                             f"{len(fraud)} fraud and {len(genuine)} genuine alerts."),
        "threshold_fraud_reviewed": Input(
            "threshold_fraud_reviewed", "Threshold: share of fraud alerts sent to an analyst",
            reviewed(fraud), "share", "non-financial", "measured",
            f"Score >= {threshold:g} or a high AML hit; {len(fraud)} fraud alerts."),
        "threshold_genuine_reviewed": Input(
            "threshold_genuine_reviewed", "Threshold: share of genuine alerts sent to an analyst",
            reviewed(genuine), "share", "non-financial", "measured",
            f"{len(genuine)} genuine alerts."),
        "sample_fraud_alerts": Input("sample_fraud_alerts", "Fraud alerts in the sample",
                                     len(fraud), "alerts", "non-financial", "measured"),
    }

    # AI performance: from the evaluation run if there is one, else assumptions.
    ev = [r for r in (evaluation or []) if r.get("decision")]
    ev_fraud = [r for r in ev if r["is_fraud"]]
    ev_genuine = [r for r in ev if not r["is_fraud"]]
    if ev_fraud:
        catch = sum(r["decision"] in ("hold", "escalate") for r in ev_fraud) / len(ev_fraud)
        m["ai_fraud_flagged"] = Input("ai_fraud_flagged", "AI: share of fraud it holds or escalates",
                                      catch, "share", "non-financial", "measured",
                                      f"From {len(ev_fraud)} evaluated fraud case(s).")
    else:
        m["ai_fraud_flagged"] = Input("ai_fraud_flagged", "AI: share of fraud it holds or escalates",
                                      0.95, "share", "non-financial", "assumption",
                                      "No evaluated fraud cases yet; run scripts/evaluate.py.")
    if ev_genuine:
        clear = sum(r["decision"] == "approve" for r in ev_genuine) / len(ev_genuine)
        m["ai_genuine_cleared"] = Input("ai_genuine_cleared", "AI: share of false alarms it clears",
                                        clear, "share", "non-financial", "measured",
                                        f"From {len(ev_genuine)} evaluated genuine case(s).")
    else:
        m["ai_genuine_cleared"] = Input("ai_genuine_cleared", "AI: share of false alarms it clears",
                                        0.70, "share", "non-financial", "assumption",
                                        "No evaluated genuine cases yet; run scripts/evaluate.py.")
    m["ai_sample_size"] = Input("ai_sample_size", "Cases the AI was evaluated on", len(ev), "cases",
                                "non-financial", "measured")
    return m


def load_evaluation(path: Path | None = None) -> list[dict]:
    path = path or settings.ROOT / "results" / "latest.json"
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return []


# --------------------------------------------------------------- the model


@dataclass
class Step:
    name: str
    formula: str
    inputs: dict
    value: float
    unit: str


@dataclass
class StrategyResult:
    strategy: str
    label: str
    steps: list[Step] = field(default_factory=list)

    def value(self, name: str) -> float:
        return next(s.value for s in self.steps if s.name == name)

    def to_dict(self) -> dict:
        return {"strategy": self.strategy, "label": self.label,
                "steps": [asdict(s) for s in self.steps]}


def _v(inputs: dict[str, Input], key: str) -> float:
    value = inputs[key].value
    return float("nan") if value is None else float(value)


def _safe_ceil_div(a: float, b: float) -> float:
    """Round-up division that returns NaN instead of crashing; guardrails report the cause."""
    if not b or b != b or a != a or b < 0:
        return float("nan")
    return float(math.ceil(a / b))


def run_strategy(strategy: str, inputs: dict[str, Input]) -> StrategyResult:
    r = StrategyResult(strategy, STRATEGIES[strategy])

    def step(name: str, formula: str, value: float, unit: str, **used: float) -> float:
        r.steps.append(Step(name, formula, {k: round(v, 4) for k, v in used.items()}, value, unit))
        return value

    v = lambda key: _v(inputs, key)  # noqa: E731

    if strategy == "manual":
        f_h, g_h, ai_cases = 1.0, 1.0, 0.0
    elif strategy == "threshold":
        f_h, g_h, ai_cases = v("threshold_fraud_reviewed"), v("threshold_genuine_reviewed"), 0.0
    else:
        f_h, g_h = v("ai_fraud_flagged"), 1 - v("ai_genuine_cleared")
        ai_cases = 1.0

    alerts = step("alerts", "payments per month × alert rate",
                  v("monthly_transactions") * v("alert_rate"), "alerts",
                  payments=v("monthly_transactions"), alert_rate=v("alert_rate"))
    fraud = step("fraud_alerts", "alerts × fraud share", alerts * v("fraud_share"), "alerts",
                 alerts=alerts, fraud_share=v("fraud_share"))
    genuine = step("genuine_alerts", "alerts − fraud alerts", alerts - fraud, "alerts",
                   alerts=alerts, fraud_alerts=fraud)
    reviews = step("analyst_reviews", "fraud alerts × share reviewed + genuine alerts × share reviewed",
                   fraud * f_h + genuine * g_h, "reviews", fraud_alerts=fraud,
                   fraud_reviewed=f_h, genuine_alerts=genuine, genuine_reviewed=g_h)
    caught = step("fraud_caught", "fraud alerts × share reviewed × analyst catch rate",
                  fraud * f_h * v("analyst_catch_rate"), "cases", fraud_alerts=fraud,
                  fraud_reviewed=f_h, analyst_catch_rate=v("analyst_catch_rate"))
    missed = step("fraud_missed", "fraud alerts − fraud caught", fraud - caught, "cases",
                  fraud_alerts=fraud, fraud_caught=caught)
    step("catch_rate", "fraud caught ÷ fraud alerts", caught / fraud if fraud > 0 else float("nan"), "share",
         fraud_caught=caught, fraud_alerts=fraud)
    held = step("genuine_held", "genuine alerts × share reviewed (held until checked)",
                genuine * g_h, "customers", genuine_alerts=genuine, genuine_reviewed=g_h)
    hours = step("analyst_hours", "analyst reviews × minutes per review ÷ 60",
                 reviews * v("minutes_per_review") / 60, "hours", analyst_reviews=reviews,
                 minutes_per_review=v("minutes_per_review"))
    needed = step("analysts_needed", "round up(analyst hours ÷ hours per analyst)",
                  _safe_ceil_div(hours, v("analyst_hours_per_month")),
                  "people", analyst_hours=hours, hours_per_analyst=v("analyst_hours_per_month"))
    staff = step("staff_cost", "analysts needed × hours per analyst × cost per hour",
                 needed * v("analyst_hours_per_month") * v("analyst_cost_per_hour"), "currency",
                 analysts_needed=needed, hours_per_analyst=v("analyst_hours_per_month"),
                 cost_per_hour=v("analyst_cost_per_hour"))
    losses = step("fraud_losses", "fraud missed × average loss", missed * v("avg_fraud_loss"),
                  "currency", fraud_missed=missed, avg_fraud_loss=v("avg_fraud_loss"))
    friction = step("lost_customer_cost", "genuine held × churn after hold × customer lifetime value",
                    held * v("churn_after_hold") * v("customer_lifetime_value"), "currency",
                    genuine_held=held, churn_after_hold=v("churn_after_hold"),
                    customer_lifetime_value=v("customer_lifetime_value"))
    ai = step("ai_cost", "alerts investigated by AI × AI cost per case",
              alerts * ai_cases * v("ai_cost_per_case"), "currency",
              ai_investigations=alerts * ai_cases, ai_cost_per_case=v("ai_cost_per_case"))
    step("total_cost", "staff + fraud losses + lost customers + AI",
         staff + losses + friction + ai, "currency", staff_cost=staff, fraud_losses=losses,
         lost_customer_cost=friction, ai_cost=ai)
    return r


# -------------------------------------------------------------- guardrails


@dataclass
class Flag:
    level: str  # "error" blocks a reliable answer; "warning" and "limitation" inform it
    message: str


def check_inputs(inputs: dict[str, Input], results: list[StrategyResult]) -> list[Flag]:
    flags: list[Flag] = []
    for i in inputs.values():
        if i.value is None or (isinstance(i.value, float) and math.isnan(i.value)):
            flags.append(Flag("error", f"Missing input: {i.label}."))
            continue
        if i.unit == "share" and not 0 <= i.value <= 1:
            flags.append(Flag("error", f"{i.label} must be between 0% and 100% (got {i.value})."))
        elif i.value < 0:
            flags.append(Flag("error", f"{i.label} cannot be negative (got {i.value})."))
    if inputs["analyst_hours_per_month"].value == 0:
        flags.append(Flag("error", "Hours per analyst cannot be zero."))
    if inputs["monthly_transactions"].value == 0:
        flags.append(Flag("error", "Payments per month cannot be zero."))
    if any(f.level == "error" for f in flags):
        return flags

    team = inputs["current_analysts"].value
    for r in results:
        if r.value("analysts_needed") > team:
            flags.append(Flag("warning", f"{r.label}: needs {r.value('analysts_needed'):.0f} analysts "
                                         f"but the team has {team:.0f}. Without hiring, a backlog builds "
                                         "and review deadlines are missed."))
    share = inputs["fraud_share"]
    if share.value > 0.2:
        flags.append(Flag("warning", f"{share.value:.0%} of alerts are fraud ({share.source}); real alert "
                                     "queues are usually 1-10% fraud. Fraud losses will dominate every "
                                     "strategy. Override the fraud share to test a realistic queue."))
    if inputs["minutes_per_review"].value < 3 or inputs["minutes_per_review"].value > 60:
        flags.append(Flag("warning", "Minutes per review looks unusual (typical 10-20)."))

    if (inputs["threshold_fraud_reviewed"].value == 1 and inputs["threshold_genuine_reviewed"].value == 0
            and inputs["threshold_fraud_reviewed"].source == "measured"):
        flags.append(Flag("limitation", "The anomaly score separates fraud from false alarms perfectly in "
                                        "this sample, so the Threshold strategy looks better than it will "
                                        "on real data. Test it with lower review rates."))
    if inputs["sample_fraud_alerts"].value < 30:
        flags.append(Flag("limitation", f"Rates are measured on only {inputs['sample_fraud_alerts'].value:.0f} "
                                        "fraud alerts; treat them as rough."))
    if inputs["ai_sample_size"].value < 30:
        src = inputs["ai_fraud_flagged"].source
        flags.append(Flag("limitation", f"AI accuracy comes from {inputs['ai_sample_size'].value:.0f} evaluated "
                                        f"case(s) ({src}); run more cases before relying on it."))
    flags.append(Flag("limitation", "Measured rates come from synthetic data with planted patterns; "
                                    "real alerts will be harder to separate."))
    flags.append(Flag("limitation", "Costs are monthly and ignore one-off set-up costs, regulatory "
                                    "fines and the value of fraud recovered after the fact."))
    return flags


# ------------------------------------------------------ scenarios, decision


def compare(inputs: dict[str, Input]) -> list[StrategyResult]:
    return [run_strategy(s, inputs) for s in STRATEGIES]


def best(results: list[StrategyResult]) -> StrategyResult:
    return min(results, key=lambda r: r.value("total_cost"))


SENSITIVE = ["analyst_cost_per_hour", "minutes_per_review", "avg_fraud_loss",
             "customer_lifetime_value", "churn_after_hold", "ai_cost_per_case",
             "ai_fraud_flagged", "ai_genuine_cleared"]


def sensitivity(inputs: dict[str, Input], change: float = 0.25) -> list[str]:
    """Inputs whose ±25% change would make a different strategy win."""
    winner = best(compare(inputs)).strategy
    flips = []
    for key in SENSITIVE:
        for factor in (1 - change, 1 + change):
            trial = copy.deepcopy(inputs)
            new = trial[key].value * factor
            trial[key].value = min(new, 1.0) if trial[key].unit == "share" else new
            other = best(compare(trial)).strategy
            if other != winner:
                flips.append(f"{inputs[key].label} {'down' if factor < 1 else 'up'} "
                             f"{change:.0%} → {STRATEGIES[other].split(':')[0]} wins")
    return flips


def explain(inputs: dict[str, Input], results: list[StrategyResult]) -> list[str]:
    """Plain-language explanation of how the numbers inform the decision."""
    win = best(results)
    base = next(r for r in results if r.strategy == "manual")
    name = win.label.split(":")[0]
    saving = base.value("total_cost") - win.value("total_cost")
    parts = {k: win.value(k) for k in ("staff_cost", "fraud_losses", "lost_customer_cost", "ai_cost")}
    biggest = max(parts, key=parts.get)
    lines = [
        f"{name} has the lowest total monthly cost: {win.value('total_cost'):,.0f} "
        f"versus {base.value('total_cost'):,.0f} for reviewing every alert by hand"
        + (f", a saving of {saving:,.0f} a month." if saving > 0 else "."),
        f"It needs {win.value('analysts_needed'):.0f} analysts and catches "
        f"{win.value('catch_rate'):.0%} of fraud alerts (manual: {base.value('catch_rate'):.0%}).",
        f"Its biggest cost is {biggest.replace('_', ' ')} ({parts[biggest]:,.0f}), so improving "
        "that input changes the answer most.",
    ]
    flips = sensitivity(inputs)
    lines.append("The choice holds if any key assumption moves by ±25%." if not flips else
                 "The choice is sensitive: " + "; ".join(flips) + ".")
    return lines


SCENARIO_DIR = settings.ROOT / "config" / "scenarios"


def load_scenarios(directory: Path | None = None) -> dict[str, dict]:
    """Each scenario is a JSON file: {"name", "description", "overrides": {input: value}}."""
    scenarios = {}
    for path in sorted(Path(directory or SCENARIO_DIR).glob("*.json")):
        data = json.loads(path.read_text())
        scenarios[path.stem] = data
    return scenarios


def compare_scenarios(transactions: pd.DataFrame, scenarios: dict[str, dict],
                      evaluation: list[dict] | None = None) -> pd.DataFrame:
    """One row per scenario × strategy: the numbers a decision-maker compares."""
    rows = []
    for key, sc in scenarios.items():
        out = build(transactions, sc.get("overrides"), evaluation)
        win = best(out["results"]).strategy if not any(f.level == "error" for f in out["flags"]) else None
        for r in out["results"]:
            rows.append({"scenario": sc.get("name", key), "strategy": r.label.split(":")[0],
                         "total_cost": r.value("total_cost"), "analysts_needed": r.value("analysts_needed"),
                         "catch_rate": r.value("catch_rate"), "customers_held": r.value("genuine_held"),
                         "best": r.strategy == win})
    return pd.DataFrame(rows)


def build(transactions: pd.DataFrame, overrides: dict[str, float] | None = None,
          evaluation: list[dict] | None = None) -> dict:
    """Everything the dashboard or a script needs, in one call."""
    inputs = default_inputs()
    for key, value in (overrides or {}).items():
        if key in inputs:
            inputs[key].value = value
    inputs.update(measure(transactions, evaluation if evaluation is not None else load_evaluation(),
                          threshold=inputs["anomaly_threshold"].value or 40))
    for key, value in (overrides or {}).items():  # measured values can be overridden too
        if key in inputs and inputs[key].source == "measured":
            inputs[key].value = value
            inputs[key].source = "assumption"
            inputs[key].note = "Overridden by the user."
    results = compare(inputs)
    flags = check_inputs(inputs, results)
    blocked = any(f.level == "error" for f in flags)
    return {"inputs": inputs, "results": results, "flags": flags,
            "explanation": [] if blocked else explain(inputs, results)}
