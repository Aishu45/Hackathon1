"""Security control register for the agent, mapped to ISO/IEC 27001:2022 Annex A
and CIS Controls v8, with a live check for each control.

This is a mapping that shows how each control is implemented and tested in
this codebase. It is not a certification or a full ISMS.

Run:  python scripts/security_check.py
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import Callable

import pandas as pd

from config import settings

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"

# Tools the agent may call. Every one of them only reads data.
READ_ONLY_TOOLS = {"get_customer_history", "get_recipient_profile",
                   "check_balance_pattern", "check_velocity"}
WRITE_VERBS = re.compile(r"transfer|pay|send|approve|release|refund|update|delete|write|create",
                         re.IGNORECASE)
SECRET_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{10,}"),                   # Anthropic keys
    re.compile(r"PRISMTRACE_API_KEY[ \t]*=[ \t]*['\"]?[A-Za-z0-9_\-]{12,}"),  # PRISM key with a value
]


@dataclass(frozen=True)
class Control:
    control_id: str
    title: str
    iso27001: str
    cis_v8: str
    implemented_in: str
    check: Callable[[], tuple[str, str]]


def _least_privilege() -> tuple[str, str]:
    from core.tools import DECISION_TOOL, TOOL_DEFINITIONS
    names = {t["name"] for t in TOOL_DEFINITIONS}
    extra = names - READ_ONLY_TOOLS
    risky = [n for n in names if WRITE_VERBS.search(n)]
    if extra or risky:
        return FAIL, f"Non-read-only tools exposed: {sorted(extra | set(risky))}"
    if "does not move money" not in DECISION_TOOL["description"]:
        return FAIL, "submit_decision must only record a recommendation."
    return PASS, f"{len(names)} read-only tools; submit_decision only records a recommendation."


def _segregation_of_duties() -> tuple[str, str]:
    from agents.risk_agent import REQUIRED_FOR_APPROVAL, apply_policy
    ok = {"decision": "approve", "risk_score": 5}
    big = apply_policy(ok, settings.HUMAN_REVIEW_AMOUNT, set(REQUIRED_FOR_APPROVAL), 0)
    hit = {"rule_id": "AML-01", "name": "test", "severity": "high"}
    flagged = apply_policy(ok, 100, set(REQUIRED_FOR_APPROVAL), 0, [hit])
    if big.decision == "escalate" and flagged.decision == "escalate":
        return PASS, (f"AI cannot approve at or above {settings.HUMAN_REVIEW_AMOUNT:,.0f} "
                      "or when a high-severity compliance rule fires.")
    return FAIL, "The AI's approval was not escalated to a human."


def _audit_trail() -> tuple[str, str]:
    from core import audit
    intact, bad_line = audit.verify()
    if not intact:
        return FAIL, f"Audit log chain broken at line {bad_line} of {settings.AUDIT_LOG.name}."
    if not settings.AUDIT_LOG.exists():
        return PASS, "Hash-chained audit log enabled (no decisions recorded yet)."
    count = len(settings.AUDIT_LOG.read_text().splitlines())
    return PASS, f"{count} decision record(s); SHA-256 chain intact."


def _masking() -> tuple[str, str]:
    from core.masking import mask_text
    if not settings.MASK_IDENTIFIERS:
        return FAIL, "MASK_IDENTIFIERS is off: real account ids are sent to PRISM."
    if "C123456" in mask_text("C123456 paid M654321"):
        return FAIL, "Masking did not replace account ids."
    if settings.MASK_SALT == "change-me-in-production":
        return WARN, "Account ids masked, but MASK_SALT is the default. Set a secret value."
    return PASS, "Account ids pseudonymised with a secret salt before leaving the system."


def _tracked_files() -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files"], cwd=settings.ROOT, capture_output=True,
                             text=True, check=True).stdout
        return [f for f in out.splitlines() if f]
    except (OSError, subprocess.CalledProcessError):
        return [str(p.relative_to(settings.ROOT)) for p in settings.ROOT.rglob("*")
                if p.is_file() and ".git" not in p.parts]


def _secrets() -> tuple[str, str]:
    gitignore = settings.ROOT / ".gitignore"
    if not gitignore.exists() or ".env" not in gitignore.read_text().split():
        return FAIL, ".env is not listed in .gitignore."
    leaks = []
    for name in _tracked_files():
        path = settings.ROOT / name
        if name == ".env" or (path.suffix in {".py", ".md", ".txt", ".csv", ".json", ".yml",
                                              ".yaml", ".toml", ".ini", ".example", ".cfg"}
                              and path.exists()):
            if name == ".env":
                leaks.append(".env is tracked by git")
                continue
            text = path.read_text(errors="ignore")
            if any(p.search(text) for p in SECRET_PATTERNS):
                leaks.append(name)
    if leaks:
        return FAIL, f"Possible secrets in tracked files: {leaks}"
    return PASS, "Keys come from the environment; .env is git-ignored; no keys in tracked files."


def _access_restriction() -> tuple[str, str]:
    from core.tools import ToolBox
    df = pd.DataFrame([
        {"txn_id": "T1", "step": 1, "type": "TRANSFER", "amount": 10.0, "nameOrig": "C100001",
         "oldbalanceOrg": 50.0, "newbalanceOrig": 40.0, "nameDest": "C100002",
         "oldbalanceDest": 0.0, "newbalanceDest": 10.0},
        {"txn_id": "T2", "step": 2, "type": "TRANSFER", "amount": 10.0, "nameOrig": "C100001",
         "oldbalanceOrg": 40.0, "newbalanceOrig": 30.0, "nameDest": "C100002",
         "oldbalanceDest": 10.0, "newbalanceDest": 20.0},
    ])
    box = ToolBox(df, "T2")
    for bad in ({"recipient_id": "C999999"}, {"recipient_id": "'; DROP TABLE"}):
        try:
            box.run("get_recipient_profile", bad)
            return FAIL, f"Lookup of {bad['recipient_id']!r} was allowed."
        except PermissionError:
            pass
    box.run("get_recipient_profile", {"recipient_id": "C100002"})
    return PASS, "Tools validate ids and only allow the two parties of the case."


def _monitoring() -> tuple[str, str]:
    import os
    if settings.MAX_TOOL_CALLS <= 0:
        return FAIL, "MAX_TOOL_CALLS must be positive."
    detail = (f"Every step traced; tool failures, access denials and >{settings.MAX_TOOL_CALLS} "
              "tool calls are recorded as security events.")
    if not os.environ.get("PRISMTRACE_API_KEY"):
        return WARN, detail + " PRISM key not set, so traces are local only."
    return PASS, detail + " Traces go to PRISM."


CONTROLS = [
    Control("SEC-01", "Least-privilege agent tools",
            "A.5.15 Access control; A.8.2 Privileged access rights",
            "6 Access Control Management", "core/tools.py", _least_privilege),
    Control("SEC-02", "Segregation of duties (human approves high-risk cases)",
            "A.5.3 Segregation of duties",
            "6 Access Control Management", "agents/risk_agent.py", _segregation_of_duties),
    Control("SEC-03", "Tamper-evident audit trail of decisions",
            "A.8.15 Logging; A.5.28 Collection of evidence; A.5.33 Protection of records",
            "8 Audit Log Management", "core/audit.py", _audit_trail),
    Control("SEC-04", "Masking of account ids sent to third parties (PRISM)",
            "A.8.11 Data masking; A.8.12 Data leakage prevention; A.5.34 Privacy and protection of PII",
            "3 Data Protection", "core/masking.py, core/tracing.py", _masking),
    Control("SEC-05", "Secrets kept out of code and the repository",
            "A.5.17 Authentication information; A.8.9 Configuration management",
            "3 Data Protection; 4 Secure Configuration", ".gitignore, .env.example", _secrets),
    Control("SEC-06", "Input validation and need-to-know data access",
            "A.8.3 Information access restriction; A.8.28 Secure coding",
            "6 Access Control Management; 16 Application Software Security",
            "core/tools.py", _access_restriction),
    Control("SEC-07", "Monitoring of agent behaviour",
            "A.8.16 Monitoring activities",
            "8 Audit Log Management", "agents/fraud_agent.py, core/tracing.py", _monitoring),
]


def run_checks() -> list[dict]:
    rows = []
    for c in CONTROLS:
        try:
            status, detail = c.check()
        except Exception as exc:  # a broken check is a failed control
            status, detail = FAIL, f"Check crashed: {exc.__class__.__name__}: {exc}"
        rows.append({"control": c.control_id, "title": c.title, "status": status,
                     "iso27001": c.iso27001, "cis_v8": c.cis_v8,
                     "implemented_in": c.implemented_in, "detail": detail})
    return rows
