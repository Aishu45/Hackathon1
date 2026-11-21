"""Pseudonymise account ids before data leaves the system (e.g. to PRISM).

ISO/IEC 27001:2022 A.8.11 Data masking, A.8.12 Data leakage prevention,
A.5.34 Privacy and protection of PII; CIS Controls v8 Control 3 Data Protection.

The same id always maps to the same pseudonym (a salted SHA-256), so traces
stay readable ("acct-3f2a91c0 sent money to acct-77b1e2d4") without exposing
real account numbers. Set MASK_SALT to a secret value in production.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from config import settings

ACCOUNT_ID = re.compile(r"\b([CM])(\d{6,})\b")


def pseudonym(account_id: str) -> str:
    digest = hashlib.sha256(f"{settings.MASK_SALT}:{account_id}".encode()).hexdigest()[:8]
    kind = "merchant" if account_id.startswith("M") else "acct"
    return f"{kind}-{digest}"


def mask_text(text: str) -> str:
    if not settings.MASK_IDENTIFIERS or not text:
        return text
    return ACCOUNT_ID.sub(lambda m: pseudonym(m.group(0)), text)


def mask(value: Any) -> Any:
    """Mask account ids anywhere inside strings, lists and dicts."""
    if isinstance(value, str):
        return mask_text(value)
    if isinstance(value, list):
        return [mask(v) for v in value]
    if isinstance(value, dict):
        return {k: mask(v) for k, v in value.items()}
    return value
