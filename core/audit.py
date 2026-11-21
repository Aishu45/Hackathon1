"""Tamper-evident audit log of every decision.

ISO/IEC 27001:2022 A.8.15 Logging, A.5.28 Collection of evidence,
A.5.33 Protection of records; CIS Controls v8 Control 8 Audit Log Management.

Each line stores the SHA-256 of the previous line, so editing or deleting
any earlier record breaks the chain and `verify()` reports where.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from config import settings

GENESIS = "0" * 64


def _digest(prev_hash: str, body: dict) -> str:
    canonical = json.dumps(body, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(f"{prev_hash}|{canonical}".encode()).hexdigest()


def _last_hash(path: Path) -> str:
    if not path.exists() or path.stat().st_size == 0:
        return GENESIS
    last = path.read_text().strip().splitlines()[-1]
    return json.loads(last)["hash"]


def append(event: str, details: dict, path: Path | None = None) -> str:
    """Add one record and return its hash."""
    path = Path(path or settings.AUDIT_LOG)
    prev = _last_hash(path)
    body = {"time": datetime.now(timezone.utc).isoformat(), "event": event, "details": details}
    record = {**body, "prev_hash": prev, "hash": _digest(prev, body)}
    with path.open("a") as f:
        f.write(json.dumps(record, default=str) + "\n")
    return record["hash"]


def verify(path: Path | None = None) -> tuple[bool, int | None]:
    """(True, None) if the chain is intact, else (False, first bad line number)."""
    path = Path(path or settings.AUDIT_LOG)
    if not path.exists():
        return True, None
    prev = GENESIS
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        try:
            record = json.loads(line)
            body = {k: record[k] for k in ("time", "event", "details")}
        except (ValueError, KeyError):
            return False, number
        if record.get("prev_hash") != prev or record.get("hash") != _digest(prev, body):
            return False, number
        prev = record["hash"]
    return True, None
