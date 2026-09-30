"""Audit log (append-only JSONL) and per-session turn state. Secrets are redacted before anything is written."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .policy import HOME
from .rules import redact


def _write(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def audit(event: str, session: str, tool: str, decision: str, rule: str, detail: str) -> None:
    detail, _ = redact(detail or "")
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event, "session": session, "tool": tool,
           "decision": decision, "rule": rule, "detail": detail[:300]}
    _write(HOME / "audit.jsonl", json.dumps(rec, ensure_ascii=False))


def _state_path(session: str) -> Path:
    safe = "".join(c for c in (session or "unknown") if c.isalnum() or c in "-_")[:80] or "unknown"
    return HOME / "sessions" / f"{safe}.json"


def load_state(session: str) -> dict:
    try:
        return json.loads(_state_path(session).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"tests_ok": 0, "tests_failed": 0, "claim_blocks": 0}


def save_state(session: str, state: dict) -> None:
    p = _state_path(session)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state), encoding="utf-8")
    os.replace(tmp, p)
