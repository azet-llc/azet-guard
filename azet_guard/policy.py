"""Policy: built-in defaults, optionally tuned by TOML files.

Load order (later wins): built-in defaults, ~/.azet-guard/policy.toml, <project>/.azet-guard.toml.

    mode = "enforce"            # "monitor" = log only, never block or ask
    disable = ["dump_environment"]
    require_tests_for_claims = true

    [actions]                   # change the action of a built-in rule: deny | ask | warn
    pipe_to_shell = "deny"

    [[shell_rules]]             # add your own command rules
    action = "ask"
    rule = "send_email"
    pattern = '\\bsendmail\\b|\\bmail\\s+-s\\b'
    message = "Sends email to someone outside the team."
"""
from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

HOME = Path(os.environ.get("AZET_GUARD_HOME", Path.home() / ".azet-guard"))
ACTIONS = ("deny", "ask", "warn")


@dataclass
class Policy:
    mode: str = "enforce"
    disable: set[str] = field(default_factory=set)
    actions: dict[str, str] = field(default_factory=dict)
    shell_rules: list[tuple[str, str, str, str]] = field(default_factory=list)
    require_tests_for_claims: bool = True
    sources: list[str] = field(default_factory=list)


def load(cwd: str | None = None) -> Policy:
    pol = Policy()
    files = [HOME / "policy.toml"]
    if cwd:
        files.append(Path(cwd) / ".azet-guard.toml")
    for f in files:
        if not f.is_file():
            continue
        data = tomllib.loads(f.read_text(encoding="utf-8"))  # a broken policy file should fail loudly
        pol.sources.append(str(f))
        if "mode" in data:
            if data["mode"] not in ("enforce", "monitor"):
                raise ValueError(f"{f}: mode must be enforce or monitor")
            pol.mode = data["mode"]
        pol.disable |= set(data.get("disable", []))
        for rule, action in data.get("actions", {}).items():
            if action not in ACTIONS:
                raise ValueError(f"{f}: actions.{rule} must be one of {ACTIONS}")
            pol.actions[rule] = action
        for r in data.get("shell_rules", []):
            if r.get("action") not in ACTIONS or not r.get("rule") or not r.get("pattern"):
                raise ValueError(f"{f}: each [[shell_rules]] needs action, rule and pattern")
            re.compile(r["pattern"])
            pol.shell_rules.append((r["action"], r["rule"], r["pattern"], r.get("message", r["rule"])))
        if "require_tests_for_claims" in data:
            pol.require_tests_for_claims = bool(data["require_tests_for_claims"])
    return pol


def apply(pol: Policy, findings):
    """Drop disabled rules and apply action overrides."""
    from .rules import Finding
    out = []
    for f in findings:
        if f.rule in pol.disable:
            continue
        out.append(Finding(pol.actions.get(f.rule, f.action), f.rule, f.message))
    return out
