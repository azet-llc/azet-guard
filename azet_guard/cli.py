"""azet-guard command line.

    azet-guard install [--project DIR] [--codex] [--dry-run]   add the hooks to Claude Code (or Codex CLI) settings
    azet-guard uninstall [--project DIR] [--codex]
    azet-guard check "<shell command>"                what the guard would do with a command
    azet-guard log [-n 20]                            recent decisions from the audit log
    azet-guard doctor                                 where it is installed and which policy applies
    azet-guard hook                                   (called by Claude Code) handle one hook event
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import sys
import time
from pathlib import Path

from . import __version__, policy, rules

MARK = "azet_guard hook"


def _command() -> str:
    # Absolute interpreter path: works from any cwd and inside pipx/uv virtualenvs without PATH tricks.
    return f"{shlex.quote(sys.executable)} -m {MARK}"


HOOKS = {
    "PreToolUse": "Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|Read",
    "PostToolUse": "Bash|Read|WebFetch|WebSearch|mcp__.*",
    "PostToolUseFailure": "Bash",
    "UserPromptSubmit": None,
    "Stop": None,
}
CODEX_HOOKS = {"PreToolUse": "Bash|apply_patch", "PostToolUse": "Bash|mcp__.*", "UserPromptSubmit": None, "Stop": None}


def settings_path(project: str | None, codex: bool = False) -> Path:
    if codex:
        return (Path(project).resolve() / ".codex" if project else Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))) / "hooks.json"
    if project:
        return Path(project).resolve() / ".claude" / "settings.json"
    return Path(os.environ.get("CLAUDE_CONFIG_DIR", Path.home() / ".claude")) / "settings.json"


def _strip(settings: dict) -> dict:
    hooks = settings.get("hooks", {})
    for event in list(hooks):
        groups = []
        for g in hooks[event]:
            kept = [h for h in g.get("hooks", []) if MARK not in h.get("command", "")]
            if kept:
                groups.append({**g, "hooks": kept})
        if groups:
            hooks[event] = groups
        else:
            del hooks[event]
    if not hooks:
        settings.pop("hooks", None)
    return settings


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))  # invalid JSON: stop, don't overwrite the user's file


def _save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_name(f"{path.name}.bak-azet-guard-{time.strftime('%Y%m%d%H%M%S')}"))
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def install(args) -> int:
    path = settings_path(args.project, args.codex)
    data = _strip(_load(path))
    hooks = data.setdefault("hooks", {})
    for event, matcher in (CODEX_HOOKS if args.codex else HOOKS).items():
        group = {"hooks": [{"type": "command", "command": _command() + (" --codex" if args.codex else ""), "timeout": 10}]}
        if matcher:
            group = {"matcher": matcher, **group}
        hooks.setdefault(event, []).append(group)
    if args.dry_run:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0
    _save(path, data)
    print(f"azet-guard {__version__} installed in {path}")
    print("Open /hooks in Codex and trust the azet-guard hooks so they run." if args.codex else "Restart Claude Code (or open /hooks) so the new hooks load.")
    return 0


def uninstall(args) -> int:
    path = settings_path(args.project, args.codex)
    if not path.exists():
        print(f"nothing to do: {path} does not exist")
        return 0
    _save(path, _strip(_load(path)))
    print(f"azet-guard removed from {path}")
    return 0


def check(args) -> int:
    pol = policy.load(os.getcwd())
    found = policy.apply(pol, rules.check_command(args.command, pol.shell_rules))
    if not found:
        print("allow")
        return 0
    for f in found:
        print(f"{f.action:5} {f.rule}: {f.message}")
    return 2 if any(f.action == "deny" for f in found) else 1


def log(args) -> int:
    p = policy.HOME / "audit.jsonl"
    if not p.exists():
        print("no decisions logged yet")
        return 0
    for line in p.read_text(encoding="utf-8").splitlines()[-args.n:]:
        r = json.loads(line)
        print(f"{r['ts']}  {r['decision']:13} {r['rule']:24} {r['tool']:8} {r['detail'][:90]}")
    return 0


def doctor(args) -> int:
    print(f"azet-guard {__version__} (python {sys.version.split()[0]})")
    for label, proj, codex in (("user", None, False), ("project", os.getcwd(), False), ("codex", None, True), ("codex-pj", os.getcwd(), True)):
        p = settings_path(proj, codex)
        on = p.exists() and MARK in p.read_text(encoding="utf-8")
        print(f"{label:8} {'installed' if on else 'not installed':14} {p}")
    pol = policy.load(os.getcwd())
    print(f"mode     {pol.mode}")
    print(f"policy   {', '.join(pol.sources) or 'built-in defaults'}")
    print(f"log      {policy.HOME / 'audit.jsonl'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="azet-guard", description="Runtime guardrails for AI coding agents (Claude Code and Codex CLI hooks).")
    ap.add_argument("--version", action="version", version=f"azet-guard {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("install", install), ("uninstall", uninstall)):
        s = sub.add_parser(name)
        s.add_argument("--project", metavar="DIR", help="use DIR/.claude/settings.json instead of your user settings")
        s.add_argument("--codex", action="store_true", help="Codex CLI: use ~/.codex/hooks.json (or DIR/.codex/hooks.json)")
        if name == "install":
            s.add_argument("--dry-run", action="store_true", help="print the resulting settings without writing")
        s.set_defaults(fn=fn)
    s = sub.add_parser("check"); s.add_argument("command"); s.set_defaults(fn=check)
    s = sub.add_parser("log"); s.add_argument("-n", type=int, default=20); s.set_defaults(fn=log)
    sub.add_parser("doctor").set_defaults(fn=doctor)
    s = sub.add_parser("hook"); s.add_argument("--codex", action="store_true")
    s.set_defaults(fn=lambda a: __import__("azet_guard.hook", fromlist=["main"]).main(codex=a.codex))
    args = ap.parse_args(argv)
    return args.fn(args)
