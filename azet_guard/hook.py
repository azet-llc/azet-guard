"""Claude Code hook entry point: `azet-guard hook` reads the event JSON on stdin and prints a decision JSON.

Fail-open by design for the guard's own bugs (a crash never blocks the user's work), but every
crash is written to the audit log. Policy files that do not parse are the exception: they fail loudly.
"""
from __future__ import annotations

import json
import sys

from . import ledger, policy, rules

FILE_WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
TEXT_RESULT_TOOLS = {"WebFetch", "WebSearch", "Read"}


def _written_text(tool: str, ti: dict) -> str:
    if tool == "Write":
        return ti.get("content", "")
    if tool == "Edit":
        return ti.get("new_string", "")
    if tool == "MultiEdit":
        return "\n".join(e.get("new_string", "") for e in ti.get("edits", []))
    if tool == "NotebookEdit":
        return ti.get("new_source", "")
    return ""


def _decide(findings):
    for action in ("deny", "ask", "warn"):
        hit = [f for f in findings if f.action == action]
        if hit:
            return action, hit
    return None, []


def pre_tool_use(ev: dict, pol: policy.Policy) -> dict | None:
    tool, ti = ev.get("tool_name", ""), ev.get("tool_input") or {}
    if tool in ("Bash", "PowerShell"):
        findings, subject = rules.check_command(ti.get("command", ""), pol.shell_rules), ti.get("command", "")
    elif tool in FILE_WRITE_TOOLS:
        path = ti.get("file_path") or ti.get("notebook_path", "")
        findings, subject = rules.check_write(path, _written_text(tool, ti)), path
    elif tool == "Read":
        findings, subject = rules.check_read(ti.get("file_path", "")), ti.get("file_path", "")
    else:
        return None
    action, hit = _decide(policy.apply(pol, findings))
    if not action:
        return None
    reason = "azet-guard: " + " ".join(f"[{f.rule}] {f.message}" for f in hit)
    rule = ",".join(f.rule for f in hit)
    if pol.mode == "monitor":
        ledger.audit("PreToolUse", ev.get("session_id", ""), tool, f"monitor:{action}", rule, subject)
        return None
    ledger.audit("PreToolUse", ev.get("session_id", ""), tool, action, rule, subject)
    if action == "warn":
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": reason}}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": action,
                                   "permissionDecisionReason": reason}}


def post_tool_use(ev: dict, pol: policy.Policy) -> dict | None:
    tool, ti, resp = ev.get("tool_name", ""), ev.get("tool_input") or {}, ev.get("tool_response")
    session = ev.get("session_id", "")
    notes, out = [], {"hookEventName": "PostToolUse"}
    if tool == "Bash":
        if rules.is_test_command(ti.get("command", "")):
            st = ledger.load_state(session)
            st["tests_ok"] = st.get("tests_ok", 0) + 1
            ledger.save_state(session, st)
        if isinstance(resp, dict) and "redact_output" not in pol.disable:
            red_out, n1 = rules.redact(str(resp.get("stdout", "")))
            red_err, n2 = rules.redact(str(resp.get("stderr", "")))
            if n1 + n2:
                out["updatedToolOutput"] = {**resp, "stdout": red_out, "stderr": red_err}
                notes.append(f"azet-guard: redacted {n1 + n2} secret value(s) from this command's output before it reached you. Do not try to print them again.")
                ledger.audit("PostToolUse", session, tool, "redact", "redact_output", ti.get("command", ""))
    if tool in TEXT_RESULT_TOOLS or tool.startswith("mcp__"):
        text = resp if isinstance(resp, str) else json.dumps(resp, ensure_ascii=False)
        found = policy.apply(pol, rules.check_injection(text))
        if found:
            notes.append("azet-guard: " + found[0].message)
            ledger.audit("PostToolUse", session, tool, "warn", "prompt_injection", found[0].message)
    if not notes or pol.mode == "monitor":
        return None
    out["additionalContext"] = " ".join(notes)
    return {"hookSpecificOutput": out}


def post_tool_use_failure(ev: dict, pol: policy.Policy) -> None:
    ti = ev.get("tool_input") or {}
    if ev.get("tool_name") == "Bash" and rules.is_test_command(ti.get("command", "")):
        st = ledger.load_state(ev.get("session_id", ""))
        st["tests_failed"] = st.get("tests_failed", 0) + 1
        ledger.save_state(ev.get("session_id", ""), st)
    return None


def user_prompt_submit(ev: dict, pol: policy.Policy) -> dict | None:
    session = ev.get("session_id", "")
    ledger.save_state(session, {"tests_ok": 0, "tests_failed": 0, "claim_blocks": 0})  # a new turn starts
    secrets = rules.find_secrets(ev.get("prompt", ""))
    if not secrets or "secret_in_prompt" in pol.disable:
        return None
    ledger.audit("UserPromptSubmit", session, "", "warn", "secret_in_prompt", ", ".join(secrets))
    if pol.mode == "monitor":
        return None
    return {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext":
            f"azet-guard: the user's message contains a secret ({', '.join(secrets)}). Do not repeat it in replies, files, commits or command lines; if it must be stored, put it in .env or a secret manager and suggest rotating it."}}


def stop(ev: dict, pol: policy.Policy) -> dict | None:
    if not pol.require_tests_for_claims or ev.get("stop_hook_active") or "unverified_test_claim" in pol.disable:
        return None
    if not rules.claims_tests_pass(ev.get("last_assistant_message", "")):
        return None
    session = ev.get("session_id", "")
    st = ledger.load_state(session)
    if st.get("tests_ok", 0) > 0 or st.get("claim_blocks", 0) > 0:
        return None
    st["claim_blocks"] = 1
    ledger.save_state(session, st)
    why = ("the last test run in this turn failed" if st.get("tests_failed") else "no test command ran in this turn")
    ledger.audit("Stop", session, "", "monitor:block" if pol.mode == "monitor" else "block", "unverified_test_claim", why)
    if pol.mode == "monitor":
        return None
    return {"decision": "block", "reason": f"azet-guard: your reply says tests pass, but {why}. Run the tests now and report the real result, or say plainly that they were not run."}


HANDLERS = {"PreToolUse": pre_tool_use, "PostToolUse": post_tool_use, "PostToolUseFailure": post_tool_use_failure,
            "UserPromptSubmit": user_prompt_submit, "Stop": stop}


def main() -> int:
    raw = sys.stdin.read()
    try:
        ev = json.loads(raw or "{}")
    except ValueError:
        return 0
    handler = HANDLERS.get(ev.get("hook_event_name", ""))
    if not handler:
        return 0
    pol = policy.load(ev.get("cwd"))  # a broken policy file raises: better loud than silently unguarded
    try:
        result = handler(ev, pol)
    except Exception as e:  # noqa: BLE001 — the guard must never break the user's session
        ledger.audit(ev.get("hook_event_name", ""), ev.get("session_id", ""), ev.get("tool_name", ""), "error", "internal", repr(e))
        return 0
    if result:
        sys.stdout.write(json.dumps(result))
    return 0
