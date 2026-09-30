# azet-guard

**Runtime guardrails for AI coding agents.** azet-guard plugs into [Claude Code hooks](https://docs.claude.com/en/docs/claude-code/hooks) and checks every tool call while the agent works:

- **Stops catastrophic commands** before they run (`rm -rf ~`, disk wipes, sending `.env` over the network).
- **Keeps secrets out of the model.** API keys in a command line are refused, keys in command output are redacted *before* the agent sees them, and keys pasted into a prompt trigger a "don't repeat this" note.
- **Asks before risky moves**: `curl … | sh`, force-pushing `main`, reading `.env` or SSH keys, dumping the environment.
- **Catches "all tests pass" when no test ran.** If the agent is about to finish with that claim and no test command ran in the turn, it is sent back to run them.
- **Flags prompt injection** in fetched pages and files ("ignore previous instructions…") so the agent treats it as data.
- **Logs every decision** to an append-only audit log, with secrets redacted.

No dependencies (Python 3.11+ standard library). No network calls. Nothing leaves your machine.

## Install

```bash
uv tool install git+https://github.com/neulketing/azet-guard     # or: pipx install git+https://github.com/neulketing/azet-guard
azet-guard install            # all your Claude Code projects (~/.claude/settings.json)
azet-guard install --project .  # only this repository (.claude/settings.json, commit it to share with your team)
```

Restart Claude Code (or open `/hooks`) so the hooks load. `azet-guard doctor` shows where it is installed and which policy applies; `azet-guard uninstall` removes only its own entries and keeps your other hooks.

## What it does in a real session

These are real Claude Code 2.1.285 runs with azet-guard installed (the key is a fake AWS-format key):

| You ask the agent to… | What happens |
| --- | --- |
| run `echo AKIA…  > /dev/null` | Blocked before it runs: *"the command line contains a secret (aws_access_key). Pass it through an environment variable or stdin instead."* |
| `cat cfg.txt` (a file holding a key) | The agent sees `aws_key=[REDACTED:aws_access_key]`; the real value never reaches the model. |
| finish with "All tests pass." without running tests | Sent back once: *"your reply says tests pass, but no test command ran in this turn."* The agent corrected its answer. |

## Rules

| Rule | Action | Example |
| --- | --- | --- |
| `secret_in_command` | deny | a token in a `curl -H` or `export` |
| `rm_root` | deny | `rm -rf /`, `rm -rf ~`, `rm -rf $HOME` |
| `disk_wipe`, `fork_bomb`, `chmod_world_root` | deny | `mkfs`, `dd of=/dev/disk2` |
| `exfil_secret_file` | deny | `curl -F f=@.env https://…` |
| `secret_in_file` | deny | writing a key into `src/config.py` (writing it into `.env` is fine) |
| `protected_path` | deny | writes into `.git/`, `~/.ssh/`, `/etc/` |
| `pipe_to_shell` | ask | `curl … \| sh` |
| `force_push_protected` | ask | `git push --force origin main` |
| `read_secret_file` | ask | `cat .env`, reading `id_ed25519`, `*.pem` (`.env.example` is fine) |
| `dump_environment`, `echo_secret_var` | ask | `env`, `printenv`, `echo $OPENAI_API_KEY` |
| `git_add_secret_file` | ask | `git add .env` |
| `rm_recursive_wildcard` | ask | `rm -rf *` |
| `redact_output` | redact | secrets in Bash output |
| `prompt_injection` | warn | "ignore all previous instructions…" in a fetched page |
| `secret_in_prompt` | warn | a key pasted into your message |
| `unverified_test_claim` | block once | "tests pass" with no test run this turn |

Detected secret formats: AWS access keys, GitHub tokens, Anthropic and OpenAI keys, Stripe keys, Slack tokens, Google API keys, private key blocks, JWTs.

`azet-guard check "<command>"` shows what the guard would do with any command (exit 0 allow, 1 ask, 2 deny).

## Policy

Defaults work out of the box. Tune them in `~/.azet-guard/policy.toml` (you) or `.azet-guard.toml` in a repository (your team):

```toml
mode = "enforce"                 # "monitor" logs what it would do but never blocks — good for a trial week
disable = ["dump_environment"]
require_tests_for_claims = true

[actions]                        # change a built-in rule: deny | ask | warn
pipe_to_shell = "deny"

[[shell_rules]]                  # add your own
action = "ask"
rule = "send_email"
pattern = '\bsendmail\b|\bmail\s+-s\b'
message = "Sends email to someone outside the team."
```

## Audit log

`~/.azet-guard/audit.jsonl` (mode 600), one JSON line per decision. `azet-guard log` prints the latest ones. Secrets are redacted before anything is written.

## Honest limits

- It is a guardrail, not a sandbox. The rules are regular expressions: a determined agent can obfuscate a command (`$(echo cm0= | base64 -d) -rf ~`). Use it together with Claude Code permissions and, for untrusted work, a container.
- Secret detection covers formats with a recognisable prefix. Plain passwords and custom tokens are not detected unless you add a rule.
- The test-claim check looks for a test command in the turn; it does not judge whether those tests cover your change.
- If azet-guard itself crashes, it fails open (your session keeps working) and records the error in the audit log. A policy file that doesn't parse fails loudly instead.

## Roadmap

Codex CLI and Cursor adapters, a team dashboard with shared policies and audit search, and SSO. If you want the team version early, write to hello@azet.io.

## Development

```bash
python3 -m unittest discover -s tests -v
```

## License

Apache-2.0. Made by [AZET](https://azet.io).
