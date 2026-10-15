# Contributing to azet-guard

Bug reports, rule suggestions and pull requests are welcome.

## Reporting bugs and requesting features

Open an issue at https://github.com/azet-llc/azet-guard/issues. Include the azet-guard version (`azet-guard --version` or `pip show azet-guard`), your OS, Python version, and the command or hook event involved. Security problems go through SECURITY.md, not public issues.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Keep the change focused: one rule or one fix per pull request.
3. Add or update tests in `tests/` for every new rule or behavior change. A new deny/ask rule needs at least one test that triggers it and one that must not.
4. Run the checks locally:
   - `python -m unittest discover -s tests`
   - `ruff check --select E9,F63,F7,F82 .`
   - `bandit -r azet_guard -lll`
5. Open the pull request against `main`. CI runs the same checks; a maintainer reviews before merge.

## Code requirements

- Python 3.11+ standard library only. No new runtime dependencies.
- No network calls from the hooks.
- Never write a secret value to stdout, the audit log or test fixtures; use obviously fake keys in tests.

By contributing you agree that your contribution is licensed under the Apache License 2.0.
