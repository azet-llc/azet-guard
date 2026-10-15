# Security policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

Fixes go into the latest release only. Upgrade with `uv tool upgrade azet-guard` or `pipx upgrade azet-guard`.

## Reporting a vulnerability

Please report security problems privately. Do not open a public issue.

- Preferred: GitHub private vulnerability reporting — the **Report a vulnerability** button under this repository's **Security** tab.
- Or email **hello@azet.io** with the subject "Security report".

Include the azet-guard version, your OS and Python version, the command or hook event that triggered the problem, and what you think the impact is. A bypass of a deny rule, a secret that reaches the model or the audit log unredacted, or a crash that disables the hooks all count as security issues.

## What to expect

- We reply within two business days.
- We confirm or reject the report within 14 days and tell you which release will carry the fix.
- Fixed vulnerabilities are published as GitHub Security Advisories and noted in the release notes, with credit to the reporter unless you ask us not to.

Please give us reasonable time to ship a fix before you share details publicly, and don't access other people's data while testing.

Company-wide policy: https://azet.io/safety#report · https://azet.io/.well-known/security.txt
