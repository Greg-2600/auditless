# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in Auditless, please report it
**privately** — never through a public issue, social media, or chat:

1. Go to the repository's **Security** tab and choose
   **Report a vulnerability** (private vulnerability reporting).
2. Describe the issue, steps to reproduce, potential impact, and a
   suggested fix if you have one.
3. Allow reasonable time (30 days) for a patch and coordinate disclosure.

### What to Expect

- Acknowledgment within 48 hours
- Initial assessment within 5 days
- Security patch release within 30 days (when possible)
- Credit in release notes (if desired)

## Security Considerations

Linux Health performs **read-only operations** on target systems:

- ✅ No system modifications
- ✅ No privileged operations
- ✅ No data exfiltration
- ✅ Local report generation only

Operator responsibilities:

- Prefer SSH key auth (`--key-file`, saved hosts) over passwords; when a
  password is needed, use `--ask-password`, never the command line.
- Serve the dashboard on loopback, or set `AUDITLESS_TOKEN` (bearer auth
  on every `/api/*` route) and put authentication + TLS in front before
  exposing it to any network.
- Scan keys are stored 0600 and never readable back through the API.
- Restrict scanner access to authorized network ranges and audit scan
  results before acting on them.

## Dependency Security

We actively monitor dependencies for vulnerabilities via:

- Regular `pip-audit` checks
- GitHub Dependabot alerts
- Manual security audits

Report dependency vulnerabilities using the process above.

---

**Thank you for helping keep Auditless secure!**
