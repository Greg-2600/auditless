# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in Linux Health Security Scanner, please report it responsibly:

### Do Not

- ❌ Open a public GitHub issue
- ❌ Post about it on social media
- ❌ Share vulnerability details publicly

### Do

1. **Email:** Send details to the maintainers (described below)
2. **Wait:** Allow reasonable time (30 days) for a patch
3. **Coordinate:** Work with maintainers on disclosure timeline

### Reporting Process

Email your security report to: **[security-contact@example.com]**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

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

However, users should:
- Use SSH key-based authentication in production (not passwords)
- Restrict scanner access to authorized network ranges
- Scan systems with your organization's security policies
- Audit scan results before acting on them

## Dependency Security

We actively monitor dependencies for vulnerabilities via:
- Regular `pip-audit` checks
- GitHub Dependabot alerts
- Manual security audits

Report dependency vulnerabilities using the process above.

---

**Thank you for helping keep Linux Health secure!**
