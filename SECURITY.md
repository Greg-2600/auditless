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
   **Report a vulnerability** (private vulnerability reporting —
   [how it works](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)).
2. Describe the issue, steps to reproduce, potential impact, and a
   suggested fix if you have one. See also our
   [supported versions](#supported-versions) and
   [security considerations](#security-considerations) below.
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

## Supply Chain (what each release artifact proves)

Every `v*` tag builds multi-arch images with attestations, then signs
and verifies them before the release counts as good:

- **SLSA provenance** — `provenance: true` on the image build records
  exactly which commit and workflow produced the image; verified
  with `slsa-verifier` (buildx attestations are not cosign envelopes,
  so `cosign verify-attestation` cannot read them).
- **SBOM** — an SPDX SBOM is generated from the pushed image and
  attached with `cosign attest --type spdxjson`, so `cosign download
  sbom` retrieves an authenticated bill of materials.
- **Signatures** — keyless Sigstore/OIDC signing; no long-lived keys.
- **Verification gate** — the release workflow itself runs
  `cosign verify`, `slsa-verifier verify-image`, a cosign SBOM
  attestation check, an SBOM download, and a boot
  smoke test of the image *by digest*. Trivy scans upload SARIF.

Verify any release yourself (no secrets needed):

```bash
VERSION=${VERSION:-2.5.3}  # export the release you want to verify
IMG=ghcr.io/greg-2600/auditless:${VERSION}
cosign verify \
  --certificate-identity-regexp "https://github.com/Greg-2600/auditless/.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$IMG"
slsa-verifier verify-image "$IMG" \
  --source-uri "github.com/Greg-2600/auditless" \
  --source-tag "v${VERSION}"
cosign download sbom "$IMG" | python3 -c "import json,sys; print(len(json.load(sys.stdin)['packages']), 'packages')"
```

---

**Thank you for helping keep Auditless secure!**

## Repository Hardening Notes

- `main` requires pull requests with green CI (tests, e2e, CodeQL,
  Trivy) and blocks force-pushes and deletions. During solo active
  development the maintainer role retains bypass for break-glass
  merges; every bypass is logged by GitHub and reviewed after the
  fact. Revisit removing bypass once a second reviewer exists.
- All GitHub Actions pin to full commit SHAs (Dependabot keeps them
  fresh); workflows run with least-privilege tokens.
