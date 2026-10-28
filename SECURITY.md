# Security Policy

## Supported Versions

We actively support and provide security updates for the following versions:

| Version | Supported          | Notes                                    |
| ------- | ------------------ | ---------------------------------------- |
| 0.34.x  | :white_check_mark: | Current stable release (recommended)     |
| 0.33.x  | :white_check_mark: | Supported                                |
| < 0.33  | :x:                | No longer supported                      |

## Reporting a Vulnerability

If you discover a security vulnerability in netcidr, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Send a detailed report to the maintainers via [GitHub Security Advisories](https://github.com/wingnut128/netcidr/security/advisories/new)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours of report
- **Initial Assessment**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: Within 7 days
  - High: Within 30 days
  - Medium/Low: Next scheduled release

## Security Best Practices

When using netcidr:

- Run the API server behind a reverse proxy in production
- Use appropriate network segmentation
- Keep the software updated to the latest version
- Review and restrict access to log files if sensitive data may be logged

## Telemetry and data sent off-host

OpenTelemetry trace export is opt-in: it needs a binary built with the `otel`
feature **and** `OTEL_EXPORTER_OTLP_ENDPOINT` set at runtime. Without both, no
spans leave the process.

When export is on:

- A redacting exporter strips any span attribute keyed like PII or a
  credential (`*email`, `sub`, `*token*`, `*secret*`, `*password*`,
  authorization/bearer, `database_url`, ...) before spans are sent. Request
  spans record the route template (e.g. `/ipam/cidr-blocks/{id}`), never the
  raw path or query string. See
  [ADR-0004](docs/adr/0004-opt-in-otlp-span-export.md).
- An inbound W3C `traceparent` header continues the caller's trace. Sampling
  is parent-based, so a caller can opt its own requests out of tracing; it
  cannot affect other callers' traces.
- The collector credential (e.g. `OTEL_EXPORTER_OTLP_HEADERS` carrying a
  Honeycomb ingest key) is an environment variable: restrict who can read the
  process environment or function configuration, and rotate it like any other
  secret.

Report a field that should have been redacted but was exported as a
vulnerability, using the process above.

## Security update automation

The daily **Security Audit (main)** runs two independent checks: Rust/dashboard
advisories and Chainguard image freshness. The latter compares each literal
`cgr.dev/chainguard/` Dockerfile `FROM` tag's registry digest with its SHA-256 pin,
including the multi-platform index. It reports stale pins even when vulnerability
scanners find no advisories or Dependabot has stopped opening updates. Registry
errors and invalid pins fail the check; they never count as current images.

A dedicated security issue tracks stale Chainguard pins and lookup failures. It
closes only when a subsequent audit sees current pins on main (or no remaining
Chainguard images), not when a proposed fix passes PR checks. This issue tracks
source freshness, not deployment status. The weekly **Image Scan** separately
tracks fixable vulnerabilities and fails visibly when findings are present.

Every advisory review must also check Chainguard freshness:

```sh
python3 .github/scripts/image_updates.py Dockerfile
```

This requires Docker Buildx and registry access, but no image build or running
Docker daemon. Exit codes are 0 for current/not applicable, 1 for stale pins, and
2 for errors. Keep Chainguard references literal and pinned as `tag@sha256:...`.
For a new digest, verify linux/amd64 and linux/arm64, scan the rebuilt image, and
merge a signed update PR. Confirm a release includes the changed Dockerfile and
that the deployed image uses that release before declaring remediation complete.
If Dependabot stalls, inspect its update logs and closed digest PRs; a successful
Dependabot run alone does not prove the image pins are fresh.
