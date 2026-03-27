# Security Policy

## Supported Versions

We actively support and provide security updates for the following versions:

| Version | Supported          | Notes                                    |
| ------- | ------------------ | ---------------------------------------- |
| 0.17.x  | :white_check_mark: | Current stable release (recommended)     |
| 0.16.x  | :white_check_mark: | Supported                                |
| < 0.16  | :x:                | No longer supported                      |

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
