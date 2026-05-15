# Web Audit Assistant

Safe web audit helper for authorized security assessments.

This project automates common low-impact web checks used during ethical hacking labs, internal audits, and defensive reviews. It focuses on evidence collection and reporting, not exploitation.

## Current Features

- Requires an explicit `--scope` before scanning.
- Checks common security headers:
  - `Content-Security-Policy`
  - `Strict-Transport-Security`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
- Reviews `Set-Cookie` flags:
  - `Secure`
  - `HttpOnly`
  - `SameSite`
- Detects risky CORS configurations.
- Identifies HTML forms and basic CSRF indicators.
- Flags password forms served over cleartext HTTP.
- Checks a small list of commonly exposed paths:
  - `/robots.txt`
  - `/.env`
  - `/.git/config`
  - `/backup.zip`
  - `/phpinfo.php`
  - `/admin`
- Sends optional low-impact canary payloads to detect simple reflection.
- Generates JSON and Markdown reports.

## Ethical Use

Use this tool only against systems you own, lab environments, bug bounty targets where this activity is allowed, or systems where you have explicit written permission.

The tool does not brute-force credentials, exploit vulnerabilities, upload files, or run destructive payloads.

## Installation

Requirements:

- Python 3.11 or higher.

From the project directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

To test the local demo after installation, open two PowerShell consoles.

Console 1, start the intentionally vulnerable demo server:

```powershell
cd C:\path\to\web-audit-assistant
.\.venv\Scripts\Activate.ps1
python tools\demo_server.py
```

Console 2, run the audit against the local demo:

```powershell
cd C:\path\to\web-audit-assistant
.\.venv\Scripts\Activate.ps1
python -m web_audit_assistant scan http://127.0.0.1:8088 --scope 127.0.0.1 --canary --json reports\demo.json --markdown reports\demo.md
```

## Usage

Analyze a target URL:

```powershell
python -m web_audit_assistant scan https://example.com --scope example.com
```

Write reports:

```powershell
python -m web_audit_assistant scan https://example.com --scope example.com --json reports/example.json --markdown reports/example.md
```

Enable low-impact reflection checks:

```powershell
python -m web_audit_assistant scan https://example.com --scope example.com --canary
```

Run the local demo server:

```powershell
python tools/demo_server.py
```

Then scan it from another terminal:

```powershell
python -m web_audit_assistant scan http://127.0.0.1:8088 --scope 127.0.0.1 --canary --json reports/demo.json --markdown reports/demo.md
```

Slow down requests:

```powershell
python -m web_audit_assistant scan https://example.com --scope example.com --delay 1.5
```

## Limitations

- This is not a full DAST scanner.
- It does not crawl the full site.
- It does not bypass authentication.
- Reflection checks use harmless canary strings and do not execute JavaScript.
- Results should be manually validated before being treated as confirmed vulnerabilities.

## Roadmap

- Controlled crawling with depth limits.
- Sitemap and robots parsing.
- Authentication support through user-provided cookies.
- HTML report.
- YAML rule configuration.
- OWASP Top 10 mapping.
