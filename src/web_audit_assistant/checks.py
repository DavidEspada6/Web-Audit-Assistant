from __future__ import annotations

import re
import urllib.parse
from collections import Counter

from .http_client import HttpClient, HttpClientError, join_url
from .models import Finding, HttpResponse


SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "MEDIUM",
        "Missing Content Security Policy",
        "A Content Security Policy helps reduce the impact of XSS and content injection issues.",
        "Define a restrictive Content-Security-Policy header appropriate for the application.",
    ),
    "Strict-Transport-Security": (
        "MEDIUM",
        "Missing HTTP Strict Transport Security",
        "HSTS tells browsers to use HTTPS for future requests.",
        "Enable Strict-Transport-Security on HTTPS responses after validating HTTPS is correctly configured.",
    ),
    "X-Frame-Options": (
        "LOW",
        "Missing clickjacking protection header",
        "X-Frame-Options or CSP frame-ancestors can help prevent clickjacking.",
        "Set X-Frame-Options or define the frame-ancestors directive in Content-Security-Policy.",
    ),
    "X-Content-Type-Options": (
        "LOW",
        "Missing MIME sniffing protection",
        "X-Content-Type-Options reduces browser MIME sniffing risks.",
        "Set X-Content-Type-Options: nosniff.",
    ),
    "Referrer-Policy": (
        "LOW",
        "Missing Referrer Policy",
        "A Referrer-Policy limits sensitive URL data sent in the Referer header.",
        "Set a Referrer-Policy such as strict-origin-when-cross-origin.",
    ),
    "Permissions-Policy": (
        "INFO",
        "Missing Permissions Policy",
        "Permissions-Policy limits access to browser features such as camera, microphone, and geolocation.",
        "Define a Permissions-Policy header matching application needs.",
    ),
}

SENSITIVE_PATHS = [
    "/robots.txt",
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/backup.tar.gz",
    "/phpinfo.php",
    "/server-status",
    "/admin",
]

FORM_RE = re.compile(r"(?is)<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>")
ATTR_RE = re.compile(r"""(?is)([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*['"]([^'"]*)['"]""")
INPUT_RE = re.compile(r"(?is)<input\b([^>]*)>")
CANARY = "web-audit-canary-9f31"


def run_checks(
    client: HttpClient,
    target_url: str,
    enable_canary: bool = False,
    sensitive_paths: list[str] | None = None,
) -> tuple[list[Finding], dict[str, object]]:
    findings: list[Finding] = []
    requested_urls: list[str] = []

    response = client.request(target_url)
    requested_urls.append(target_url)
    findings.extend(check_security_headers(response))
    findings.extend(check_cookies(response))
    findings.extend(check_cors(client, target_url, requested_urls))
    findings.extend(check_forms(response))
    findings.extend(check_sensitive_paths(client, target_url, sensitive_paths or SENSITIVE_PATHS, requested_urls))

    if enable_canary:
        findings.extend(check_canary_reflection(client, target_url, requested_urls))

    stats = {
        "requested_urls": len(requested_urls),
        "status": response.status,
        "content_length": len(response.body),
        "findings_by_severity": dict(Counter(finding.severity for finding in findings)),
    }
    return sort_findings(findings), stats


def check_security_headers(response: HttpResponse) -> list[Finding]:
    findings = []
    is_https = urllib.parse.urlparse(response.url).scheme == "https"

    for header, (severity, title, description, recommendation) in SECURITY_HEADERS.items():
        if header == "Strict-Transport-Security" and not is_https:
            continue
        if response.get_header(header):
            continue
        findings.append(
            make_finding(
                response.url,
                rule_id=f"MISSING_{header.upper().replace('-', '_')}",
                title=title,
                severity=severity,
                category="Security Headers",
                description=description,
                evidence=f"Header not present: {header}",
                recommendation=recommendation,
            )
        )

    csp = response.get_header("Content-Security-Policy")
    if csp and "unsafe-inline" in csp.lower():
        findings.append(
            make_finding(
                response.url,
                rule_id="CSP_UNSAFE_INLINE",
                title="Content Security Policy allows unsafe-inline",
                severity="LOW",
                category="Security Headers",
                description="The CSP contains unsafe-inline, which can weaken XSS protections.",
                evidence=csp,
                recommendation="Avoid unsafe-inline where possible. Prefer nonces, hashes, or external scripts from trusted sources.",
            )
        )

    return findings


def check_cookies(response: HttpResponse) -> list[Finding]:
    findings = []
    for cookie in response.get_headers("Set-Cookie"):
        lowered = cookie.lower()
        cookie_name = cookie.split("=", 1)[0]

        if "secure" not in lowered:
            findings.append(
                make_finding(
                    response.url,
                    rule_id="COOKIE_MISSING_SECURE",
                    title="Cookie missing Secure flag",
                    severity="MEDIUM",
                    category="Cookies",
                    description="A cookie without Secure may be sent over cleartext HTTP.",
                    evidence=f"{cookie_name} missing Secure",
                    recommendation="Set the Secure attribute on session and sensitive cookies.",
                )
            )

        if "httponly" not in lowered:
            findings.append(
                make_finding(
                    response.url,
                    rule_id="COOKIE_MISSING_HTTPONLY",
                    title="Cookie missing HttpOnly flag",
                    severity="LOW",
                    category="Cookies",
                    description="A cookie without HttpOnly can be accessed by client-side scripts.",
                    evidence=f"{cookie_name} missing HttpOnly",
                    recommendation="Set HttpOnly on cookies that do not need to be accessed by JavaScript.",
                )
            )

        if "samesite=" not in lowered:
            findings.append(
                make_finding(
                    response.url,
                    rule_id="COOKIE_MISSING_SAMESITE",
                    title="Cookie missing SameSite attribute",
                    severity="LOW",
                    category="Cookies",
                    description="SameSite helps reduce cross-site request risks.",
                    evidence=f"{cookie_name} missing SameSite",
                    recommendation="Set SameSite=Lax or SameSite=Strict where compatible with application flows.",
                )
            )

    return findings


def check_cors(client: HttpClient, target_url: str, requested_urls: list[str] | None = None) -> list[Finding]:
    origin = "https://audit-canary.invalid"
    try:
        response = client.request(target_url, headers={"Origin": origin})
        if requested_urls is not None:
            requested_urls.append(target_url)
    except HttpClientError:
        return []

    allow_origin = response.get_header("Access-Control-Allow-Origin")
    allow_credentials = response.get_header("Access-Control-Allow-Credentials")
    if not allow_origin:
        return []

    findings = []
    if allow_origin == "*":
        findings.append(
            make_finding(
                response.url,
                rule_id="CORS_WILDCARD_ORIGIN",
                title="CORS allows any origin",
                severity="MEDIUM",
                category="CORS",
                description="The application allows cross-origin requests from any origin.",
                evidence="Access-Control-Allow-Origin: *",
                recommendation="Restrict Access-Control-Allow-Origin to trusted origins only.",
            )
        )

    if allow_origin == origin and allow_credentials and allow_credentials.lower() == "true":
        findings.append(
            make_finding(
                response.url,
                rule_id="CORS_REFLECTS_ORIGIN_WITH_CREDENTIALS",
                title="CORS reflects arbitrary origin with credentials",
                severity="HIGH",
                category="CORS",
                description="The application reflected an untrusted Origin and allows credentials.",
                evidence=f"Access-Control-Allow-Origin: {allow_origin}; Access-Control-Allow-Credentials: {allow_credentials}",
                recommendation="Use an allowlist for trusted origins and avoid credentialed CORS unless required.",
            )
        )

    return findings


def check_forms(response: HttpResponse) -> list[Finding]:
    findings = []
    page_is_https = urllib.parse.urlparse(response.url).scheme == "https"

    for form_match in FORM_RE.finditer(response.body):
        attrs = parse_attrs(form_match.group("attrs"))
        body = form_match.group("body")
        method = attrs.get("method", "get").lower()
        action = attrs.get("action", response.url)
        form_url = urllib.parse.urljoin(response.url, action)
        inputs = [parse_attrs(input_match.group(1)) for input_match in INPUT_RE.finditer(body)]
        has_password = any(input_attrs.get("type", "").lower() == "password" for input_attrs in inputs)
        has_csrf = any(is_csrf_like(input_attrs.get("name", "")) for input_attrs in inputs)

        if has_password and not page_is_https:
            findings.append(
                make_finding(
                    response.url,
                    rule_id="PASSWORD_FORM_OVER_HTTP",
                    title="Password form served over HTTP",
                    severity="HIGH",
                    category="Forms",
                    description="A password input was found on a page served without HTTPS.",
                    evidence=f"Form action: {form_url}",
                    recommendation="Serve login and sensitive forms only over HTTPS.",
                )
            )

        if method == "post" and not has_csrf:
            findings.append(
                make_finding(
                    response.url,
                    rule_id="POST_FORM_NO_CSRF_TOKEN",
                    title="POST form without obvious CSRF token",
                    severity="LOW",
                    category="Forms",
                    description="A POST form was found without an input name that appears to contain a CSRF token.",
                    evidence=f"Form action: {form_url}",
                    recommendation="Verify whether CSRF protection exists server-side or add an anti-CSRF token.",
                )
            )

    return findings


def check_sensitive_paths(
    client: HttpClient,
    target_url: str,
    paths: list[str],
    requested_urls: list[str],
) -> list[Finding]:
    findings = []

    for path in paths:
        url = join_url(target_url, path)
        try:
            response = client.request(url)
            requested_urls.append(url)
        except HttpClientError:
            continue

        if response.status in {401, 403}:
            findings.append(
                make_finding(
                    url,
                    rule_id="INTERESTING_PATH_RESTRICTED",
                    title="Interesting path exists but is restricted",
                    severity="INFO",
                    category="Exposure",
                    description="A commonly interesting path exists but returned an access control response.",
                    evidence=f"HTTP {response.status} {response.reason}",
                    recommendation="Confirm access controls are expected and logs are monitored.",
                )
            )
        elif 200 <= response.status < 300:
            severity = "HIGH" if path in {"/.env", "/.git/config", "/phpinfo.php"} else "MEDIUM"
            findings.append(
                make_finding(
                    url,
                    rule_id="EXPOSED_INTERESTING_PATH",
                    title="Potentially exposed interesting path",
                    severity=severity,
                    category="Exposure",
                    description="A commonly sensitive or administrative path returned a successful response.",
                    evidence=f"{path} returned HTTP {response.status}",
                    recommendation="Verify whether this path should be public. Restrict, remove, or monitor it as appropriate.",
                )
            )

    return findings


def check_canary_reflection(
    client: HttpClient,
    target_url: str,
    requested_urls: list[str],
) -> list[Finding]:
    parsed = urllib.parse.urlparse(target_url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    query["audit_canary"] = [CANARY]
    canary_query = urllib.parse.urlencode(query, doseq=True)
    canary_url = urllib.parse.urlunparse(parsed._replace(query=canary_query))

    try:
        response = client.request(canary_url)
        requested_urls.append(canary_url)
    except HttpClientError:
        return []

    if CANARY not in response.body:
        return []

    return [
        make_finding(
            response.url,
            rule_id="CANARY_REFLECTED_IN_RESPONSE",
            title="Canary value reflected in response",
            severity="LOW",
            category="Input Reflection",
            description="A harmless canary query parameter was reflected in the HTTP response.",
            evidence=CANARY,
            recommendation="Manually verify context and output encoding. Reflection alone is not a confirmed XSS vulnerability.",
        )
    ]


def parse_attrs(value: str) -> dict[str, str]:
    return {name.lower(): attr_value for name, attr_value in ATTR_RE.findall(value)}


def is_csrf_like(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in ["csrf", "xsrf", "requesttoken", "authenticity_token"])


def make_finding(
    url: str,
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    evidence: str,
    recommendation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category=category,
        description=description,
        evidence=evidence[:500],
        recommendation=recommendation,
        url=url,
    )


def sort_findings(findings: list[Finding]) -> list[Finding]:
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    return sorted(findings, key=lambda finding: (severity_order.get(finding.severity, 0), finding.rule_id), reverse=True)
