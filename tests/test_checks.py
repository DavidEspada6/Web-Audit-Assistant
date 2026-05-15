import unittest

from web_audit_assistant.checks import check_cookies, check_forms, check_security_headers
from web_audit_assistant.models import Header, HttpResponse


class CheckTests(unittest.TestCase):
    def test_missing_security_headers_are_reported(self):
        response = response_for("https://example.test", headers=[])

        findings = check_security_headers(response)

        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("MISSING_CONTENT_SECURITY_POLICY", rule_ids)
        self.assertIn("MISSING_STRICT_TRANSPORT_SECURITY", rule_ids)

    def test_cookie_flags_are_reported(self):
        response = response_for(
            "https://example.test",
            headers=[Header("Set-Cookie", "session=abc123; Path=/")],
        )

        findings = check_cookies(response)

        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("COOKIE_MISSING_SECURE", rule_ids)
        self.assertIn("COOKIE_MISSING_HTTPONLY", rule_ids)
        self.assertIn("COOKIE_MISSING_SAMESITE", rule_ids)

    def test_password_form_over_http_is_reported(self):
        response = response_for(
            "http://example.test/login",
            body='<form method="post"><input type="password" name="password"></form>',
        )

        findings = check_forms(response)

        self.assertTrue(any(finding.rule_id == "PASSWORD_FORM_OVER_HTTP" for finding in findings))


def response_for(url: str, headers=None, body: str = "") -> HttpResponse:
    return HttpResponse(
        url=url,
        status=200,
        reason="OK",
        headers=headers or [],
        body=body,
        elapsed_ms=1.0,
    )


if __name__ == "__main__":
    unittest.main()

