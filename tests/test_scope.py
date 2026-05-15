import unittest

from web_audit_assistant.scope import build_scope_policy


class ScopeTests(unittest.TestCase):
    def test_allows_exact_host_and_subdomain(self):
        scope = build_scope_policy(["example.com"])

        self.assertTrue(scope.is_allowed_url("https://example.com"))
        self.assertTrue(scope.is_allowed_url("https://app.example.com/login"))

    def test_blocks_out_of_scope_host(self):
        scope = build_scope_policy(["example.com"])

        self.assertFalse(scope.is_allowed_url("https://evil-example.com"))
        self.assertFalse(scope.is_allowed_url("https://example.org"))


if __name__ == "__main__":
    unittest.main()

