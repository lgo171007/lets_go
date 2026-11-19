import unittest
from core.scanner import ScamScanner


class TestScamScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = ScamScanner()

    def test_safe_url(self):
        result = self.scanner.analyze_url("https://example.com")
        self.assertIsInstance(result, dict)
        self.assertIn("score", result)
        self.assertIn("status", result)

    def test_http_url(self):
        result = self.scanner.analyze_url("http://example.com")
        self.assertGreaterEqual(result["score"], 0)

    def test_invalid_url(self):
        result = self.scanner.analyze_url("not-a-valid-url")
        self.assertIsInstance(result, dict)

    def test_ip_address_url(self):
        result = self.scanner.analyze_url("http://192.0.2.1")
        self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main()
