import unittest
from modules.sms_checker import SMSChecker
from modules.phishing_checker import PhishingChecker


class TestSMSChecker(unittest.TestCase):

    def setUp(self):
        self.checker = SMSChecker()

    def test_normal_message(self):
        result = self.checker.analyze(
            "Hello! How are you? See you tomorrow."
        )
        self.assertIsInstance(result, dict)
        self.assertIn("score", result)
        self.assertIn("status", result)

    def test_suspicious_message(self):
        result = self.checker.analyze(
            "URGENT! Your account is blocked. Verify your password immediately."
        )
        self.assertGreater(result["score"], 0)


class TestPhishingChecker(unittest.TestCase):

    def setUp(self):
        self.checker = PhishingChecker()

    def test_normal_url(self):
        result = self.checker.analyze("https://example.com")
        self.assertIsInstance(result, dict)
        self.assertIn("score", result)
        self.assertIn("status", result)

    def test_suspicious_url(self):
        result = self.checker.analyze(
            "http://account-verify.example.test"
        )
        self.assertGreater(result["score"], 0)


if __name__ == "__main__":
    unittest.main()
