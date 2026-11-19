
import re
from urllib.parse import urlparse, unquote


class PhishingChecker:

    BRANDS = [
        "google", "facebook", "instagram",
        "paypal", "microsoft", "apple",
        "amazon", "netflix", "telegram"
    ]

    LOGIN_WORDS = [
        "login", "signin", "sign-in",
        "verify", "account", "password",
        "credential", "authentication"
    ]

    def analyze(self, url):

        if not isinstance(url, str) or not url.strip():
            return {
                "status": "INVALID",
                "score": 0,
                "findings": ["Empty URL"]
            }

        if not re.match(r"^https?://", url, re.I):
            url = "https://" + url

        try:
            parsed = urlparse(url)
            host = parsed.hostname

            if not host:
                raise ValueError()

        except ValueError:
            return {
                "status": "INVALID",
                "score": 0,
                "findings": ["Invalid URL"]
            }

        score = 0
        findings = []
        domain = host.lower()
        full_url = unquote(url).lower()

        def flag(points, message):
            nonlocal score
            score += points
            findings.append(message)

        # Check brand names in suspicious domains
        for brand in self.BRANDS:
            if brand in domain:
                legitimate_domains = {
                    "google": ["google.com"],
                    "facebook": ["facebook.com"],
                    "instagram": ["instagram.com"],
                    "paypal": ["paypal.com"],
                    "microsoft": ["microsoft.com"],
                    "apple": ["apple.com"],
                    "amazon": ["amazon.com"],
                    "netflix": ["netflix.com"],
                    "telegram": ["telegram.org"]
                }

                if not any(
                    domain == d or domain.endswith("." + d)
                    for d in legitimate_domains[brand]
                ):
                    flag(
                        30,
                        "Possible brand impersonation: " + brand
                    )

        # Login-related words
        matches = [
            word for word in self.LOGIN_WORDS
            if word in full_url
        ]

        if matches:
            flag(
                min(25, len(matches) * 5),
                "Login-related terms found: " + ", ".join(matches)
            )

        # URL encoding
        if "%" in url:
            flag(10, "URL contains encoded characters")

        # Excessive subdomains
        if len(domain.split(".")) > 4:
            flag(15, "Unusually many subdomains")

        # HTTPS check
        if parsed.scheme.lower() != "https":
            flag(10, "Connection does not use HTTPS")

        # Suspicious @ character
        if "@" in url:
            flag(20, "URL contains an @ symbol")

        score = min(score, 100)

        if score >= 50:
            status = "HIGH RISK"
        elif score >= 20:
            status = "SUSPICIOUS"
        else:
            status = "LOW RISK"

        if not findings:
            findings.append(
                "No obvious phishing indicators detected"
            )

        return {
            "url": url,
            "domain": domain,
            "status": status,
            "score": score,
            "findings": findings
        }


if __name__ == "__main__":

    checker = PhishingChecker()

    print("=" * 40)
    print("     PHISHING DETECTOR")
    print("=" * 40)

    target = input("Enter URL: ")

    result = checker.analyze(target)

    print("\n========== REPORT ==========")
    print("Status:", result["status"])
    print("Risk Score:", result["score"], "/100")

    for finding in result["findings"]:
        print("-", finding)

    print("=" * 40)
