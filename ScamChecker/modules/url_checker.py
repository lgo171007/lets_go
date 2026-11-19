
import re
from urllib.parse import urlparse
from ipaddress import ip_address

from core.scanner import ScamScanner


class URLChecker:

    def __init__(self):
        self.scanner = ScamScanner()

    def validate_url(self, url):

        if not isinstance(url, str) or not url.strip():
            return False, "URL cannot be empty"

        url = url.strip()

        if re.search(r"\s", url):
            return False, "URL contains whitespace"

        if not re.match(r"^https?://", url, re.I):
            url = "https://" + url

        try:
            parsed = urlparse(url)

            if parsed.scheme not in ("http", "https"):
                return False, "Unsupported URL scheme"

            if not parsed.hostname:
                return False, "Invalid hostname"

            if parsed.username or parsed.password:
                return False, "URL contains embedded credentials"

            # Validate IP or domain format
            try:
                ip_address(parsed.hostname)
            except ValueError:
                domain = parsed.hostname

                if (
                    len(domain) > 253
                    or "." not in domain
                    or any(
                        not label
                        or len(label) > 63
                        or label.startswith("-")
                        or label.endswith("-")
                        or not re.fullmatch(
                            r"[A-Za-z0-9-]+", label
                        )
                        for label in domain.rstrip(".").split(".")
                    )
                ):
                    return False, "Invalid domain format"

            # Validate port
            try:
                parsed.port
            except ValueError:
                return False, "Invalid port"

            return True, url

        except ValueError:
            return False, "Malformed URL"

    def check(self, url):

        valid, result = self.validate_url(url)

        if not valid:
            return {
                "valid": False,
                "status": "INVALID",
                "score": 0,
                "findings": [result]
            }

        report = self.scanner.analyze_url(result)

        report["valid"] = True

        return report


if __name__ == "__main__":

    checker = URLChecker()

    print("=" * 40)
    print("       SCAMCHECKER URL CHECKER")
    print("=" * 40)

    target = input("Enter URL to check: ")

    result = checker.check(target)

    print("\n========== URL REPORT ==========")
    print("Valid:", result["valid"])
    print("Status:", result["status"])
    print("Risk Score:", result["score"], "/100")

    print("\nFindings:")

    for finding in result["findings"]:
        print("-", finding)

    print("=" * 40)
