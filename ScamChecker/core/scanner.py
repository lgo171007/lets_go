import re
import ipaddress
from urllib.parse import urlparse, unquote


class ScamScanner:

    SUSPICIOUS_TLDS = {
        ".xyz", ".top", ".click", ".work",
        ".buzz", ".rest", ".fit"
    }

    SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co",
        "is.gd", "cutt.ly", "shorturl.at"
    }

    SUSPICIOUS_WORDS = {
        "login", "verify", "account", "secure",
        "update", "password", "bank", "wallet",
        "free", "gift", "claim", "confirm"
    }

    def analyze_url(self, url):

        url = url.strip()

        if not url:
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
                raise ValueError("Invalid hostname")

        except ValueError:
            return {
                "status": "INVALID",
                "score": 0,
                "findings": ["Invalid URL format"]
            }

        score = 0
        findings = []

        def add_risk(points, message):
            nonlocal score
            score += points
            findings.append(message)

        # Check IP address hostname
        try:
            ipaddress.ip_address(host)
            add_risk(30, "URL uses an IP address instead of a domain")
        except ValueError:
            pass

        # Check URL shorteners
        if host.lower() in self.SHORTENERS:
            add_risk(20, "URL uses a link shortening service")

        # Check suspicious TLD
        if any(host.lower().endswith(tld)
               for tld in self.SUSPICIOUS_TLDS):
            add_risk(20, "Domain uses a commonly abused TLD")

        # Check punycode
        if "xn--" in host.lower():
            add_risk(25, "Domain contains Punycode")

        # Check @ symbol
        if "@" in url:
            add_risk(25, "URL contains an @ symbol")

        # Check excessive subdomains
        if len(host.split(".")) > 4:
            add_risk(15, "URL contains many subdomains")

        # Check suspicious keywords
        decoded_url = unquote(url).lower()

        matched_words = [
            word for word in self.SUSPICIOUS_WORDS
            if word in decoded_url
        ]

        if matched_words:
            add_risk(
                min(20, len(matched_words) * 5),
                "Suspicious keywords found: "
                + ", ".join(matched_words)
            )

        # Check URL length
        if len(url) > 100:
            add_risk(10, "Unusually long URL")

        # Check HTTP connection
        if parsed.scheme.lower() == "http":
            add_risk(10, "URL does not use HTTPS")

        score = min(score, 100)

        if score >= 60:
            status = "HIGH RISK"
        elif score >= 30:
            status = "SUSPICIOUS"
        else:
            status = "LOW RISK"

        if not findings:
            findings.append("No obvious suspicious patterns detected")

        return {
            "url": url,
            "domain": host,
            "status": status,
            "score": score,
            "findings": findings
        }


if __name__ == "__main__":

    scanner = ScamScanner()

    print("=" * 40)
    print("       SCAMCHECKER SCANNER")
    print("=" * 40)

    target = input("Enter URL: ")

    result = scanner.analyze_url(target)

    print("\n========== SCAN REPORT ==========")
    print("URL:", result.get("url", target))
    print("Domain:", result.get("domain", "N/A"))
    print("Status:", result["status"])
    print("Risk Score:", str(result["score"]) + "/100")

    print("\nFindings:")

    for item in result["findings"]:
        print("-", item)

    print("\nNote: This is a heuristic analysis.")
    print("It cannot guarantee that a URL is safe.")
    print("=" * 40)
