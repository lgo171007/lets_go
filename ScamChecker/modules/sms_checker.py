import re


class SMSChecker:

    RULES = [
        (
            r"\b(otp|one.time.password|verification code)\b",
            20,
            "Message mentions an OTP or verification code"
        ),
        (
            r"\b(pin|password|passcode)\b",
            25,
            "Message mentions sensitive credentials"
        ),
        (
            r"\b(prize|lottery|winner|jackpot|free gift)\b",
            20,
            "Possible fake prize or lottery message"
        ),
        (
            r"\b(urgent|immediately|act now|limited time)\b",
            15,
            "Message uses urgency tactics"
        ),
        (
            r"\b(send money|pay now|transfer money)\b",
            25,
            "Message requests a financial transaction"
        ),
        (
            r"\b(account suspended|account blocked|verify account)\b",
            20,
            "Possible account impersonation"
        ),
        (
            r"\b(bank details|card details|cvv)\b",
            25,
            "Message mentions sensitive financial details"
        )
    ]

    LINK_PATTERN = re.compile(
        r"https?://\S+|www\.\S+",
        re.IGNORECASE
    )

    def analyze(self, message):

        if not isinstance(message, str) or not message.strip():
            return {
                "status": "INVALID",
                "score": 0,
                "findings": ["Empty or invalid message"]
            }

        text = message.lower()
        score = 0
        findings = []

        for pattern, points, description in self.RULES:

            if re.search(pattern, text):
                score += points
                findings.append(description)

        if self.LINK_PATTERN.search(message):
            score += 20
            findings.append("Message contains a web link")

        score = min(score, 100)

        if score >= 60:
            status = "HIGH RISK"
        elif score >= 30:
            status = "SUSPICIOUS"
        else:
            status = "LOW RISK"

        if not findings:
            findings.append(
                "No obvious scam patterns detected"
            )

        return {
            "status": status,
            "score": score,
            "findings": findings
        }


if __name__ == "__main__":

    checker = SMSChecker()

    print("=" * 40)
    print("       SCAMCHECKER SMS ANALYZER")
    print("=" * 40)

    message = input("Enter SMS message: ")

    result = checker.analyze(message)

    print("\n========== SMS REPORT ==========")
    print("Status:", result["status"])
    print("Risk Score:", result["score"], "/100")

    print("\nFindings:")

    for finding in result["findings"]:
        print("-", finding)

    print("\nNote: Heuristic analysis only.")
    print("Do not share OTP, PIN or passwords.")
    print("=" * 40)
