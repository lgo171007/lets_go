
from modules.url_checker import URLChecker
from modules.sms_checker import SMSChecker
from modules.phishing_checker import PhishingChecker


def main():
    while True:
        print("\n" + "=" * 40)
        print("       SCAM CHECKER")
        print("=" * 40)
        print("1. URL Checker")
        print("2. SMS Scam Checker")
        print("3. Phishing Checker")
        print("4. Exit")
        print("=" * 40)

        choice = input("Select an option: ").strip()

        if choice == "1":
            url = input("Enter URL: ").strip()
            checker = URLChecker()
            print(checker.analyze(url))

        elif choice == "2":
            message = input("Enter SMS message: ").strip()
            checker = SMSChecker()
            print(checker.analyze(message))

        elif choice == "3":
            url = input("Enter URL: ").strip()
            checker = PhishingChecker()
            print(checker.analyze(url))

        elif choice == "4":
            print("Thank you for using Scam Checker!")
            break

        else:
            print("Invalid option! Try again.")


if __name__ == "__main__":
    main()

