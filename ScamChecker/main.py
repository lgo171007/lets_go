
from modules.url_checker import URLChecker
from modules.sms_checker import SMSChecker
from modules.phishing_checker import PhishingChecker

# Terminal Colors
RESET = "\033[0m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RED = "\033[91m"
YELLOW = "\033[93m"
WHITE = "\033[97m"
BOLD = "\033[1m"


def banner():
    print(CYAN + r"""
   _____ ____    _    __  __
  / ____/ ___|  / \  |  \/  |
 | (___ \___ \ / _ \ | \  / |
  \___ \ ___) / ___ \| |\/| |
  ____) |____/_/   \_\_|  |_|
 |_____/

       S C A M   C H E C K E R
       Detect | Prevent | Stay Safe
""" + RESET)


def show_menu():
    print(CYAN + "=" * 42)
    print("              MAIN MENU")
    print("=" * 42 + RESET)

    print(GREEN + " [1] " + WHITE + "URL Checker")
    print(GREEN + " [2] " + WHITE + "SMS Scam Checker")
    print(GREEN + " [3] " + WHITE + "Phishing Checker")
    print(RED + " [4] " + WHITE + "Exit")
    print(CYAN + "=" * 42 + RESET)


def show_report(result):
    print("\n" + CYAN + "=" * 42)
    print("                SCAN REPORT")
    print("=" * 42 + RESET)

    if not isinstance(result, dict):
        print(YELLOW + str(result) + RESET)
        return

    status = result.get("status", "UNKNOWN")
    score = result.get("score", 0)

    if status == "LOW RISK":
        color = GREEN
    elif status == "SUSPICIOUS":
        color = YELLOW
    else:
        color = RED

    print(WHITE + " Status : " + color + BOLD + str(status) + RESET)
    print(WHITE + " Score  : " + YELLOW + str(score) + RESET)

    if "domain" in result:
        print(WHITE + " Domain : " + CYAN + str(result["domain"]) + RESET)

    if "valid" in result:
        print(WHITE + " Valid  : " + str(result["valid"]) + RESET)

    print(CYAN + "\n Findings:" + RESET)

    findings = result.get("findings", [])

    if findings:
        for item in findings:
            print(YELLOW + "  [!] " + WHITE + str(item) + RESET)
    else:
        print(GREEN + "  [+] No findings reported" + RESET)

    print(CYAN + "=" * 42 + RESET)
    print(YELLOW + " Note: This is a heuristic-based result.")
    print("It cannot guarantee that a message or URL is safe." + RESET)


def main():
    while True:
        banner()
        show_menu()

        choice = input(CYAN + "\n Select an option: " + GREEN).strip()
        print(RESET)

        try:
            if choice == "1":
                url = input(" Enter URL: ").strip()

                if not url:
                    print(RED + " URL cannot be empty!" + RESET)
                    continue

                checker = URLChecker()
                result = checker.check(url)
                show_report(result)

            elif choice == "2":
                message = input(" Enter SMS message: ").strip()

                if not message:
                    print(RED + " Message cannot be empty!" + RESET)
                    continue

                checker = SMSChecker()
                result = checker.analyze(message)
                show_report(result)

            elif choice == "3":
                url = input(" Enter URL: ").strip()

                if not url:
                    print(RED + " URL cannot be empty!" + RESET)
                    continue

                checker = PhishingChecker()
                result = checker.analyze(url)
                show_report(result)

            elif choice == "4":
                print(GREEN + "\n Thank you for using Scam Checker!")
                print(" Stay Alert. Think Before You Click!\n" + RESET)
                break

            else:
                print(RED + " Invalid option! Try again." + RESET)

        except Exception as error:
            print(RED + "\n An error occurred: " + str(error) + RESET)

        input(CYAN + "\n Press Enter to continue..." + RESET)


if __name__ == "__main__":
    main()

