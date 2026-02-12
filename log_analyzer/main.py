from reader import load_log_gen
from reporter import generate_report, log_analyze
from config import save_report


def main():
    suspicious = log_analyze("./network_traffic.log")
    report = generate_report(suspicious)
    print(report)
    save_report(report, "security_report.txt")
    print("\n\tThe report was successfully updated!")


if __name__ == "__main__":
    main()