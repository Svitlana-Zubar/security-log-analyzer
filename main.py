from parser import read_logs, parse_log
from reporter import analyze_logs, save_report


def main():
    lines = read_logs("logs/sample_auth.log")
    logs = []

    for line in lines:
        logs.append(parse_log(line))

    alerts = analyze_logs(logs)

    save_report(alerts, "reports/security_report.json")


if __name__ == "__main__":
    main()