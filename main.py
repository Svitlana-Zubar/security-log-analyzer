from parser import read_logs, parse_log
from reporter import analyze_logs, save_report
import argparse





def main():
    parser = argparse.ArgumentParser(
        description="Analyse SSH authentication logs for suspicious activity."
    )

    parser.add_argument(
        "input_file",
        help="Path to the SSH authentication log file"
    )

    parser.add_argument(
        "--output",
        default="reports/security_report.json",
        help="Path for the generated JSON security report"
    )

    args = parser.parse_args()

    lines = read_logs(args.input_file)
    logs = []

    for line in lines:
        logs.append(parse_log(line))

    alerts = analyze_logs(logs)

    save_report(alerts, args.output)

    print("Analysis complete.")
    print(f"{len(alerts)} security alerts detected.")
    print(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()