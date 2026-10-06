from detector import (
detect_brute_force,
detect_success_after_failure,
detect_multiple_accounts
)

import json


def analyze_logs(logs: list[dict]) -> list:
    alerts = []

    alerts.extend(detect_brute_force(logs))
    alerts.extend(detect_success_after_failure(logs))
    alerts.extend(detect_multiple_accounts(logs))
    return alerts


def save_report(alerts: list[dict], file_path: str) -> None:
    with open(file_path, "w") as file:
        json.dump(obj=alerts, fp=file, default=str, indent=4)

