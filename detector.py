from datetime import datetime, timedelta


def parse_timestamp(timestamp: str) -> datetime:
    date = datetime.strptime(f"{timestamp} 2026", "%b %d %H:%M:%S %Y")
    return date.replace(year=2026)


def within_time_window(first_timestamp: datetime, second_timestamp: datetime, minutes: int = 2) -> bool:
    return abs(second_timestamp - first_timestamp) <= timedelta(minutes=minutes)


def group_failed_logins(logs: list[dict]) -> dict:
    failed_logins = {}
    for log in logs:
        if log["event_type"] == "failed_login":
            ip = log["ip_address"]
            timestamp = log["timestamp"]
            if ip not in failed_logins:
                failed_logins[ip] = [timestamp]
            else:
                failed_logins[ip].append(timestamp)
    return failed_logins


def detect_brute_force(logs: list[dict]) -> list:
    failed_logins = group_failed_logins(logs)
    alerts = []
    for ip, timestamps in failed_logins.items():
        if len(timestamps) >= 5:
            for i in range(len(timestamps) - 4):
                first = parse_timestamp(timestamps[i])
                fifth = parse_timestamp(timestamps[i + 4])
                if within_time_window(first, fifth):
                    alert = {
                        "type": "brute_force",
                        "severity": "HIGH",
                        "ip_address": ip,
                        "attempts": 5,
                        "start_time": first,
                        "end_time": fifth,
                        "mitre_attack": {
                            "technique_id": "T1110",
                            "technique": "Brute Force"
                        }
                    }
                    alerts.append(alert)
                    break
    return alerts


def group_events_by_ip(logs: list[dict]) -> dict:
    events_by_ip = {}
    for log in logs:
        ip = log["ip_address"]
        if ip not in events_by_ip:
            events_by_ip[ip] = [log]
        else:
            events_by_ip[ip].append(log)
    return events_by_ip


def detect_success_after_failure(logs: list[dict]) -> list:
    events_by_ip = group_events_by_ip(logs)
    alerts = []
    for ip, events in events_by_ip.items():
        failed_attempts = []
        for event in events:
            if event["event_type"] == "failed_login":
                failed_attempts.append(event)
            elif event["event_type"] == "successful_login":
                if len(failed_attempts) >= 3:
                    third_last_failure = failed_attempts[-3]
                    failure_time = parse_timestamp(third_last_failure["timestamp"])
                    success_time = parse_timestamp(event["timestamp"])
                    if within_time_window(failure_time, success_time, minutes=5):
                        alert ={
                            "type": "successful_login_after_failure",
                            "severity": "HIGH",
                            "ip_address": ip,
                            "username": event["username"],
                            "failed_attempts": len(failed_attempts),
                            "window_start": failure_time,
                            "successful_login": success_time
                        }
                        alerts.append(alert)
                failed_attempts.clear()
    return alerts


def detect_multiple_accounts(logs: list[dict]) -> list:
    events_by_ip = group_events_by_ip(logs)
    alerts = []
    for ip, events in events_by_ip.items():
        failed_events = []
        for event in events:
            if event["event_type"] == "failed_login":
                failed_events.append(event)
        failed_events.sort(key=lambda event: parse_timestamp(event["timestamp"]))
        alert_found = False
        for i in range(len(failed_events)):
            first_time = parse_timestamp(failed_events[i]["timestamp"])
            usernames = set()
            for j in range(i, len(failed_events)):
                event_time = parse_timestamp(failed_events[j]["timestamp"])
                if within_time_window(first_time, event_time, minutes=5):
                    usernames.add(failed_events[j]["username"])
                    if len(usernames) >= 3:
                        alert = {
                            "type": "multiple_accounts_targeted",
                            "severity": "MEDIUM",
                            "ip_address": ip,
                            "accounts_targeted": len(usernames),
                            "usernames": list(usernames)
                        }
                        alerts.append(alert)
                        alert_found = True
                        break
            if alert_found:
                break
    return alerts
