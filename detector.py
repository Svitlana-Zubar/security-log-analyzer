from datetime import datetime, timedelta

from parser import read_logs, parse_log

def parse_timestamp(timestamp: str) -> datetime:
    date = datetime.strptime(f"{timestamp} 2026", "%b %d %H:%M:%S %Y")
    return date.replace(year=2026)

print(parse_timestamp("Sep 29 10:05:12"))

def within_time_window(first_timestamp: datetime, second_timestamp: datetime, minutes: int = 2) -> bool:
    return abs(second_timestamp - first_timestamp) <= timedelta(minutes=minutes)

first = parse_timestamp("Sep 29 10:05:12")
second = parse_timestamp("Sep 29 10:06:04")
third = parse_timestamp("Sep 29 10:10:00")

print(within_time_window(first, second))
print(within_time_window(first, third))
print(within_time_window(first, first))

def count_failed_logins(logs: list[dict]) -> dict:
    failed_logs_count = {}
    for log in logs:
        if log["event_type"] == "failed_login":
            ip = log["ip_address"]
            if ip in failed_logs_count:
                failed_logs_count[ip] += 1
            else:
                failed_logs_count[ip] = 1
    return failed_logs_count

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
                        "end_time": fifth
                    }
                    alerts.append(alert)
                    break
    return alerts

logs = []
for line in read_logs("logs/sample_auth.log"):
    logs.append(parse_log(line))

print(detect_brute_force(logs))