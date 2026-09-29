import re

def read_logs(file_path) -> list:
    logs_list = []
    with open(file_path, "r") as file:
        for line in file:
            logs_list.append(line.strip())
    return logs_list

def extract_ip(log_line: str) -> str | None:
    ip_address = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_line)
    if ip_address:
        return ip_address.group()
    return None

def print_ips():
    for log in read_logs("logs/sample_auth.log"):
        print(extract_ip(log))

print_ips()

def extract_event_type(log_line: str) -> str | None:
    if "Failed password" in log_line:
        return "failed_login"
    elif "Accepted password" in log_line:
        return "successful_login"
    else:
        return None

def extract_username(log_line: str) -> str | None:
    username = re.search(r"password for (\w+) from", log_line)
    if username:
        return username.group(1)
    return None

def extract_timestamp(log_line: str) -> str | None:
    timestamp = re.search(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", log_line)
    if timestamp:
        return timestamp.group(1)
    return None

def parse_log(log_line: str) -> dict:
    timestamp = extract_timestamp(log_line)
    ip = extract_ip(log_line)
    username = extract_username(log_line)
    event_type = extract_event_type(log_line)
    log_dict = {
        "timestamp": timestamp,
        "ip_address": ip,
        "username": username,
        "event_type": event_type
    }
    return log_dict

for log in read_logs("logs/sample_auth.log"):
    print(parse_log(log))
