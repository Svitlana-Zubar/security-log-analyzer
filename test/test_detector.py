from detector import (
detect_brute_force,
detect_success_after_failure,
detect_multiple_accounts
)

def test_detect_brute_force():
    logs = [
        {
            "timestamp": "Sep 29 10:00:00",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:00:20",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:00:40",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:01:00",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:01:20",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        }
    ]

    alerts = detect_brute_force(logs)
    assert len(alerts) == 1
    assert alerts[0]["type"] == "brute_force"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["ip_address"] == "192.168.1.50"
    assert alerts[0]["attempts"] == 5

def test_no_brute_force_below_threshold():
    logs = [
        {
            "timestamp": "Sep 29 10:00:00",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:00:20",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:00:40",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:01:00",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        }
    ]

    alerts = detect_brute_force(logs)

    assert len(alerts) == 0

def test_detect_success_after_failure():
    logs = [
        {
            "timestamp": "Sep 29 10:00:00",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:01:00",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:02:00",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:03:00",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "successful_login"
        }
    ]

    alerts = detect_success_after_failure(logs)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "successful_login_after_failure"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["ip_address"] == "192.168.1.50"
    assert alerts[0]["username"] == "admin"
    assert alerts[0]["failed_attempts"] == 3

def test_no_success_after_failure_below_threshold():
    logs = [
        {
            "timestamp": "Sep 29 10:00:00",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:01:00",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:02:00",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "successful_login"
        }
    ]

    alerts = detect_success_after_failure(logs)

    assert len(alerts) == 0

def test_no_success_after_failure_outside_time_window():
    logs = [
        {
            "timestamp": "Sep 29 10:00:00",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:01:00",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:02:00",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:10:00",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "successful_login"
        }
    ]

    alerts = detect_success_after_failure(logs)

    assert len(alerts) == 0

def test_detect_multiple_accounts():
    logs = [
        {
            "timestamp": "Sep 29 10:00:00",
            "ip_address": "192.168.1.50",
            "username": "lana",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:01:00",
            "ip_address": "192.168.1.50",
            "username": "root",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:02:00",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        }
    ]

    alerts = detect_multiple_accounts(logs)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "multiple_accounts_targeted"
    assert alerts[0]["severity"] == "MEDIUM"
    assert alerts[0]["ip_address"] == "192.168.1.50"
    assert alerts[0]["accounts_targeted"] == 3
    assert set(alerts[0]["usernames"]) == {"admin", "root", "lana"}

def test_no_multiple_accounts_below_threshold():
    logs = [
        {
            "timestamp": "Sep 29 10:01:00",
            "ip_address": "192.168.1.50",
            "username": "root",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:02:00",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        }
    ]

    alerts = detect_multiple_accounts(logs)

    assert len(alerts) == 0

def test_no_multiple_accounts_outside_time_window():
    logs = [
        {
            "timestamp": "Sep 29 10:01:00",
            "ip_address": "192.168.1.50",
            "username": "root",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:02:00",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_type": "failed_login"
        },
        {
            "timestamp": "Sep 29 10:10:00",
            "ip_address": "192.168.1.50",
            "username": "lana",
            "event_type": "failed_login"
        }
    ]

    alerts = detect_multiple_accounts(logs)

    assert len(alerts) == 0