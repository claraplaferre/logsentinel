from datetime import datetime
from src.logsentinel import SecurityEvent, detect_multi_account_targeting


def test_detects_multi_account_targeting():
    events = [
        SecurityEvent(datetime(2026, 9, 8, 18, 0, 1), "admin", "203.0.113.42", False),
        SecurityEvent(datetime(2026, 9, 8, 18, 0, 2), "root", "203.0.113.42", False),
        SecurityEvent(datetime(2026, 9, 8, 18, 0, 3), "guest", "203.0.113.42", False),
    ]   

    alerts = detect_multi_account_targeting(
        events,
        min_unique_users=3,
    )

    assert len(alerts) == 1
    assert alerts[0].rule_id == "LS-001"
    assert alerts[0].source_ip == "203.0.113.42"
    assert alerts[0].failed_attempts == 3
    assert alerts[0].targeted_users == {"admin", "root", "guest"}

def test_does_not_alert_below_threshold():
    events = [
        SecurityEvent(datetime(2026, 9, 8, 18, 0, 1), "admin", "203.0.113.42", False),
        SecurityEvent(datetime(2026, 9, 8, 18, 0, 2), "root", "203.0.113.42", False),
    ]

    alerts = detect_multi_account_targeting(
        events,
        min_unique_users=3,
    )

    assert len(alerts) == 0

def test_does_not_alert_outside_time_window():
    events = [
        SecurityEvent(
            datetime(2026, 9, 8, 18, 0, 0),
            "admin",
            "203.0.113.42",
            False,
        ),
        SecurityEvent(
            datetime(2026, 9, 8, 18, 2, 0),
            "root",
            "203.0.113.42",
            False,
        ),
        SecurityEvent(
            datetime(2026, 9, 8, 18, 4, 0),
            "guest",
            "203.0.113.42",
            False,
        ),
    ]

    alerts = detect_multi_account_targeting(
        events,
        min_unique_users=3,
        time_window_seconds=60,
    )

    assert len(alerts) == 0

def test_detects_suspicious_cluster_despite_later_activity():
    events = [
        SecurityEvent(
            datetime(2026, 9, 8, 10, 0, 0),
            "admin",
            "203.0.113.42",
            False,
        ),
        SecurityEvent(
            datetime(2026, 9, 8, 10, 0, 10),
            "root",
            "203.0.113.42",
            False,
        ),
        SecurityEvent(
            datetime(2026, 9, 8, 10, 0, 20),
            "guest",
            "203.0.113.42",
            False,
        ),

        # Unrelated activity much later
        SecurityEvent(
            datetime(2026, 9, 8, 14, 0, 0),
            "admin",
            "203.0.113.42",
            False,
        ),
    ]

    alerts = detect_multi_account_targeting(
        events,
        min_unique_users=3,
        time_window_seconds=60,
    )

    assert len(alerts) == 1
    assert alerts[0].source_ip == "203.0.113.42"
    assert alerts[0].targeted_users == {"admin", "root", "guest"}