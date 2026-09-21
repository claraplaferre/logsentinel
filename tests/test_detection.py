from datetime import datetime

from src.logsentinel.models import SecurityEvent

from src.logsentinel.detection import (
    detect_multi_account_targeting,
    detect_repeated_failures,
    get_time_windows,
)

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

def test_detects_repeated_failures():
    events = [
        SecurityEvent(
            datetime(2026, 9, 8, 18, 0, 0),
            "root",
            "203.0.113.50",
            False,
        ),
        SecurityEvent(
            datetime(2026, 9, 8, 18, 0, 10),
            "root",
            "203.0.113.50",
            False,
        ),
        SecurityEvent(
            datetime(2026, 9, 8, 18, 0, 20),
            "root",
            "203.0.113.50",
            False,
        ),
        SecurityEvent(
            datetime(2026, 9, 8, 18, 0, 30),
            "root",
            "203.0.113.50",
            False,
        ),
        SecurityEvent(
            datetime(2026, 9, 8, 18, 0, 40),
            "root",
            "203.0.113.50",
            False,
        ),
    ]

    alerts = detect_repeated_failures(
        events,
        min_failed_attempts=5,
        time_window_seconds=60,
    )

    assert len(alerts) == 1
    assert alerts[0].rule_id == "LS-002"
    assert alerts[0].source_ip == "203.0.113.50"
    assert alerts[0].failed_attempts == 5

def test_repeated_failures_below_threshold_does_not_alert():
    events = [
        SecurityEvent(
            datetime(2026, 9, 8, 18, 0, 0),
            "root",
            "203.0.113.50",
            False,
        ),
        SecurityEvent(
            datetime(2026, 9, 8, 18, 0, 10),
            "root",
            "203.0.113.50",
            False,
        ),
        SecurityEvent(
            datetime(2026, 9, 8, 18, 0, 20),
            "root",
            "203.0.113.50",
            False,
        ),
        SecurityEvent(
            datetime(2026, 9, 8, 18, 0, 30),
            "root",
            "203.0.113.50",
            False,
        ),
    ]

    alerts = detect_repeated_failures(
        events,
        min_failed_attempts=5,
        time_window_seconds=60,
    )

    assert len(alerts) == 0

def test_repeated_failures_outside_time_window_does_not_alert():
    events = [
        SecurityEvent(
            datetime(2026, 9, 8, 18, 0, 0),
            "root",
            "203.0.113.50",
            False,
        ),
        SecurityEvent(
            datetime(2026, 9, 8, 18, 1, 0),
            "root",
            "203.0.113.50",
            False,
        ),
        SecurityEvent(
            datetime(2026, 9, 8, 18, 2, 0),
            "root",
            "203.0.113.50",
            False,
        ),
        SecurityEvent(
            datetime(2026, 9, 8, 18, 3, 0),
            "root",
            "203.0.113.50",
            False,
        ),
        SecurityEvent(
            datetime(2026, 9, 8, 18, 4, 0),
            "root",
            "203.0.113.50",
            False,
        ),
    ]

    alerts = detect_repeated_failures(
        events,
        min_failed_attempts=5,
        time_window_seconds=60,
    )

    assert len(alerts) == 0

def test_get_time_windows_groups_events_within_window():
    events = [
        SecurityEvent(
            datetime(2026, 9, 8, 18, 0, 0),
            "root",
            "203.0.113.50",
            False,
        ),
        SecurityEvent(
            datetime(2026, 9, 8, 18, 0, 10),
            "root",
            "203.0.113.50",
            False,
        ),
        SecurityEvent(
            datetime(2026, 9, 8, 18, 0, 20),
            "root",
            "203.0.113.50",
            False,
        ),
        SecurityEvent(
            datetime(2026, 9, 8, 18, 2, 0),
            "root",
            "203.0.113.50",
            False,
        ),
    ]

    windows = get_time_windows(
        events,
        time_window_seconds=60,
    )

    assert len(windows[0]) == 3
    assert len(windows[1]) == 2
    assert len(windows[2]) == 1
    assert len(windows[3]) == 1
