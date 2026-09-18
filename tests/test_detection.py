from src.logsentinel import SecurityEvent, detect_multi_account_targeting


def test_detects_multi_account_targeting():
    events = [
        SecurityEvent("Sep 08 18:00:01", "admin", "203.0.113.42", False),
        SecurityEvent("Sep 08 18:00:02", "root", "203.0.113.42", False),
        SecurityEvent("Sep 08 18:00:03", "guest", "203.0.113.42", False),
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
        SecurityEvent("Sep 08 18:00:01", "admin", "203.0.113.42", False),
        SecurityEvent("Sep 08 18:00:02", "root", "203.0.113.42", False),
    ]

    alerts = detect_multi_account_targeting(
        events,
        min_unique_users=3,
    )

    assert len(alerts) == 0