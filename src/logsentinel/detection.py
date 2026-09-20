from datetime import timedelta

from .models import SecurityEvent, SecurityAlert


def detect_multi_account_targeting(
    events: list[SecurityEvent],
    min_unique_users: int = 3,
    time_window_seconds: int = 60,
) -> list[SecurityAlert]:

    failed_by_ip = {}

    for event in events:
        if event.success:
            continue

        if event.source_ip not in failed_by_ip:
            failed_by_ip[event.source_ip] = []

        failed_by_ip[event.source_ip].append(event)

    alerts = []

    for source_ip, ip_events in failed_by_ip.items():
        ip_events.sort(key=lambda event: event.timestamp)

        for start_index, start_event in enumerate(ip_events):
            window_events = []

            for event in ip_events[start_index:]:
                if event.timestamp - start_event.timestamp > timedelta(
                    seconds=time_window_seconds
                ):
                    break

                window_events.append(event)

            targeted_users = {
                event.username
                for event in window_events
            }

            if len(targeted_users) < min_unique_users:
                continue

            alert = SecurityAlert(
                rule_id="LS-001",
                source_ip=source_ip,
                failed_attempts=len(window_events),
                targeted_users=targeted_users,
            )

            alerts.append(alert)
            break

    return alerts
