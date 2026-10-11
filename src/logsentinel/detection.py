from datetime import timedelta

from src.logsentinel.config import DetectionConfig
from .models import SecurityEvent, SecurityAlert
from .config import DetectionConfig

def group_failed_events_by_ip(
    events: list[SecurityEvent],
) -> dict[str, list[SecurityEvent]]:
    failed_by_ip = {}

    for event in events:
        if event.success:
            continue

        if event.source_ip not in failed_by_ip:
            failed_by_ip[event.source_ip] = []

        failed_by_ip[event.source_ip].append(event)

    return failed_by_ip

def get_time_windows(
    events: list[SecurityEvent],
    time_window_seconds: int,
) -> list[list[SecurityEvent]]:
    events = sorted(
        events,
        key=lambda event: event.timestamp,
    )

    windows = []

    for start_index, start_event in enumerate(events):
        window_events = []

        for event in events[start_index:]:
            if event.timestamp - start_event.timestamp > timedelta(
                seconds=time_window_seconds
            ):
                break

            window_events.append(event)

        windows.append(window_events)

    return windows

def detect_multi_account_targeting(
    events: list[SecurityEvent],
    config: DetectionConfig | None = None,
) -> list[SecurityAlert]:

    if config is None:
        config = DetectionConfig()

    min_unique_users = config.ls001_min_unique_users
    time_window_seconds = config.ls001_time_window_seconds

    failed_by_ip = group_failed_events_by_ip(events)

    alerts = []

    for source_ip, ip_events in failed_by_ip.items():
        for window_events in get_time_windows(
            ip_events,
            time_window_seconds,
        ):
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

def detect_repeated_failures(
    events: list[SecurityEvent],
    config: DetectionConfig | None = None,
) -> list[SecurityAlert]:

    if config is None:
        config = DetectionConfig()

    min_failed_attempts = config.ls002_min_failed_attempts
    time_window_seconds = config.ls002_time_window_seconds

    failed_by_ip = group_failed_events_by_ip(events)

    alerts = []

    for source_ip, ip_events in failed_by_ip.items():
        for window_events in get_time_windows(
            ip_events,
            time_window_seconds,
        ):
            if len(window_events) < min_failed_attempts:
                continue

            alert = SecurityAlert(
                rule_id="LS-002",
                source_ip=source_ip,
                failed_attempts=len(window_events),
                targeted_users={
                    event.username
                    for event in window_events
                },
            )

            alerts.append(alert)
            break

    return alerts
