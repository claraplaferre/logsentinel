from dataclasses import dataclass
from pathlib import Path
from collections import Counter


@dataclass
class SecurityEvent:
    timestamp: str
    username: str
    source_ip: str
    success: bool

@dataclass
class SecurityAlert:
    rule_id: str
    source_ip: str
    failed_attempts: int
    targeted_users: set[str]

def parse_line(line: str) -> SecurityEvent | None:
    parts = line.split()

    if len(parts) < 14:
        return None

    timestamp = " ".join(parts[0:3])

    if "Failed password" in line:
        success = False
    elif "Accepted password" in line:
        success = True
    else:
        return None

    username = parts[8]
    source_ip = parts[10]

    if "." not in source_ip:
        return None

    return SecurityEvent(
        timestamp=timestamp,
        username=username,
        source_ip=source_ip,
        success=success,
    )


def load_events(path: Path) -> list[SecurityEvent]:
    events = []

    for line in path.read_text().splitlines():
        event = parse_line(line)

        if event is not None:
            events.append(event)

    return events

def group_failed_activity(events: list[SecurityEvent]) -> dict:
    activity_by_ip = {}

    for event in events:
        if event.success:
            continue

        if event.source_ip not in activity_by_ip:
            activity_by_ip[event.source_ip] = {
                "failed_attempts": 0,
                "targeted_users": set(),
            }

        activity_by_ip[event.source_ip]["failed_attempts"] += 1
        activity_by_ip[event.source_ip]["targeted_users"].add(event.username)

    return activity_by_ip

def detect_multi_account_targeting(
    events: list[SecurityEvent],
    min_unique_users: int = 3,
) -> list[SecurityAlert]:

    activity_by_ip = group_failed_activity(events)
    alerts = []

    for source_ip, activity in activity_by_ip.items():
        targeted_users = activity["targeted_users"]

        if len(targeted_users) < min_unique_users:
            continue

        alert = SecurityAlert(
            rule_id="LS-001",
            source_ip=source_ip,
            failed_attempts=activity["failed_attempts"],
            targeted_users=targeted_users,
        )

        alerts.append(alert)

    return alerts

def build_report(events: list[SecurityEvent]) -> None:
    failed_events = [event for event in events if not event.success]
    successful_events = [event for event in events if event.success]

    failed_users = Counter(event.username for event in failed_events)
    failed_ips = Counter(event.source_ip for event in failed_events)

    print("=" * 32)
    print("       LOGSENTINEL v0.1")
    print("=" * 32)
    print(f"Total events: {len(events)}")
    print(f"Failed logins: {len(failed_events)}")
    print(f"Successful logins: {len(successful_events)}")

    print("\nTargeted users:")
    for username, count in failed_users.most_common():
        print(f"{count:>3} {username}")

    print("\nTop source IPs:")
    for source_ip, count in failed_ips.most_common(5):
        print(f"{count:>3} {source_ip}")


def main() -> None:
    log_path = Path("data/security.log")

    if not log_path.exists():
        print(f"ERROR: log file not found: {log_path}")
        return

    events = load_events(log_path)

    alerts = detect_multi_account_targeting(events)

    print("\nDetected alerts:")
    for alert in alerts:
        print(alert)

    build_report(events)


if __name__ == "__main__":
    main()