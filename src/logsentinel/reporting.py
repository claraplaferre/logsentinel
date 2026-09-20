from collections import Counter

from .models import SecurityEvent


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
