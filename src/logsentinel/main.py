from pathlib import Path

from .detection import detect_multi_account_targeting
from .parser import load_events
from .reporting import build_report


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
