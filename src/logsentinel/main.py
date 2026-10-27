import argparse

from pathlib import Path

from .detection import (
    detect_multi_account_targeting,
    detect_repeated_failures,
)
from .parser import load_events
from .reporting import build_report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="LogSentinel - Security Log Analysis Tool"
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/security.log"),
        help="Path to the security log file",
    )

    args = parser.parse_args()
    log_path = args.input

    if not log_path.exists():
        parser.error(f"Log file not found: {log_path}")

    if not log_path.is_file():
        parser.error(f"Path is not a file: {log_path}")

    try:
        events = load_events(log_path)
    except OSError as exc:
        parser.error(f"Cannot read log file '{log_path}': {exc}")

    alerts = [
        *detect_multi_account_targeting(events),
        *detect_repeated_failures(events),
    ]
    print("\nDetected alerts:")

    for alert in alerts:
        print(alert)

    build_report(events)


if __name__ == "__main__":
    main()
