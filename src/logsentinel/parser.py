from datetime import datetime
from ipaddress import ip_address
from pathlib import Path

from .models import SecurityEvent


def parse_line(line: str) -> SecurityEvent | None:
    parts = line.split()

    if len(parts) < 14:
        return None

    timestamp = " ".join(parts[0:3])

    try:
        timestamp = datetime.strptime(
            f"2024 {timestamp}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None

    if "Failed password" in line:
        success = False
    elif "Accepted password" in line:
        success = True
    else:
        return None

    try:
        from_index = parts.index("from")
        username = parts[from_index - 1]
        source_ip = parts[from_index + 1]
    except (ValueError, IndexError):
        return None
	
    try:
    	ip_address(source_ip)
    except ValueError:
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
