from datetime import datetime
from pathlib import Path

from .models import SecurityEvent


def parse_line(line: str) -> SecurityEvent | None:
    parts = line.split()

    if len(parts) < 14:
        return None

    timestamp = " ".join(parts[0:3])
    timestamp = datetime.strptime(
        timestamp,
        "%b %d %H:%M:%S",
    )

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
