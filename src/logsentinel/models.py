from dataclasses import dataclass
from datetime import datetime


@dataclass
class SecurityEvent:
    timestamp: datetime
    username: str
    source_ip: str
    success: bool


@dataclass
class SecurityAlert:
    rule_id: str
    source_ip: str
    failed_attempts: int
    targeted_users: set[str]
