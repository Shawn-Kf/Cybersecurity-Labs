from dataclasses import dataclass
from datetime import datetime


@dataclass
class SecurityEvent:
    timestamp: datetime
    event_id: int
    username: str
    source_ip: str
    status: str
    logon_type: int