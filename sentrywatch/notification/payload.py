from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass
class NotificationPayload:
    incident_id: str
    incident_type: str
    source_ip: str
    severity_score: Optional[int]
    recommended_action: Optional[str]
    timestamp: str
    enforcement_status: str  # enforced, dry_run_only, none
    lookup_reference: str
    event_reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
