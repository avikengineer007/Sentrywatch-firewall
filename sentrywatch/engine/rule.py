from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional
from sentrywatch.ingest.normalizer import LogEvent


@dataclass
class IncidentTrigger:
    rule_id: str
    incident_type: str  # brute_force, port_scan, priv_esc, anomalous_outbound, suspicious_process
    source_ip: Optional[str]
    raw_evidence: str


class BaseRule(ABC):
    def __init__(self, rule_id: str, incident_type: str):
        self.rule_id = rule_id
        self.incident_type = incident_type

    @abstractmethod
    def evaluate(self, event: LogEvent) -> Optional[IncidentTrigger]:
        """Evaluate a incoming normalized log event and return an IncidentTrigger if rule fires."""
        pass
