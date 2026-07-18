import uuid
from typing import Callable, List, Optional
from sentrywatch.config import SentrywatchConfig
from sentrywatch.db.repository import Incident, utc_now_iso
from sentrywatch.engine.rule import BaseRule
from sentrywatch.engine.rules.anomalous_out import AnomalousOutboundRule
from sentrywatch.engine.rules.brute_force import BruteForceRule
from sentrywatch.engine.rules.port_scan import PortScanRule
from sentrywatch.engine.rules.priv_esc import PrivEscRule
from sentrywatch.engine.rules.suspicious_proc import SuspiciousProcessRule
from sentrywatch.ingest.normalizer import LogEvent


class DetectionEngine:
    def __init__(self, config: SentrywatchConfig, rules: Optional[List[BaseRule]] = None):
        self.config = config
        self.rules = rules or [
            BruteForceRule(
                threshold=config.brute_force_threshold, window_seconds=config.brute_force_window
            ),
            PortScanRule(
                threshold_ports=config.port_scan_threshold, window_seconds=config.port_scan_window
            ),
            PrivEscRule(
                threshold=config.priv_esc_threshold, window_seconds=config.priv_esc_window
            ),
            AnomalousOutboundRule(),
            SuspiciousProcessRule(),
        ]

    def process_event(
        self, event: LogEvent, on_incident: Optional[Callable[[Incident], None]] = None
    ) -> List[Incident]:
        created_incidents: List[Incident] = []
        for rule in self.rules:
            trigger = rule.evaluate(event)
            if trigger:
                incident = Incident(
                    id=str(uuid.uuid4()),
                    created_at=utc_now_iso(),
                    incident_type=trigger.incident_type,
                    source_ip=trigger.source_ip,
                    raw_evidence=trigger.raw_evidence,
                    status="new",
                    matched_rule_id=trigger.rule_id,
                )
                created_incidents.append(incident)
                if on_incident:
                    on_incident(incident)
        return created_incidents
