from typing import Optional, Set
from sentrywatch.engine.rule import BaseRule, IncidentTrigger
from sentrywatch.ingest.normalizer import LogEvent

SUSPICIOUS_OUTBOUND_PORTS = {4444, 8443, 6667, 1337, 31337}


class AnomalousOutboundRule(BaseRule):
    def __init__(self, suspicious_ports: Set[int] = None):
        super().__init__(rule_id="RULE_ANOMALOUS_OUT_01", incident_type="anomalous_outbound")
        self.suspicious_ports = suspicious_ports or SUSPICIOUS_OUTBOUND_PORTS

    def evaluate(self, event: LogEvent) -> Optional[IncidentTrigger]:
        if event.parsed_fields.get("event_category") != "outbound_conn":
            return None

        dst_port = event.parsed_fields.get("dst_port")
        dst_ip = event.parsed_fields.get("dst_ip")

        if dst_port and (int(dst_port) in self.suspicious_ports):
            return IncidentTrigger(
                rule_id=self.rule_id,
                incident_type=self.incident_type,
                source_ip=dst_ip or event.source_ip,
                raw_evidence=event.raw_line,
            )
        return None
