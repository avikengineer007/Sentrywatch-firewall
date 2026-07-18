from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from sentrywatch.engine.rule import BaseRule, IncidentTrigger
from sentrywatch.ingest.normalizer import LogEvent


class PortScanRule(BaseRule):
    def __init__(self, threshold_ports: int = 10, window_seconds: int = 60):
        super().__init__(rule_id="RULE_PORT_SCAN_01", incident_type="port_scan")
        self.threshold_ports = threshold_ports
        self.window_seconds = window_seconds
        # ip -> list of (timestamp, port, raw_line)
        self.history: Dict[str, List[Tuple[datetime, int, str]]] = defaultdict(list)

    def evaluate(self, event: LogEvent) -> Optional[IncidentTrigger]:
        if event.parsed_fields.get("event_category") != "firewall_drop":
            return None

        ip = event.source_ip
        dst_port = event.parsed_fields.get("dst_port")
        if not ip or dst_port is None:
            return None

        now = event.timestamp
        # Prune events outside window
        self.history[ip] = [
            (ts, p, line)
            for ts, p, line in self.history[ip]
            if (now - ts).total_seconds() <= self.window_seconds
        ]

        self.history[ip].append((now, int(dst_port), event.raw_line))

        unique_ports: Set[int] = {p for _, p, _ in self.history[ip]}
        if len(unique_ports) >= self.threshold_ports:
            evidence = "\n".join([line for _, _, line in self.history[ip]])
            self.history[ip] = []
            return IncidentTrigger(
                rule_id=self.rule_id,
                incident_type=self.incident_type,
                source_ip=ip,
                raw_evidence=evidence,
            )
        return None
