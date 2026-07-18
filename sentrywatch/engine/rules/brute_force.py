from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional
from sentrywatch.engine.rule import BaseRule, IncidentTrigger
from sentrywatch.ingest.normalizer import LogEvent


class BruteForceRule(BaseRule):
    def __init__(self, threshold: int = 5, window_seconds: int = 120):
        super().__init__(rule_id="RULE_BRUTE_FORCE_01", incident_type="brute_force")
        self.threshold = threshold
        self.window_seconds = window_seconds
        # ip -> list of (timestamp, raw_line)
        self.history: Dict[str, List[tuple[datetime, str]]] = defaultdict(list)

    def evaluate(self, event: LogEvent) -> Optional[IncidentTrigger]:
        if event.parsed_fields.get("event_category") != "auth_failure":
            return None

        ip = event.source_ip
        if not ip:
            return None

        now = event.timestamp
        # Prune old events outside window
        self.history[ip] = [
            (ts, line)
            for ts, line in self.history[ip]
            if (now - ts).total_seconds() <= self.window_seconds
        ]

        self.history[ip].append((now, event.raw_line))

        if len(self.history[ip]) >= self.threshold:
            evidence_lines = [line for _, line in self.history[ip]]
            # Reset history after trigger to prevent immediate duplicate triggers
            self.history[ip] = []
            return IncidentTrigger(
                rule_id=self.rule_id,
                incident_type=self.incident_type,
                source_ip=ip,
                raw_evidence="\n".join(evidence_lines),
            )
        return None
