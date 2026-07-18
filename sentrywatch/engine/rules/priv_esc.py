from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional
from sentrywatch.engine.rule import BaseRule, IncidentTrigger
from sentrywatch.ingest.normalizer import LogEvent


class PrivEscRule(BaseRule):
    def __init__(self, threshold: int = 3, window_seconds: int = 300):
        super().__init__(rule_id="RULE_PRIV_ESC_01", incident_type="priv_esc")
        self.threshold = threshold
        self.window_seconds = window_seconds
        # key (user or ip) -> list of (timestamp, line)
        self.history: Dict[str, List[tuple[datetime, str]]] = defaultdict(list)

    def evaluate(self, event: LogEvent) -> Optional[IncidentTrigger]:
        cat = event.parsed_fields.get("event_category")
        if cat != "priv_esc_failure":
            return None

        key = event.source_ip or event.parsed_fields.get("user", "unknown_user")
        now = event.timestamp

        self.history[key] = [
            (ts, line)
            for ts, line in self.history[key]
            if (now - ts).total_seconds() <= self.window_seconds
        ]

        self.history[key].append((now, event.raw_line))

        if len(self.history[key]) >= self.threshold:
            evidence = "\n".join([line for _, line in self.history[key]])
            self.history[key] = []
            return IncidentTrigger(
                rule_id=self.rule_id,
                incident_type=self.incident_type,
                source_ip=event.source_ip,
                raw_evidence=evidence,
            )
        return None
