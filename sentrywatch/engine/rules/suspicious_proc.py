from typing import Optional, Set
from sentrywatch.engine.rule import BaseRule, IncidentTrigger
from sentrywatch.ingest.normalizer import LogEvent

UNEXPECTED_PARENTS: Set[str] = {"nginx", "apache2", "httpd", "www-data", "node", "python"}
SHELL_PROCESSES: Set[str] = {"sh", "bash", "zsh", "dash", "nc", "netcat", "ncat", "perl"}


class SuspiciousProcessRule(BaseRule):
    def __init__(self):
        super().__init__(rule_id="RULE_SUSPICIOUS_PROC_01", incident_type="suspicious_process")

    def evaluate(self, event: LogEvent) -> Optional[IncidentTrigger]:
        if event.parsed_fields.get("event_category") != "process_exec":
            return None

        parent = str(event.parsed_fields.get("parent", "")).lower()
        proc = str(event.parsed_fields.get("process", "")).lower()

        if parent in UNEXPECTED_PARENTS and (proc in SHELL_PROCESSES or "sh" in proc):
            return IncidentTrigger(
                rule_id=self.rule_id,
                incident_type=self.incident_type,
                source_ip=event.source_ip,
                raw_evidence=event.raw_line,
            )
        return None
