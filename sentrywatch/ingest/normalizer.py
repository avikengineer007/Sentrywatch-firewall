import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass
class LogEvent:
    timestamp: datetime
    source: str
    raw_line: str
    parsed_fields: Dict[str, Any] = field(default_factory=dict)

    @property
    def source_ip(self) -> Optional[str]:
        return self.parsed_fields.get("src_ip")


# Regex patterns for parsing common log formats
SSH_FAILED_PAT = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (?P<src_port>\d+)"
)

UFW_BLOCK_PAT = re.compile(
    r"SRC=(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+DST=(?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?DPT=(?P<dst_port>\d+)"
)

SUDO_FAIL_PAT = re.compile(
    r"sudo:.*?authentication failure;.*?user=(?P<user>\S+).*?COMMAND=(?P<command>.*)"
)

OUTBOUND_PAT = re.compile(
    r"OUTBOUND_CONN.*?src=(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?dst=(?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?dport=(?P<dst_port>\d+)"
)

EXECVE_PAT = re.compile(
    r"EXECVE.*?process=(?P<process>\S+).*?parent=(?P<parent>\S+)(?:.*?src_ip=(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?.*?cmdline=(?P<cmdline>.*)"
)


class EventNormalizer:
    @staticmethod
    def normalize(raw_line: str, source: str = "syslog") -> LogEvent:
        line = raw_line.strip()
        now = datetime.now(timezone.utc)
        parsed: Dict[str, Any] = {}

        # 1. Check SSH failed
        m = SSH_FAILED_PAT.search(line)
        if m:
            parsed = m.groupdict()
            parsed["event_category"] = "auth_failure"
            parsed["src_port"] = int(parsed["src_port"])
            return LogEvent(timestamp=now, source=source, raw_line=line, parsed_fields=parsed)

        # 2. Check UFW / Firewall
        m = UFW_BLOCK_PAT.search(line)
        if m:
            parsed = m.groupdict()
            parsed["event_category"] = "firewall_drop"
            parsed["dst_port"] = int(parsed["dst_port"])
            return LogEvent(timestamp=now, source=source, raw_line=line, parsed_fields=parsed)

        # 3. Check Sudo failure
        m = SUDO_FAIL_PAT.search(line)
        if m:
            parsed = m.groupdict()
            parsed["event_category"] = "priv_esc_failure"
            # Optional IP extraction if present in line
            ip_m = re.search(r"rhost=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            if ip_m:
                parsed["src_ip"] = ip_m.group(1)
            return LogEvent(timestamp=now, source=source, raw_line=line, parsed_fields=parsed)

        # 4. Check Outbound connection
        m = OUTBOUND_PAT.search(line)
        if m:
            parsed = m.groupdict()
            parsed["event_category"] = "outbound_conn"
            parsed["dst_port"] = int(parsed["dst_port"])
            return LogEvent(timestamp=now, source=source, raw_line=line, parsed_fields=parsed)

        # 5. Check Execve process spawn
        m = EXECVE_PAT.search(line)
        if m:
            parsed = m.groupdict()
            parsed["event_category"] = "process_exec"
            return LogEvent(timestamp=now, source=source, raw_line=line, parsed_fields=parsed)

        # Default fallback
        # Generic IP extraction if present
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        if ip_match:
            parsed["src_ip"] = ip_match.group(0)

        parsed["event_category"] = "generic"
        return LogEvent(timestamp=now, source=source, raw_line=line, parsed_fields=parsed)
