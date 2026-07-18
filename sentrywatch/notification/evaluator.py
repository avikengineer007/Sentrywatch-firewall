from datetime import datetime, timezone
from typing import Dict, Optional, Tuple
from sentrywatch.config import SentrywatchConfig
from sentrywatch.db.repository import Incident, Repository
from sentrywatch.notification.payload import NotificationPayload


class NotificationEvaluator:
    def __init__(self, config: SentrywatchConfig, repo: Optional[Repository] = None):
        self.config = config
        self.repo = repo
        # (ip, incident_type) -> last_notified_timestamp
        self._cooldown_cache: Dict[Tuple[str, str], datetime] = {}
        self._last_scoring_outage_alert: Optional[datetime] = None

    def evaluate_incident(
        self, incident: Incident, enforcement_status: str = "none"
    ) -> Optional[NotificationPayload]:
        """Evaluates whether an incident triggers a notification based on deterministic rules."""
        if not self.config.notify_enabled:
            return None

        ip = incident.source_ip or "0.0.0.0"
        inc_type = incident.incident_type

        # 1. Deterministic Threshold Checks
        reasons = []
        if (
            incident.severity_score is not None
            and incident.severity_score >= self.config.notify_threshold
        ):
            reasons.append(
                f"Severity score ({incident.severity_score}) >= threshold ({self.config.notify_threshold})"
            )

        if incident.recommended_action == "consider_block":
            reasons.append("Recommended action is consider_block")

        if enforcement_status == "enforced":
            reasons.append("Block action enforced by firewall")

        if not reasons:
            return None

        # 2. Cooldown / Deduplication Check
        now = datetime.now(timezone.utc)
        cache_key = (ip, inc_type)
        if cache_key in self._cooldown_cache:
            last_ts = self._cooldown_cache[cache_key]
            if (now - last_ts).total_seconds() < self.config.notify_cooldown_seconds:
                return None

        if self.repo:
            recent_audits = self.repo.list_audit_entries(limit=50)
            for entry in recent_audits:
                if entry.event_type == "notification":
                    p = entry.payload
                    if p.get("source_ip") == ip:
                        try:
                            ts = datetime.fromisoformat(entry.timestamp.replace("Z", "+00:00"))
                            if (now - ts).total_seconds() < self.config.notify_cooldown_seconds:
                                return None
                        except Exception:
                            pass

        # Update cooldown timestamp
        self._cooldown_cache[cache_key] = now

        lookup_ref = f"sentrywatch ui -> select incident {incident.id}"
        return NotificationPayload(
            incident_id=incident.id,
            incident_type=inc_type,
            source_ip=ip,
            severity_score=incident.severity_score,
            recommended_action=incident.recommended_action,
            timestamp=incident.created_at,
            enforcement_status=enforcement_status,
            lookup_reference=lookup_ref,
            event_reason="; ".join(reasons),
        )

    def evaluate_scoring_outage(
        self, last_successful_score_time: Optional[datetime]
    ) -> Optional[NotificationPayload]:
        """Evaluates system health alert when AI scoring layer is down."""
        if not self.config.notify_enabled or not last_successful_score_time:
            return None

        now = datetime.now(timezone.utc)
        down_seconds = (now - last_successful_score_time).total_seconds()
        threshold_seconds = self.config.notify_scoring_down_alert_minutes * 60

        if down_seconds >= threshold_seconds:
            # Check cooldown for system health alert
            if self._last_scoring_outage_alert:
                if (now - self._last_scoring_outage_alert).total_seconds() < self.config.notify_cooldown_seconds:
                    return None

            self._last_scoring_outage_alert = now
            return NotificationPayload(
                incident_id="SYSTEM-HEALTH",
                incident_type="scoring_layer_outage",
                source_ip="127.0.0.1",
                severity_score=None,
                recommended_action="check_api_key_or_network",
                timestamp=now.isoformat(),
                enforcement_status="none",
                lookup_reference="sentrywatch config",
                event_reason=f"Scoring layer unavailable for {int(down_seconds // 60)} minutes (threshold: {self.config.notify_scoring_down_alert_minutes}m)",
            )

        return None
