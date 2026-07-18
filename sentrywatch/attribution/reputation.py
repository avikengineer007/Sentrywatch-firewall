from datetime import datetime, timezone
from typing import Dict
from sentrywatch.db.repository import Incident, IPReputation, Repository, utc_now_iso

INCIDENT_WEIGHTS: Dict[str, int] = {
    "brute_force": 15,
    "port_scan": 20,
    "anomalous_outbound": 25,
    "priv_esc": 30,
    "suspicious_process": 35,
}


class ReputationEngine:
    def __init__(self, repo: Repository):
        self.repo = repo

    def calculate_score(
        self, incident_counts: Dict[str, int], last_seen_iso: str
    ) -> int:
        base_score = 0
        for inc_type, count in incident_counts.items():
            weight = INCIDENT_WEIGHTS.get(inc_type, 10)
            base_score += weight * count

        # Apply time decay based on hours since last seen
        try:
            last_seen = datetime.fromisoformat(last_seen_iso.replace("Z", "+00:00"))
            hours_elapsed = (datetime.now(timezone.utc) - last_seen).total_seconds() / 3600.0
        except Exception:
            hours_elapsed = 0.0

        if hours_elapsed < (1.0 / 60.0):
            decay_factor = 1.0
        else:
            decay_factor = max(0.2, 1.0 - (hours_elapsed * 0.05))
        final_score = int(base_score * decay_factor)
        return max(0, min(100, final_score))

    def update_reputation(self, incident: Incident) -> IPReputation:
        ip = incident.source_ip or "0.0.0.0"
        now_str = utc_now_iso()

        existing = self.repo.get_ip_reputation(ip)
        if existing:
            first_seen = existing.first_seen
            counts = dict(existing.incident_counts)
            counts[incident.incident_type] = counts.get(incident.incident_type, 0) + 1
            currently_blocked = existing.currently_blocked
            block_expires = existing.block_expires_at
        else:
            first_seen = now_str
            counts = {incident.incident_type: 1}
            currently_blocked = False
            block_expires = None

        new_score = self.calculate_score(counts, now_str)

        rep = IPReputation(
            ip=ip,
            first_seen=first_seen,
            last_seen=now_str,
            incident_counts=counts,
            reputation_score=new_score,
            currently_blocked=currently_blocked,
            block_expires_at=block_expires,
        )

        self.repo.save_ip_reputation(rep)
        return rep
