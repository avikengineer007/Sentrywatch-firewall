import uuid
from typing import Optional
from sentrywatch.config import SentrywatchConfig
from sentrywatch.db.repository import BlockAction, Incident, Repository, utc_now_iso
from sentrywatch.decision.allowlist import AllowlistEvaluator
from sentrywatch.decision.firewall.base import BaseFirewallAdapter
from sentrywatch.decision.firewall.iptables import IptablesAdapter
from sentrywatch.decision.firewall.nftables import NftablesAdapter
from sentrywatch.decision.firewall.simulator import SimulatedFirewallAdapter


class DecisionEngine:
    def __init__(
        self,
        config: SentrywatchConfig,
        repo: Repository,
        firewall: Optional[BaseFirewallAdapter] = None,
    ):
        self.config = config
        self.repo = repo
        if firewall:
            self.firewall = firewall
        else:
            if config.firewall_adapter == "iptables":
                self.firewall = IptablesAdapter()
            elif config.firewall_adapter == "nftables":
                self.firewall = NftablesAdapter()
            else:
                self.firewall = SimulatedFirewallAdapter()

    def evaluate_incident(self, incident: Incident) -> Optional[BlockAction]:
        """Evaluate deterministic block decision for a newly triggered incident."""
        ip = incident.source_ip
        if not ip:
            return None

        # Ensure ip_reputation entry exists to satisfy DB foreign key
        if not self.repo.get_ip_reputation(ip):
            from sentrywatch.attribution.reputation import ReputationEngine
            ReputationEngine(self.repo).update_reputation(incident)
        allowlist_items = self.repo.get_allowlist()
        allowlist = AllowlistEvaluator(allowlist_items)
        if allowlist.is_allowlisted(ip):
            self.repo.update_incident_status(incident.id, "allowlisted")
            return None

        # 2. Check if deterministic rule fired
        if not incident.matched_rule_id:
            return None

        # 3. Determine execution mode (dry_run vs enforced)
        mode = "dry_run" if self.config.dry_run else "enforced"
        ttl = self.config.default_ttl_seconds
        now_str = utc_now_iso()

        action = BlockAction(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            ip=ip,
            rule_id=incident.matched_rule_id,
            mode=mode,
            ttl_seconds=ttl,
            created_at=now_str,
            expired_at=None,
            reversed_manually=False,
        )

        # 4. Enforce via firewall adapter ONLY if dry-run is disabled
        if mode == "enforced":
            self.firewall.block_ip(ip, comment=f"Sentrywatch rule {incident.matched_rule_id}")
            self.repo.update_incident_status(incident.id, "enforced")
        else:
            self.repo.update_incident_status(incident.id, "dry_run_only")

        self.repo.add_block_action(action)
        return action
