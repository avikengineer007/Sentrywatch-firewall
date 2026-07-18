from typing import List, Set
from sentrywatch.decision.firewall.base import BaseFirewallAdapter


class SimulatedFirewallAdapter(BaseFirewallAdapter):
    def __init__(self):
        self.blocked_ips: Set[str] = set()

    def block_ip(self, ip: str, comment: str = "") -> bool:
        self.blocked_ips.add(ip)
        return True

    def unblock_ip(self, ip: str) -> bool:
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            return True
        return False

    def list_blocked_ips(self) -> List[str]:
        return sorted(list(self.blocked_ips))
