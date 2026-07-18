import logging
import subprocess
from typing import List
from sentrywatch.decision.firewall.base import BaseFirewallAdapter

logger = logging.getLogger("sentrywatch.firewall.nftables")


class NftablesAdapter(BaseFirewallAdapter):
    def __init__(self, table_name: str = "sentrywatch", set_name: str = "blackhole"):
        self.table_name = table_name
        self.set_name = set_name

    def block_ip(self, ip: str, comment: str = "") -> bool:
        cmd = ["nft", "add", "element", "inet", self.table_name, self.set_name, f"{{ {ip} }}"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return res.returncode == 0
        except Exception as e:
            logger.error(f"Failed to block IP {ip} via nftables: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        cmd = ["nft", "delete", "element", "inet", self.table_name, self.set_name, f"{{ {ip} }}"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return res.returncode == 0
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip} via nftables: {e}")
            return False

    def list_blocked_ips(self) -> List[str]:
        cmd = ["nft", "list", "set", "inet", self.table_name, self.set_name]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            blocked = []
            for line in res.stdout.splitlines():
                line = line.strip()
                if line.endswith(",") or line.endswith("}"):
                    clean = line.strip(", }").strip()
                    if clean:
                        blocked.append(clean)
            return blocked
        except Exception as e:
            logger.error(f"Failed to list nftables elements: {e}")
            return []
