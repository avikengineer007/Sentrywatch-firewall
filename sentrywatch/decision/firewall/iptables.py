import logging
import subprocess
from typing import List
from sentrywatch.decision.firewall.base import BaseFirewallAdapter

logger = logging.getLogger("sentrywatch.firewall.iptables")


class IptablesAdapter(BaseFirewallAdapter):
    def block_ip(self, ip: str, comment: str = "") -> bool:
        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", comment or "Sentrywatch block"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return res.returncode == 0
        except Exception as e:
            logger.error(f"Failed to block IP {ip} via iptables: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return res.returncode == 0
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip} via iptables: {e}")
            return False

    def list_blocked_ips(self) -> List[str]:
        cmd = ["iptables", "-L", "INPUT", "-n"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            blocked = []
            for line in res.stdout.splitlines():
                if "DROP" in line:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] != "0.0.0.0/0":
                        blocked.append(parts[3])
            return blocked
        except Exception as e:
            logger.error(f"Failed to list iptables rules: {e}")
            return []
