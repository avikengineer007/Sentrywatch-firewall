from abc import ABC, abstractmethod
from typing import List


class BaseFirewallAdapter(ABC):
    @abstractmethod
    def block_ip(self, ip: str, comment: str = "") -> bool:
        """Apply a block rule for the specified IP address."""
        pass

    @abstractmethod
    def unblock_ip(self, ip: str) -> bool:
        """Remove a block rule for the specified IP address."""
        pass

    @abstractmethod
    def list_blocked_ips(self) -> List[str]:
        """Return a list of currently blocked IP addresses."""
        pass
