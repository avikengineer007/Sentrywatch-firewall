import ipaddress
from typing import List
from sentrywatch.db.repository import AllowlistItem


class AllowlistEvaluator:
    def __init__(self, allowlist_items: List[AllowlistItem] = None):
        self.items = allowlist_items or []

    def is_allowlisted(self, ip_str: str) -> bool:
        if not ip_str or ip_str == "0.0.0.0":
            return True

        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        for item in self.items:
            try:
                net_obj = ipaddress.ip_network(item.ip_or_cidr, strict=False)
                if ip_obj in net_obj:
                    return True
            except ValueError:
                if item.ip_or_cidr == ip_str:
                    return True

        return False
