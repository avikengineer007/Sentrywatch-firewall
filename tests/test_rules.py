import pytest
from datetime import datetime, timezone
from sentrywatch.engine.rules.anomalous_out import AnomalousOutboundRule
from sentrywatch.engine.rules.brute_force import BruteForceRule
from sentrywatch.engine.rules.port_scan import PortScanRule
from sentrywatch.engine.rules.priv_esc import PrivEscRule
from sentrywatch.engine.rules.suspicious_proc import SuspiciousProcessRule
from sentrywatch.ingest.normalizer import EventNormalizer


def test_brute_force_rule():
    rule = BruteForceRule(threshold=3, window_seconds=60)
    ip = "192.168.1.100"

    trigger = None
    for i in range(3):
        line = f"Failed password for invalid user admin from {ip} port {40000+i} ssh2"
        event = EventNormalizer.normalize(line)
        t = rule.evaluate(event)
        if t:
            trigger = t

    assert trigger is not None
    assert trigger.incident_type == "brute_force"
    assert trigger.source_ip == ip


def test_port_scan_rule():
    rule = PortScanRule(threshold_ports=3, window_seconds=60)
    ip = "203.0.113.50"

    trigger = None
    for port in [80, 443, 22]:
        line = f"[UFW BLOCK] IN=eth0 OUT= SRC={ip} DST=10.0.0.1 PROTO=TCP SPT=12345 DPT={port} SYN"
        event = EventNormalizer.normalize(line)
        t = rule.evaluate(event)
        if t:
            trigger = t

    assert trigger is not None
    assert trigger.incident_type == "port_scan"
    assert trigger.source_ip == ip


def test_priv_esc_rule():
    rule = PrivEscRule(threshold=2, window_seconds=60)
    ip = "198.51.100.99"

    trigger = None
    for _ in range(2):
        line = f"sudo: pam_unix(sudo:auth): authentication failure; logname=user user=root ruser= rhost={ip} tty=/dev/pts/0 dev= COMMAND=/bin/bash"
        event = EventNormalizer.normalize(line)
        t = rule.evaluate(event)
        if t:
            trigger = t

    assert trigger is not None
    assert trigger.incident_type == "priv_esc"
    assert trigger.source_ip == ip


def test_anomalous_outbound_rule():
    rule = AnomalousOutboundRule()
    line = "OUTBOUND_CONN src=192.168.1.50 dst=198.51.100.44 dport=4444 proto=TCP state=ESTABLISHED"
    event = EventNormalizer.normalize(line)
    trigger = rule.evaluate(event)

    assert trigger is not None
    assert trigger.incident_type == "anomalous_outbound"
    assert trigger.source_ip == "198.51.100.44"


def test_suspicious_process_rule():
    rule = SuspiciousProcessRule()
    line = "EXECVE process=sh parent=nginx src_ip=45.33.32.156 cmdline=/bin/sh -c 'id'"
    event = EventNormalizer.normalize(line)
    trigger = rule.evaluate(event)

    assert trigger is not None
    assert trigger.incident_type == "suspicious_process"
    assert trigger.source_ip == "45.33.32.156"
