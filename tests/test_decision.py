from sentrywatch.config import SentrywatchConfig
from sentrywatch.db.repository import AllowlistItem, Incident, Repository, utc_now_iso
from sentrywatch.db.schema import init_db
from sentrywatch.decision.allowlist import AllowlistEvaluator
from sentrywatch.decision.evaluator import DecisionEngine
from sentrywatch.decision.firewall.simulator import SimulatedFirewallAdapter


def test_allowlist_evaluator():
    items = [
        AllowlistItem(ip_or_cidr="127.0.0.1", reason="localhost", added_at=utc_now_iso(), added_by="sys"),
        AllowlistItem(ip_or_cidr="10.0.0.0/8", reason="internal", added_at=utc_now_iso(), added_by="sys"),
    ]
    evaluator = AllowlistEvaluator(items)

    assert evaluator.is_allowlisted("127.0.0.1") is True
    assert evaluator.is_allowlisted("10.1.2.3") is True
    assert evaluator.is_allowlisted("203.0.113.5") is False


def test_decision_engine_dry_run_and_enforcement(tmp_path):
    db_file = tmp_path / "test.db"
    init_db(db_file)
    repo = Repository(db_file)
    fw = SimulatedFirewallAdapter()

    # 1. Dry Run test
    cfg_dry = SentrywatchConfig(dry_run=True)
    de_dry = DecisionEngine(cfg_dry, repo, firewall=fw)

    inc = Incident(
        id="inc-dry",
        created_at=utc_now_iso(),
        incident_type="brute_force",
        source_ip="198.51.100.22",
        raw_evidence="failed logins",
        status="new",
        matched_rule_id="RULE_BRUTE_FORCE_01",
    )

    act_dry = de_dry.evaluate_incident(inc)
    assert act_dry is not None
    assert act_dry.mode == "dry_run"
    assert "198.51.100.22" not in fw.list_blocked_ips()

    # 2. Enforced mode test
    cfg_enf = SentrywatchConfig(dry_run=False)
    de_enf = DecisionEngine(cfg_enf, repo, firewall=fw)

    inc_enf = Incident(
        id="inc-enf",
        created_at=utc_now_iso(),
        incident_type="port_scan",
        source_ip="198.51.100.33",
        raw_evidence="port scan",
        status="new",
        matched_rule_id="RULE_PORT_SCAN_01",
    )

    act_enf = de_enf.evaluate_incident(inc_enf)
    assert act_enf is not None
    assert act_enf.mode == "enforced"
    assert "198.51.100.33" in fw.list_blocked_ips()
