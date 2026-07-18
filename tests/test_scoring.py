from sentrywatch.config import SentrywatchConfig
from sentrywatch.db.repository import Incident, IPReputation, utc_now_iso
from sentrywatch.scoring.client import ScoringClient


def test_scoring_client_offline_fallback():
    cfg = SentrywatchConfig(anthropic_api_key=None)
    client = ScoringClient(cfg)

    inc = Incident(
        id="inc-test",
        created_at=utc_now_iso(),
        incident_type="suspicious_process",
        source_ip="198.51.100.1",
        raw_evidence="EXECVE process=sh parent=nginx",
        status="new",
    )

    ip_rep = IPReputation(
        ip="198.51.100.1",
        first_seen=utc_now_iso(),
        last_seen=utc_now_iso(),
        incident_counts={"suspicious_process": 1},
        reputation_score=35,
        currently_blocked=False,
    )

    res = client.score_incident(inc, ip_rep)

    assert res.is_fallback is True
    assert 0 <= res.severity_score <= 100
    assert res.recommended_action in ["monitor", "review", "consider_block"]
    assert "Offline Mode" in res.rationale
