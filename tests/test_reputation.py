from sentrywatch.attribution.reputation import ReputationEngine
from sentrywatch.db.repository import Incident, Repository, utc_now_iso
from sentrywatch.db.schema import init_db


def test_reputation_scoring_and_decay(tmp_path):
    db_file = tmp_path / "test.db"
    init_db(db_file)
    repo = Repository(db_file)
    rep_engine = ReputationEngine(repo)

    inc1 = Incident(
        id="inc-1",
        created_at=utc_now_iso(),
        incident_type="brute_force",
        source_ip="192.0.2.10",
        raw_evidence="failed login",
        status="new",
    )

    rep1 = rep_engine.update_reputation(inc1)
    assert rep1.reputation_score == 15
    assert rep1.incident_counts["brute_force"] == 1

    inc2 = Incident(
        id="inc-2",
        created_at=utc_now_iso(),
        incident_type="priv_esc",
        source_ip="192.0.2.10",
        raw_evidence="sudo fail",
        status="new",
    )

    rep2 = rep_engine.update_reputation(inc2)
    assert rep2.reputation_score == 45  # 15 + 30
    assert rep2.incident_counts["priv_esc"] == 1
