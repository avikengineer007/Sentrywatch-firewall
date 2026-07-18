from sentrywatch.db.repository import Incident, Repository, utc_now_iso
from sentrywatch.db.schema import init_db


def test_db_repository_crud(tmp_path):
    db_file = tmp_path / "test.db"
    init_db(db_file, default_allowlist=["127.0.0.1", "10.0.0.0/8"])
    repo = Repository(db_file)

    allowlist = repo.get_allowlist()
    assert len(allowlist) == 2

    inc = Incident(
        id="inc-100",
        created_at=utc_now_iso(),
        incident_type="anomalous_outbound",
        source_ip="198.51.100.5",
        raw_evidence="outbound conn",
        status="new",
    )
    repo.create_incident(inc)

    fetched = repo.get_incident("inc-100")
    assert fetched is not None
    assert fetched.incident_type == "anomalous_outbound"

    repo.update_incident_score("inc-100", 75, "High risk outbound", "consider_block", "high")
    updated = repo.get_incident("inc-100")
    assert updated.severity_score == 75
    assert updated.status == "scored"
