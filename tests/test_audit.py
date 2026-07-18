from sentrywatch.audit.logger import AuditLogger
from sentrywatch.audit.verifier import AuditVerifier
from sentrywatch.db.repository import Repository
from sentrywatch.db.schema import init_db


def test_audit_log_hash_chain_and_tamper_detection(tmp_path):
    db_file = tmp_path / "test.db"
    init_db(db_file)
    repo = Repository(db_file)
    logger = AuditLogger(repo)
    verifier = AuditVerifier(repo)

    # 1. Log 3 events
    e1 = logger.log_event("detection", {"incident_id": "1", "ip": "1.1.1.1"})
    e2 = logger.log_event("score", {"incident_id": "1", "severity_score": 85})
    e3 = logger.log_event("decision", {"incident_id": "1", "mode": "dry_run"})

    res = verifier.verify_chain()
    assert res.is_valid is True
    assert res.total_entries == 3

    # 2. Tamper with e2 in DB directly
    import sqlite3
    conn = sqlite3.connect(repo.db_path)
    conn.execute("UPDATE audit_log SET payload = '{\"tampered\": true}' WHERE id = ?", (e2.id,))
    conn.commit()
    conn.close()

    res_tampered = verifier.verify_chain()
    assert res_tampered.is_valid is False
    assert res_tampered.first_tampered_id == e2.id
