import time
from datetime import datetime, timedelta, timezone
from sentrywatch.audit.logger import AuditLogger
from sentrywatch.config import SentrywatchConfig
from sentrywatch.db.repository import Incident, Repository, utc_now_iso
from sentrywatch.db.schema import init_db
from sentrywatch.notification.channels.base import BaseNotificationChannel
from sentrywatch.notification.dispatcher import NotificationDispatcher
from sentrywatch.notification.evaluator import NotificationEvaluator
from sentrywatch.notification.payload import NotificationPayload


class MockChannel(BaseNotificationChannel):
    def __init__(self, should_succeed: bool = True):
        super().__init__(name="mock")
        self.should_succeed = should_succeed
        self.received_payloads = []

    def send(self, payload: NotificationPayload) -> bool:
        self.received_payloads.append(payload)
        return self.should_succeed


def test_notification_threshold_evaluator():
    cfg = SentrywatchConfig(notify_enabled=True, notify_threshold=70, notify_cooldown_seconds=300)
    evaluator = NotificationEvaluator(cfg)

    inc_low = Incident(
        id="inc-low",
        created_at=utc_now_iso(),
        incident_type="brute_force",
        source_ip="192.168.1.50",
        raw_evidence="failed ssh",
        status="scored",
        severity_score=50,
        recommended_action="review",
    )
    p_low = evaluator.evaluate_incident(inc_low, enforcement_status="none")
    assert p_low is None

    inc_high = Incident(
        id="inc-high",
        created_at=utc_now_iso(),
        incident_type="brute_force",
        source_ip="192.168.1.50",
        raw_evidence="failed ssh",
        status="scored",
        severity_score=85,
        recommended_action="review",
    )
    p_high = evaluator.evaluate_incident(inc_high, enforcement_status="none")
    assert p_high is not None
    assert p_high.source_ip == "192.168.1.50"
    assert p_high.severity_score == 85
    assert "Severity score" in p_high.event_reason


def test_notification_cooldown_deduplication():
    cfg = SentrywatchConfig(notify_enabled=True, notify_threshold=70, notify_cooldown_seconds=300)
    evaluator = NotificationEvaluator(cfg)

    inc1 = Incident(
        id="inc-1",
        created_at=utc_now_iso(),
        incident_type="port_scan",
        source_ip="203.0.113.10",
        raw_evidence="port scan",
        status="scored",
        severity_score=80,
        recommended_action="review",
    )
    p1 = evaluator.evaluate_incident(inc1, enforcement_status="none")
    assert p1 is not None

    # Duplicate IP + incident_type within cooldown window
    inc2 = Incident(
        id="inc-2",
        created_at=utc_now_iso(),
        incident_type="port_scan",
        source_ip="203.0.113.10",
        raw_evidence="port scan",
        status="scored",
        severity_score=90,
        recommended_action="consider_block",
    )
    p2 = evaluator.evaluate_incident(inc2, enforcement_status="none")
    assert p2 is None

    # Different IP should trigger
    inc3 = Incident(
        id="inc-3",
        created_at=utc_now_iso(),
        incident_type="port_scan",
        source_ip="203.0.113.20",
        raw_evidence="port scan",
        status="scored",
        severity_score=90,
        recommended_action="consider_block",
    )
    p3 = evaluator.evaluate_incident(inc3, enforcement_status="none")
    assert p3 is not None


def test_scoring_outage_alert():
    cfg = SentrywatchConfig(notify_enabled=True, notify_scoring_down_alert_minutes=10)
    evaluator = NotificationEvaluator(cfg)

    now = datetime.now(timezone.utc)
    recent = now - timedelta(minutes=5)
    outage_time = now - timedelta(minutes=15)

    assert evaluator.evaluate_scoring_outage(recent) is None

    alert = evaluator.evaluate_scoring_outage(outage_time)
    assert alert is not None
    assert alert.incident_type == "scoring_layer_outage"
    assert "unavailable for 15 minutes" in alert.event_reason


def test_dispatcher_and_audit_logging(tmp_path):
    db_file = tmp_path / "test_notif.db"
    init_db(db_file)
    repo = Repository(db_file)
    audit = AuditLogger(repo)

    cfg = SentrywatchConfig(notify_enabled=True, notify_channels=["mock"])
    dispatcher = NotificationDispatcher(cfg, audit_logger=audit)

    mock_ch = MockChannel(should_succeed=True)
    dispatcher.channels["mock"] = mock_ch

    dispatcher.start()

    payload = NotificationPayload(
        incident_id="test-inc-id",
        incident_type="priv_esc",
        source_ip="198.51.100.77",
        severity_score=95,
        recommended_action="consider_block",
        timestamp=utc_now_iso(),
        enforcement_status="enforced",
        lookup_reference="sentrywatch ui -> inc-id",
        event_reason="High severity",
    )

    dispatcher.dispatch_async(payload)
    time.sleep(0.5)
    dispatcher.stop()

    assert len(mock_ch.received_payloads) == 1
    assert mock_ch.received_payloads[0].incident_id == "test-inc-id"

    audit_entries = repo.list_audit_entries()
    notif_audits = [e for e in audit_entries if e.event_type == "notification"]
    assert len(notif_audits) == 1
    assert notif_audits[0].payload["channel"] == "mock"
    assert notif_audits[0].payload["status"] == "sent"
