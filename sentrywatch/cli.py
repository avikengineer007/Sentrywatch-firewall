import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from sentrywatch.attribution.reputation import ReputationEngine
from sentrywatch.audit.logger import AuditLogger
from sentrywatch.audit.verifier import AuditVerifier
from sentrywatch.config import get_config
from sentrywatch.db.repository import Incident, Repository, utc_now_iso
from sentrywatch.db.schema import init_db
from sentrywatch.decision.evaluator import DecisionEngine
from sentrywatch.engine.detector import DetectionEngine
from sentrywatch.ingest.file_tailer import LogFileTailer
from sentrywatch.ingest.normalizer import LogEvent
from sentrywatch.ingest.simulator import AttackSimulator
from sentrywatch.scoring.client import ScoringClient
from sentrywatch.ui.app import SentrywatchTUI


def run_daemon(db_path: Path, logfile: Path = None, simulate: bool = False) -> None:
    cfg = get_config()
    cfg.db_path = db_path
    init_db(cfg.db_path, cfg.allowlist)

    repo = Repository(cfg.db_path)
    audit = AuditLogger(repo)
    rep_engine = ReputationEngine(repo)
    detector = DetectionEngine(cfg)
    scorer = ScoringClient(cfg)
    decision = DecisionEngine(cfg, repo)

    from sentrywatch.notification.dispatcher import NotificationDispatcher
    from sentrywatch.notification.evaluator import NotificationEvaluator

    notif_eval = NotificationEvaluator(cfg, repo)
    notif_disp = NotificationDispatcher(cfg, audit)
    notif_disp.start()

    last_score_time = datetime.now(timezone.utc)

    audit.log_event("config_change", {"dry_run": cfg.dry_run, "firewall": cfg.firewall_adapter})

    print(f"[*] Sentrywatch v2 Daemon starting. DB: {cfg.db_path}, Dry-Run: {cfg.dry_run}")

    def on_event(event: LogEvent):
        nonlocal last_score_time
        incidents = detector.process_event(event)
        for inc in incidents:
            repo.create_incident(inc)
            audit.log_event("detection", {"incident_id": inc.id, "type": inc.incident_type, "ip": inc.source_ip})

            # Update IP reputation
            rep = rep_engine.update_reputation(inc)

            # Score incident (advisory AI)
            score_res = scorer.score_incident(inc, rep)
            repo.update_incident_score(
                inc.id,
                score_res.severity_score,
                score_res.rationale,
                score_res.recommended_action,
                score_res.confidence,
            )
            if not score_res.is_fallback:
                last_score_time = datetime.now(timezone.utc)

            audit.log_event(
                "score",
                {
                    "incident_id": inc.id,
                    "severity_score": score_res.severity_score,
                    "action": score_res.recommended_action,
                },
            )

            # Evaluate decision engine (deterministic)
            action = decision.evaluate_incident(inc)
            enf_status = action.mode if action else "none"
            if action:
                audit.log_event(
                    "decision",
                    {
                        "incident_id": inc.id,
                        "ip": action.ip,
                        "mode": action.mode,
                        "ttl": action.ttl_seconds,
                    },
                )
                print(f"[!] Block action created for IP {action.ip} (mode: {action.mode})")

            # Evaluate notifications (deterministic)
            inc_scored = repo.get_incident(inc.id) or inc
            notif_payload = notif_eval.evaluate_incident(inc_scored, enforcement_status=enf_status)
            if notif_payload:
                notif_disp.dispatch_async(notif_payload)

    if simulate:
        sim = AttackSimulator()
        print("[*] Generating simulated attack stream...")
        try:
            while True:
                sim.run_simulation(on_event, interval_seconds=1.0, count=2)
                time.sleep(1)
        except KeyboardInterrupt:
            print("[*] Daemon stopped.")
    elif logfile:
        tailer = LogFileTailer(logfile)
        print(f"[*] Tailing logfile: {logfile}")
        try:
            tailer.tail(on_event)
        except KeyboardInterrupt:
            tailer.stop()
            print("[*] Daemon stopped.")
    else:
        print("[!] No logfile specified and simulate flag not set. Running simulation mode by default.")
        sim = AttackSimulator()
        try:
            while True:
                sim.run_simulation(on_event, interval_seconds=2.0, count=1)
                time.sleep(2)
        except KeyboardInterrupt:
            print("[*] Daemon stopped.")


def run_tui(db_path: Path) -> None:
    cfg = get_config()
    cfg.db_path = db_path
    init_db(cfg.db_path, cfg.allowlist)
    repo = Repository(cfg.db_path)
    tui = SentrywatchTUI(repo, cfg)
    tui.run()


def run_verify(db_path: Path) -> None:
    cfg = get_config()
    cfg.db_path = db_path
    init_db(cfg.db_path, cfg.allowlist)
    repo = Repository(cfg.db_path)
    verifier = AuditVerifier(repo)
    res = verifier.verify_chain()

    print("\n--- Sentrywatch Audit Log Integrity Check ---")
    print(f"Total Signed Entries: {res.total_entries}")
    if res.is_valid:
        print("Status: [PASS] Cryptographic hash-chain intact and fully verified.")
        sys.exit(0)
    else:
        print(f"Status: [FAIL] TAMPER DETECTED!")
        print(f"First Tampered Entry ID: {res.first_tampered_id}")
        print(f"Reason: {res.tamper_reason}")
        sys.exit(1)


def run_simulate_incident(
    db_path: Path,
    incident_type: str = "brute_force",
    source_ip: str = "192.168.1.100",
    severity: int = 80,
    recommended_action: str = "review",
    enforce: bool = False,
) -> None:
    cfg = get_config()
    cfg.db_path = db_path
    init_db(cfg.db_path, cfg.allowlist)

    repo = Repository(cfg.db_path)
    audit = AuditLogger(repo)
    rep_engine = ReputationEngine(repo)

    from sentrywatch.notification.dispatcher import NotificationDispatcher
    from sentrywatch.notification.evaluator import NotificationEvaluator

    notif_eval = NotificationEvaluator(cfg, repo)
    notif_disp = NotificationDispatcher(cfg, audit)
    notif_disp.start()

    import uuid
    inc_id = str(uuid.uuid4())
    now_str = utc_now_iso()

    inc = Incident(
        id=inc_id,
        created_at=now_str,
        incident_type=incident_type,
        source_ip=source_ip,
        raw_evidence=f"Simulated incident test ({incident_type}) from {source_ip}",
        status="scored",
        severity_score=severity,
        score_rationale="Simulated test incident rationale",
        recommended_action=recommended_action,
        score_confidence="high",
        matched_rule_id="RULE_SIMULATED_TEST",
    )

    repo.create_incident(inc)
    audit.log_event("detection", {"incident_id": inc.id, "type": inc.incident_type, "ip": inc.source_ip})

    rep = rep_engine.update_reputation(inc)
    audit.log_event("score", {"incident_id": inc.id, "severity_score": severity, "action": recommended_action})

    enf_status = "enforced" if enforce else "dry_run_only"
    if enforce:
        from sentrywatch.decision.evaluator import DecisionEngine
        decision = DecisionEngine(cfg, repo)
        decision.evaluate_incident(inc)

    notif_payload = notif_eval.evaluate_incident(inc, enforcement_status=enf_status)
    if notif_payload:
        notif_disp.dispatch_async(notif_payload)
        print(f"[+] Notification triggered! Reason: {notif_payload.event_reason}")
    else:
        print("[i] Notification evaluated: SUPPRESSED (did not meet threshold or suppressed by cooldown deduplication).")

    time.sleep(0.5)
    notif_disp.stop()


def main():
    parser = argparse.ArgumentParser(prog="sentrywatch", description="Sentrywatch v2 Intrusion Detection & Prevention System")
    parser.add_argument("--db", type=Path, default=Path("sentrywatch.db"), help="Path to SQLite database")

    subparsers = parser.add_subparsers(dest="command")

    # daemon command
    d_parser = subparsers.add_parser("daemon", help="Run detection daemon")
    d_parser.add_argument("--logfile", type=Path, help="Logfile to tail")
    d_parser.add_argument("--simulate", action="store_true", help="Run synthetic attack generator")

    # tui command
    subparsers.add_parser("ui", help="Launch Rich Terminal UI")
    subparsers.add_parser("tui", help="Launch Rich Terminal UI")

    # audit command
    a_parser = subparsers.add_parser("audit", help="Audit log operations")
    a_sub = a_parser.add_subparsers(dest="audit_command")
    a_sub.add_parser("verify", help="Verify hash chain integrity")

    # simulate command
    s_parser = subparsers.add_parser("simulate", help="Run attack simulator")
    s_parser.add_argument("--count", type=int, default=5, help="Number of simulation rounds")

    # simulate-incident command
    si_parser = subparsers.add_parser("simulate-incident", help="Simulate a single incident to test notification triggers")
    si_parser.add_argument("--type", default="brute_force", help="Incident type")
    si_parser.add_argument("--ip", default="192.168.1.100", help="Source IP")
    si_parser.add_argument("--severity", type=int, default=80, help="Severity score (0-100)")
    si_parser.add_argument("--recommended-action", default="review", help="Recommended action (monitor/review/consider_block)")
    si_parser.add_argument("--enforce", action="store_true", help="Set enforcement status to enforced")

    # config command
    subparsers.add_parser("config", help="Print active configuration")

    args = parser.parse_args()

    if args.command == "daemon":
        run_daemon(args.db, logfile=args.logfile, simulate=args.simulate)
    elif args.command in ("ui", "tui"):
        run_tui(args.db)
    elif args.command == "audit":
        if getattr(args, "audit_command", None) == "verify":
            run_verify(args.db)
        else:
            run_verify(args.db)
    elif args.command == "simulate":
        run_daemon(args.db, simulate=True)
    elif args.command == "simulate-incident":
        run_simulate_incident(
            args.db,
            incident_type=args.type,
            source_ip=args.ip,
            severity=args.severity,
            recommended_action=args.recommended_action,
            enforce=args.enforce,
        )
    elif args.command == "config":
        cfg = get_config()
        print(f"Sentrywatch v2 Configuration:")
        print(f"  DB Path:          {cfg.db_path}")
        print(f"  Dry Run:          {cfg.dry_run}")
        print(f"  Firewall Adapter: {cfg.firewall_adapter}")
        print(f"  Default TTL:      {cfg.default_ttl_seconds}s")
        print(f"  Allowlist:        {cfg.allowlist}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
