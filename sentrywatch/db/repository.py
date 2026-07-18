import json
import sqlite3
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from sentrywatch.db.connection import get_db


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Incident:
    id: str
    created_at: str
    incident_type: str
    source_ip: Optional[str]
    raw_evidence: str
    status: str  # new, scored, decided, enforced, dry_run_only
    severity_score: Optional[int] = None
    score_rationale: Optional[str] = None
    recommended_action: Optional[str] = None
    score_confidence: Optional[str] = None
    matched_rule_id: Optional[str] = None


@dataclass
class IPReputation:
    ip: str
    first_seen: str
    last_seen: str
    incident_counts: Dict[str, int]
    reputation_score: int
    currently_blocked: bool
    block_expires_at: Optional[str] = None


@dataclass
class BlockAction:
    id: str
    incident_id: Optional[str]
    ip: str
    rule_id: str
    mode: str  # dry_run, enforced
    ttl_seconds: int
    created_at: str
    expired_at: Optional[str] = None
    reversed_manually: bool = False


@dataclass
class AllowlistItem:
    ip_or_cidr: str
    reason: str
    added_at: str
    added_by: str


@dataclass
class AuditEntry:
    id: str
    timestamp: str
    event_type: str
    payload: dict
    prev_hash: str
    this_hash: str


class Repository:
    def __init__(self, db_path: Path):
        self.db_path = db_path

    # --- Incidents ---
    def create_incident(self, incident: Incident) -> None:
        with get_db(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO incidents (
                    id, created_at, incident_type, source_ip, raw_evidence, status,
                    severity_score, score_rationale, recommended_action, score_confidence, matched_rule_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.id,
                    incident.created_at,
                    incident.incident_type,
                    incident.source_ip,
                    incident.raw_evidence,
                    incident.status,
                    incident.severity_score,
                    incident.score_rationale,
                    incident.recommended_action,
                    incident.score_confidence,
                    incident.matched_rule_id,
                ),
            )

    def update_incident_score(
        self,
        incident_id: str,
        score: int,
        rationale: str,
        recommended_action: str,
        confidence: str,
    ) -> None:
        with get_db(self.db_path) as conn:
            conn.execute(
                """
                UPDATE incidents
                SET severity_score = ?,
                    score_rationale = ?,
                    recommended_action = ?,
                    score_confidence = ?,
                    status = 'scored'
                WHERE id = ?
                """,
                (score, rationale, recommended_action, confidence, incident_id),
            )

    def update_incident_status(self, incident_id: str, status: str) -> None:
        with get_db(self.db_path) as conn:
            conn.execute(
                "UPDATE incidents SET status = ? WHERE id = ?",
                (status, incident_id),
            )

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        with get_db(self.db_path) as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if not row:
                return None
            return Incident(**dict(row))

    def list_incidents(self, limit: int = 50) -> List[Incident]:
        with get_db(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [Incident(**dict(r)) for r in rows]

    def count_incidents_since(self, seconds: int) -> int:
        with get_db(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT COUNT(*) as cnt FROM incidents
                WHERE strftime('%s', 'now') - strftime('%s', created_at) <= ?
                """,
                (seconds,),
            ).fetchone()
            return rows["cnt"] if rows else 0

    # --- IP Reputation ---
    def get_ip_reputation(self, ip: str) -> Optional[IPReputation]:
        with get_db(self.db_path) as conn:
            row = conn.execute("SELECT * FROM ip_reputation WHERE ip = ?", (ip,)).fetchone()
            if not row:
                return None
            data = dict(row)
            data["incident_counts"] = json.loads(data["incident_counts"])
            data["currently_blocked"] = bool(data["currently_blocked"])
            return IPReputation(**data)

    def save_ip_reputation(self, rep: IPReputation) -> None:
        with get_db(self.db_path) as conn:
            counts_str = json.dumps(rep.incident_counts)
            conn.execute(
                """
                INSERT INTO ip_reputation (
                    ip, first_seen, last_seen, incident_counts, reputation_score, currently_blocked, block_expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    incident_counts = excluded.incident_counts,
                    reputation_score = excluded.reputation_score,
                    currently_blocked = excluded.currently_blocked,
                    block_expires_at = excluded.block_expires_at
                """,
                (
                    rep.ip,
                    rep.first_seen,
                    rep.last_seen,
                    counts_str,
                    rep.reputation_score,
                    1 if rep.currently_blocked else 0,
                    rep.block_expires_at,
                ),
            )

    def list_top_reputation_ips(self, limit: int = 10) -> List[IPReputation]:
        with get_db(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM ip_reputation ORDER BY reputation_score DESC, last_seen DESC LIMIT ?",
                (limit,),
            ).fetchall()
            result = []
            for r in rows:
                data = dict(r)
                data["incident_counts"] = json.loads(data["incident_counts"])
                data["currently_blocked"] = bool(data["currently_blocked"])
                result.append(IPReputation(**data))
            return result

    def list_all_reputation_ips(self) -> List[IPReputation]:
        with get_db(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM ip_reputation ORDER BY last_seen DESC").fetchall()
            result = []
            for r in rows:
                data = dict(r)
                data["incident_counts"] = json.loads(data["incident_counts"])
                data["currently_blocked"] = bool(data["currently_blocked"])
                result.append(IPReputation(**data))
            return result

    # --- Block Actions ---
    def add_block_action(self, action: BlockAction) -> None:
        with get_db(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO block_actions (
                    id, incident_id, ip, rule_id, mode, ttl_seconds, created_at, expired_at, reversed_manually
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action.id,
                    action.incident_id,
                    action.ip,
                    action.rule_id,
                    action.mode,
                    action.ttl_seconds,
                    action.created_at,
                    action.expired_at,
                    1 if action.reversed_manually else 0,
                ),
            )

    def list_active_blocks(self) -> List[BlockAction]:
        with get_db(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT * FROM block_actions
                WHERE reversed_manually = 0 AND (expired_at IS NULL OR expired_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                """
            ).fetchall()
            return [
                BlockAction(
                    id=r["id"],
                    incident_id=r["incident_id"],
                    ip=r["ip"],
                    rule_id=r["rule_id"],
                    mode=r["mode"],
                    ttl_seconds=r["ttl_seconds"],
                    created_at=r["created_at"],
                    expired_at=r["expired_at"],
                    reversed_manually=bool(r["reversed_manually"]),
                )
                for r in rows
            ]

    # --- Allowlist ---
    def get_allowlist(self) -> List[AllowlistItem]:
        with get_db(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM allowlist").fetchall()
            return [AllowlistItem(**dict(r)) for r in rows]

    def add_allowlist_item(self, item: AllowlistItem) -> None:
        with get_db(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO allowlist (ip_or_cidr, reason, added_at, added_by)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip_or_cidr) DO UPDATE SET reason = excluded.reason
                """,
                (item.ip_or_cidr, item.reason, item.added_at, item.added_by),
            )

    # --- Audit Log ---
    def get_latest_audit_entry(self) -> Optional[AuditEntry]:
        with get_db(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC, id DESC LIMIT 1"
            ).fetchone()
            if not row:
                return None
            data = dict(row)
            data["payload"] = json.loads(data["payload"])
            return AuditEntry(**data)

    def add_audit_entry(self, entry: AuditEntry) -> None:
        with get_db(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO audit_log (id, timestamp, event_type, payload, prev_hash, this_hash)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.id,
                    entry.timestamp,
                    entry.event_type,
                    json.dumps(entry.payload),
                    entry.prev_hash,
                    entry.this_hash,
                ),
            )

    def list_audit_entries(self, limit: int = 100) -> List[AuditEntry]:
        with get_db(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY timestamp ASC, id ASC LIMIT ?", (limit,)
            ).fetchall()
            res = []
            for r in rows:
                data = dict(r)
                data["payload"] = json.loads(data["payload"])
                res.append(AuditEntry(**data))
            return res
