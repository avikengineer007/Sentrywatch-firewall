import sqlite3
from pathlib import Path
from sentrywatch.db.connection import get_db

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    incident_type TEXT NOT NULL,
    source_ip TEXT,
    raw_evidence TEXT NOT NULL,
    status TEXT NOT NULL,
    severity_score INTEGER,
    score_rationale TEXT,
    recommended_action TEXT,
    score_confidence TEXT,
    matched_rule_id TEXT
);

CREATE TABLE IF NOT EXISTS ip_reputation (
    ip TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    incident_counts TEXT NOT NULL, -- JSON object
    reputation_score INTEGER NOT NULL DEFAULT 0,
    currently_blocked INTEGER NOT NULL DEFAULT 0,
    block_expires_at TEXT
);

CREATE TABLE IF NOT EXISTS block_actions (
    id TEXT PRIMARY KEY,
    incident_id TEXT,
    ip TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    ttl_seconds INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expired_at TEXT,
    reversed_manually INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(ip) REFERENCES ip_reputation(ip)
);

CREATE TABLE IF NOT EXISTS allowlist (
    ip_or_cidr TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    added_at TEXT NOT NULL,
    added_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL, -- JSON string
    prev_hash TEXT NOT NULL,
    this_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents(source_ip);
CREATE INDEX IF NOT EXISTS idx_block_actions_ip ON block_actions(ip);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(timestamp);
"""


def init_db(db_path: Path, default_allowlist: list[str] = None) -> None:
    with get_db(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
        if default_allowlist:
            now_iso = "2026-07-19T00:00:00Z"
            for item in default_allowlist:
                conn.execute(
                    """
                    INSERT INTO allowlist (ip_or_cidr, reason, added_at, added_by)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(ip_or_cidr) DO NOTHING
                    """,
                    (item, "Default system allowlist", now_iso, "system"),
                )
