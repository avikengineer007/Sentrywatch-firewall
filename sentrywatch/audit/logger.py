import hashlib
import json
import uuid
from typing import Any, Dict
from sentrywatch.db.repository import AuditEntry, Repository, utc_now_iso

GENESIS_HASH = "0" * 64


def compute_entry_hash(
    entry_id: str, timestamp: str, event_type: str, payload: Dict[str, Any], prev_hash: str
) -> str:
    payload_str = json.dumps(payload, sort_keys=True)
    raw = f"{entry_id}|{timestamp}|{event_type}|{payload_str}|{prev_hash}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class AuditLogger:
    def __init__(self, repo: Repository):
        self.repo = repo

    def log_event(self, event_type: str, payload: Dict[str, Any]) -> AuditEntry:
        latest = self.repo.get_latest_audit_entry()
        prev_hash = latest.this_hash if latest else GENESIS_HASH

        entry_id = str(uuid.uuid4())
        ts = utc_now_iso()
        this_hash = compute_entry_hash(entry_id, ts, event_type, payload, prev_hash)

        entry = AuditEntry(
            id=entry_id,
            timestamp=ts,
            event_type=event_type,
            payload=payload,
            prev_hash=prev_hash,
            this_hash=this_hash,
        )

        self.repo.add_audit_entry(entry)
        return entry
