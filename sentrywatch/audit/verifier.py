from dataclasses import dataclass
from typing import List, Optional
from sentrywatch.audit.logger import GENESIS_HASH, compute_entry_hash
from sentrywatch.db.repository import Repository


@dataclass
class VerificationResult:
    is_valid: bool
    total_entries: int
    first_tampered_id: Optional[str] = None
    tamper_reason: Optional[str] = None


class AuditVerifier:
    def __init__(self, repo: Repository):
        self.repo = repo

    def verify_chain(self) -> VerificationResult:
        entries = self.repo.list_audit_entries(limit=10000)
        if not entries:
            return VerificationResult(is_valid=True, total_entries=0)

        expected_prev_hash = GENESIS_HASH

        for idx, entry in enumerate(entries):
            if entry.prev_hash != expected_prev_hash:
                return VerificationResult(
                    is_valid=False,
                    total_entries=len(entries),
                    first_tampered_id=entry.id,
                    tamper_reason=f"Previous hash mismatch at index {idx}. Expected {expected_prev_hash[:16]}..., got {entry.prev_hash[:16]}...",
                )

            recomputed = compute_entry_hash(
                entry.id, entry.timestamp, entry.event_type, entry.payload, entry.prev_hash
            )

            if entry.this_hash != recomputed:
                return VerificationResult(
                    is_valid=False,
                    total_entries=len(entries),
                    first_tampered_id=entry.id,
                    tamper_reason=f"Hash mismatch at index {idx}. Entry payload/fields tampered.",
                )

            expected_prev_hash = entry.this_hash

        return VerificationResult(is_valid=True, total_entries=len(entries))
