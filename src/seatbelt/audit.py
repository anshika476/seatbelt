"""Tamper-evident audit log.

Every verdict is appended to a chain: a record's ``hash`` is an HMAC over its
canonical body plus the previous record's hash. Editing, reordering or deleting
a record breaks verification from that point onward.

The HMAC key never enters the log file, so a party who can write to the log
cannot recompute a valid chain without also holding the key. That is a weaker
guarantee than a signature with an offline key, and it is the honest one: it
detects tampering by anyone who does not have the running process's key, which
is the realistic threat for an agent editing its own audit trail.

Secrets are redacted before they reach a record; see :func:`redact`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

GENESIS_HASH = "0" * 64

REDACTED = "[redacted]"


def _canonical(payload: Mapping[str, Any]) -> bytes:
    """Serialize deterministically so hashes do not depend on key order."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def redact(value: Any, secrets: Iterable[str] = ()) -> Any:
    """Replace known secret values anywhere in a JSON-shaped structure.

    Only exact substring matches are replaced. This is a last line of defence
    for the log, not the egress check itself: a secret that reached this point
    should already have been denied.
    """
    needles = [s for s in secrets if s]
    if not needles:
        return value
    if isinstance(value, str):
        for needle in needles:
            value = value.replace(needle, REDACTED)
        return value
    if isinstance(value, Mapping):
        return {k: redact(v, needles) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, needles) for v in value]
    return value


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One adjudication, sealed into the chain."""

    seq: int
    ts: str
    action: Mapping[str, Any]
    decision: str
    rule_id: str
    reason: str
    evidence: Mapping[str, Any]
    prev_hash: str
    hash: str

    def body(self) -> dict[str, Any]:
        """The hashed portion of the record: everything except ``hash``."""
        return {
            "seq": self.seq,
            "ts": self.ts,
            "action": dict(self.action),
            "decision": self.decision,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "evidence": dict(self.evidence),
            "prev_hash": self.prev_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        body = self.body()
        body["hash"] = self.hash
        return body


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """Outcome of checking a whole chain.

    ``failed_seq`` is the zero-based position of the first bad record in the
    file, which is what a human wants when they open the log and look.
    """

    ok: bool
    checked: int
    failed_seq: int | None = None
    reason: str = ""

    def __bool__(self) -> bool:
        return self.ok


class AuditLog:
    """An in-memory hash chain, persisted to JSONL in a later task."""

    def __init__(self, key: bytes | None = None) -> None:
        if key is not None and len(key) < 16:
            raise ValueError("audit key must be at least 16 bytes")
        self._key = key or os.urandom(32)
        self._records: list[AuditRecord] = []

    @property
    def key(self) -> bytes:
        """The HMAC key.

        Needed to verify a log loaded in a different process. It must never be
        written into the log file itself.
        """
        return self._key

    @property
    def records(self) -> tuple[AuditRecord, ...]:
        return tuple(self._records)

    def __len__(self) -> int:
        return len(self._records)

    @classmethod
    def from_records(
        cls, records: Iterable[AuditRecord], key: bytes | None = None
    ) -> "AuditLog":
        """Rebuild a log from records, without re-sealing them.

        Used when reading a log back from disk, and by tests that need to
        present a tampered chain to :meth:`verify`.
        """
        log = cls(key=key)
        log._records = list(records)
        return log

    def append(
        self,
        *,
        action: Mapping[str, Any],
        decision: str,
        rule_id: str,
        reason: str,
        evidence: Mapping[str, Any] | None = None,
        secrets: Iterable[str] = (),
    ) -> AuditRecord:
        """Seal and append one record, returning it."""
        prev_hash = self._records[-1].hash if self._records else GENESIS_HASH
        record = AuditRecord(
            seq=len(self._records),
            ts=_utc_now(),
            action=redact(dict(action), secrets),
            decision=decision,
            rule_id=rule_id,
            reason=reason,
            evidence=redact(dict(evidence or {}), secrets),
            prev_hash=prev_hash,
            hash="",
        )
        sealed = replace(record, hash=self._seal(record.body()))
        self._records.append(sealed)
        return sealed

    def _seal(self, body: Mapping[str, Any]) -> str:
        return hmac.new(self._key, _canonical(body), hashlib.sha256).hexdigest()

    def verify(self) -> VerifyResult:
        """Check sequence numbers, links and seals across the whole chain."""
        prev = GENESIS_HASH
        for index, record in enumerate(self._records):
            if record.seq != index:
                return VerifyResult(
                    False, index, index, f"record declares seq {record.seq}, expected {index}"
                )
            if record.prev_hash != prev:
                return VerifyResult(
                    False, index, index, "record does not link to its predecessor"
                )
            if not hmac.compare_digest(record.hash, self._seal(record.body())):
                return VerifyResult(False, index, index, "record seal does not match its body")
            prev = record.hash
        return VerifyResult(True, len(self._records))
