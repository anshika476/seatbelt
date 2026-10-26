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
from pathlib import Path
from typing import Any, Iterable, Mapping

GENESIS_HASH = "0" * 64

REDACTED = "[redacted]"

#: Environment variable holding the audit HMAC key.
#:
#: Seatbelt reads it at startup and removes it from the environment of every
#: command it executes, so a guarded shell cannot simply run ``env`` and lift
#: it. That is a speed bump, not isolation: see ``docs/THREAT_MODEL.md``.
AUDIT_KEY_ENV = "SEATBELT_AUDIT_KEY"

#: Prefix used for every variable stripped from a child environment.
_PROTECTED_ENV_PREFIX = "SEATBELT_"


#: Where audit records go unless told otherwise. Outside the workspace on
#: purpose: the agent can write the workspace, and must not write its own log.
DEFAULT_AUDIT_PATH = "~/.seatbelt/audit.jsonl"


def default_audit_path() -> str:
    """Resolve the audit log path: explicit argument, environment, then default."""
    return os.path.expanduser(
        os.environ.get("SEATBELT_AUDIT_LOG") or DEFAULT_AUDIT_PATH
    )


def key_from_env(env: Mapping[str, str] | None = None) -> bytes | None:
    """Read the audit key from the environment.

    Accepts 64 hex characters, base64, or at least 16 raw bytes. A value that is
    present but unusable raises rather than silently falling back to a random
    key, because a silent fallback would produce a log nobody can verify while
    looking like everything worked.
    """
    source = os.environ if env is None else env
    raw = source.get(AUDIT_KEY_ENV)
    if not raw:
        return None

    text = raw.strip()
    if len(text) == 64:
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass
    try:
        import base64

        decoded = base64.b64decode(text, validate=True)
        if len(decoded) >= 16:
            return decoded
    except (ValueError, TypeError):
        pass
    if len(text.encode("utf-8")) >= 16:
        return text.encode("utf-8")
    raise ValueError(
        f"{AUDIT_KEY_ENV} is set but unusable: expected 64 hex chars, base64, "
        "or at least 16 raw bytes"
    )


def child_env(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return the environment to hand to an executed command.

    Every ``SEATBELT_*`` variable is removed, so the guarded process does not
    inherit the audit key, the policy path, or any other seatbelt knob. The
    guardian keeps its own copy in memory.
    """
    source = dict(os.environ if env is None else env)
    return {k: v for k, v in source.items() if not k.startswith(_PROTECTED_ENV_PREFIX)}


def _canonical(payload: Mapping[str, Any]) -> bytes:
    """Serialize deterministically so hashes do not depend on key order."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _read_records(path: Path) -> list[AuditRecord]:
    """Load a JSONL chain. A corrupt line is an error, never skipped."""
    records: list[AuditRecord] = []
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                records.append(AuditRecord.from_dict(json.loads(stripped)))
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError(f"{path}:{number}: unreadable audit record: {exc}") from exc
    return records


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
    exit_code: int | None = None
    duration_ms: int | None = None

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
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
        }

    def to_dict(self) -> dict[str, Any]:
        body = self.body()
        body["hash"] = self.hash
        return body

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "AuditRecord":
        return cls(
            seq=int(raw["seq"]),
            ts=str(raw["ts"]),
            action=dict(raw.get("action") or {}),
            decision=str(raw["decision"]),
            rule_id=str(raw["rule_id"]),
            reason=str(raw["reason"]),
            evidence=dict(raw.get("evidence") or {}),
            prev_hash=str(raw["prev_hash"]),
            hash=str(raw["hash"]),
            exit_code=raw.get("exit_code"),
            duration_ms=raw.get("duration_ms"),
        )


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
    """An in-memory hash chain, persisted to JSONL.

    The key comes from ``SEATBELT_AUDIT_KEY`` when it is set, so a log written
    by one process can be verified by another. Without it the log uses an
    ephemeral random key: the chain still detects edits, but only within the
    life of that process.
    """

    def __init__(self, key: bytes | None = None, path: str | os.PathLike[str] | None = None) -> None:
        resolved = key if key is not None else key_from_env()
        if resolved is not None and len(resolved) < 16:
            raise ValueError("audit key must be at least 16 bytes")
        self._key = resolved or os.urandom(32)
        self._key_is_ephemeral = resolved is None
        self._path = Path(path) if path is not None else None
        self._records: list[AuditRecord] = []
        if self._path is not None and self._path.exists():
            self._records = _read_records(self._path)

    @property
    def key(self) -> bytes:
        """The HMAC key.

        Needed to verify a log loaded in a different process. It must never be
        written into the log file itself, and it is stripped from the
        environment of every command Seatbelt executes; see :func:`child_env`.
        """
        return self._key

    @property
    def key_is_ephemeral(self) -> bool:
        """True when no key was supplied and a throwaway one was generated."""
        return self._key_is_ephemeral

    @property
    def path(self) -> Path | None:
        return self._path

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
        exit_code: int | None = None,
        duration_ms: int | None = None,
    ) -> AuditRecord:
        """Seal and append one record, returning it.

        When the log has a path the record is written through immediately and
        flushed: a crash after a decision must not lose the decision.
        """
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
            exit_code=exit_code,
            duration_ms=duration_ms,
        )
        sealed = replace(record, hash=self._seal(record.body()))
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(sealed.to_dict(), sort_keys=True, ensure_ascii=False))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._write_anchor(sealed)
        self._records.append(sealed)
        return sealed

    def _seal(self, body: Mapping[str, Any]) -> str:
        return hmac.new(self._key, _canonical(body), hashlib.sha256).hexdigest()

    def verify(self) -> VerifyResult:
        """Check sequence numbers, links, seals, and the head anchor."""
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

        anchored = self._check_anchor()
        if anchored is not None:
            return anchored
        return VerifyResult(True, len(self._records))

    # -- head anchor ------------------------------------------------------ #
    #
    # A hash chain cannot notice that its own tail was cut off: the last record
    # links backwards, and nothing declares how long the chain should be. The
    # anchor records the head (seq and hash) in a sidecar file, so deleting the
    # newest record leaves the two disagreeing.
    #
    # This is not a security boundary. Anyone who can write the log can write the
    # anchor too. It catches truncation by a tool, a truncating editor, or an
    # agent that removes the record it dislikes, which is the realistic case.

    @property
    def _anchor_path(self) -> Path | None:
        return self._path.with_suffix(self._path.suffix + ".head") if self._path else None

    def _write_anchor(self, record: AuditRecord) -> None:
        anchor = self._anchor_path
        if anchor is None:
            return
        anchor.write_text(
            json.dumps({"seq": record.seq, "hash": record.hash}, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _check_anchor(self) -> VerifyResult | None:
        anchor = self._anchor_path
        if anchor is None or not anchor.exists():
            return None
        try:
            data = json.loads(anchor.read_text(encoding="utf-8"))
            expected_seq = int(data["seq"])
            expected_hash = str(data["hash"])
        except (OSError, ValueError, KeyError, TypeError):
            return VerifyResult(False, len(self._records), None, "head anchor is unreadable")

        if not self._records:
            return VerifyResult(False, 0, None, "head anchor exists but the log is empty")
        last = self._records[-1]
        if last.seq != expected_seq or not hmac.compare_digest(last.hash, expected_hash):
            return VerifyResult(
                False,
                len(self._records),
                len(self._records),
                f"log ends at seq {last.seq} but the head anchor records seq {expected_seq}",
            )
        return None
