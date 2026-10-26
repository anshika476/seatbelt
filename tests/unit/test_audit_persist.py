"""Persistence of the audit chain: append, reload, verify, tamper."""

from __future__ import annotations

import json

import pytest

from seatbelt.audit import AuditLog

KEY = b"0123456789abcdef0123456789abcdef"


def _append(log: AuditLog, decision: str = "allow", exit_code: int | None = 0) -> None:
    log.append(
        action={"kind": "shell", "target": "ls"},
        decision=decision,
        rule_id="shell.readonly",
        reason="read-only command",
        evidence={"command": "ls"},
        exit_code=exit_code,
        duration_ms=12,
    )


def test_records_survive_a_reload(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    first = AuditLog(key=KEY, path=path)
    _append(first)
    _append(first, decision="deny", exit_code=126)

    second = AuditLog(key=KEY, path=path)

    assert len(second) == 2
    assert second.verify().ok
    assert [record.seq for record in second.records] == [0, 1]


def test_chain_continues_across_processes(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditLog(key=KEY, path=path).append(
        action={}, decision="allow", rule_id="r", reason="one", exit_code=0
    )

    second = AuditLog(key=KEY, path=path)
    _append(second)

    third = AuditLog(key=KEY, path=path)
    assert third.records[-1].seq == 1
    assert third.verify().ok


def test_exit_code_and_duration_are_persisted(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    _append(AuditLog(key=KEY, path=path), exit_code=3)

    raw = json.loads(path.read_text(encoding="utf-8").strip().splitlines()[0])

    assert raw["exit_code"] == 3
    assert raw["duration_ms"] == 12


def test_each_record_is_one_line(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(key=KEY, path=path)
    for _ in range(5):
        _append(log)

    assert len(path.read_text(encoding="utf-8").strip().splitlines()) == 5


def test_tampering_on_disk_is_detected(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(key=KEY, path=path)
    _append(log)
    _append(log, decision="deny", exit_code=126)

    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["decision"] = "allow"
    lines[1] = json.dumps(record, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    reloaded = AuditLog(key=KEY, path=path)

    assert reloaded.verify().ok is False
    assert reloaded.verify().failed_seq == 1


def test_deleting_a_line_is_detected(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(key=KEY, path=path)
    for _ in range(3):
        _append(log)

    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")

    reloaded = AuditLog(key=KEY, path=path)

    assert reloaded.verify().ok is False
    assert reloaded.verify().failed_seq == 1


def test_a_corrupt_line_raises_instead_of_being_skipped(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    _append(AuditLog(key=KEY, path=path))
    with path.open("a", encoding="utf-8") as handle:
        handle.write("{not json}\n")

    with pytest.raises(ValueError, match="unreadable audit record"):
        AuditLog(key=KEY, path=path)


def test_directory_is_created_on_first_write(tmp_path) -> None:
    path = tmp_path / "nested" / "deeper" / "audit.jsonl"

    _append(AuditLog(key=KEY, path=path))

    assert path.exists()