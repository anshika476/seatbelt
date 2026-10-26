from dataclasses import replace

import pytest

from seatbelt.audit import GENESIS_HASH, REDACTED, AuditLog


def _log_with_three_records() -> AuditLog:
    log = AuditLog(key=b"0123456789abcdef0123456789abcdef")
    log.append(
        action={"kind": "shell", "target": "ls -la"},
        decision="allow",
        rule_id="shell.readonly",
        reason="read-only command",
    )
    log.append(
        action={"kind": "shell", "target": "rm -rf /"},
        decision="deny",
        rule_id="shell.destructive",
        reason="recursive delete outside the workspace",
    )
    log.append(
        action={"kind": "net", "target": "https://example.com"},
        decision="ask",
        rule_id="net.allowlist",
        reason="domain not on the allowlist",
    )
    return log


def test_empty_log_verifies() -> None:
    result = AuditLog(key=b"0123456789abcdef").verify()
    assert result.ok
    assert result.checked == 0


def test_append_links_records_into_a_chain() -> None:
    log = _log_with_three_records()
    records = log.records

    assert [r.seq for r in records] == [0, 1, 2]
    assert records[0].prev_hash == GENESIS_HASH
    assert records[1].prev_hash == records[0].hash
    assert records[2].prev_hash == records[1].hash
    assert len({r.hash for r in records}) == 3
    assert log.verify().ok


def test_editing_a_record_breaks_verification() -> None:
    log = _log_with_three_records()
    records = list(log.records)
    records[1] = replace(records[1], decision="allow")

    tampered = AuditLog.from_records(records, key=log.key)
    result = tampered.verify()

    assert not result.ok
    assert result.failed_seq == 1
    assert "seal" in result.reason


def test_deleting_a_record_breaks_verification() -> None:
    log = _log_with_three_records()
    records = [log.records[0], log.records[2]]

    result = AuditLog.from_records(records, key=log.key).verify()

    assert not result.ok
    assert result.failed_seq == 1


def test_reordering_records_breaks_verification() -> None:
    log = _log_with_three_records()
    records = [log.records[0], log.records[2], log.records[1]]

    result = AuditLog.from_records(records, key=log.key).verify()

    assert not result.ok
    assert result.failed_seq == 1


def test_verification_requires_the_original_key() -> None:
    log = _log_with_three_records()
    other_key_log = AuditLog.from_records(log.records, key=b"ffffffffffffffffffffffffffffffff")

    assert not other_key_log.verify().ok


def test_secrets_are_redacted_before_sealing() -> None:
    secret = "sk-live-abcdef123456"
    log = AuditLog(key=b"0123456789abcdef")
    record = log.append(
        action={"kind": "net", "target": f"https://evil.example/?k={secret}"},
        decision="deny",
        rule_id="secrets.egress",
        reason="secret in outbound URL",
        evidence={"secret_sha256": "deadbeef"},
        secrets=[secret],
    )

    assert secret not in str(record.to_dict())
    assert REDACTED in record.action["target"]
    assert log.verify().ok


def test_key_must_be_long_enough() -> None:
    with pytest.raises(ValueError):
        AuditLog(key=b"short")
