"""The audit key: where it comes from and what a child process sees."""

from __future__ import annotations

import base64

import pytest

from seatbelt.audit import AUDIT_KEY_ENV, AuditLog, child_env, key_from_env

HEX_KEY = "a" * 64


def test_key_from_hex() -> None:
    assert key_from_env({AUDIT_KEY_ENV: HEX_KEY}) == bytes.fromhex(HEX_KEY)


def test_key_from_base64() -> None:
    raw = b"0123456789abcdef0123"
    encoded = base64.b64encode(raw).decode()
    assert key_from_env({AUDIT_KEY_ENV: encoded}) == raw


def test_key_from_raw_text() -> None:
    assert key_from_env({AUDIT_KEY_ENV: "a long enough passphrase"}) == b"a long enough passphrase"


def test_missing_key_is_not_an_error() -> None:
    assert key_from_env({}) is None


def test_unusable_key_raises_rather_than_falling_back() -> None:
    """A silent fallback would produce an unverifiable log that looks fine."""
    with pytest.raises(ValueError):
        key_from_env({AUDIT_KEY_ENV: "short"})


def test_log_uses_the_environment_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(AUDIT_KEY_ENV, HEX_KEY)
    log = AuditLog()

    assert log.key == bytes.fromhex(HEX_KEY)
    assert log.key_is_ephemeral is False


def test_log_without_a_key_is_ephemeral(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(AUDIT_KEY_ENV, raising=False)
    log = AuditLog()

    assert log.key_is_ephemeral is True
    assert len(log.key) == 32


def test_child_env_strips_every_seatbelt_variable() -> None:
    source = {
        "PATH": "/usr/bin",
        AUDIT_KEY_ENV: HEX_KEY,
        "SEATBELT_POLICY": "/etc/seatbelt.yaml",
        "HOME": "/root",
    }

    result = child_env(source)

    assert result == {"PATH": "/usr/bin", "HOME": "/root"}
    assert AUDIT_KEY_ENV not in result
