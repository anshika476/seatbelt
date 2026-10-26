"""`seatbelt verify`: an audit log a human can check with one command."""

from __future__ import annotations

import argparse
import json

import pytest

from seatbelt.audit import AuditLog
from seatbelt.cli import EXIT_ALLOW, EXIT_DENY, EXIT_USAGE, main

KEY = "0123456789abcdef" * 4


def _args(path, **kwargs) -> argparse.Namespace:
    return argparse.Namespace(
        command="verify",
        audit=str(path),
        json=kwargs.get("json", False),
    )


@pytest.fixture
def log_path(tmp_path, monkeypatch):
    monkeypatch.setenv("SEATBELT_AUDIT_KEY", KEY)
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path=path)
    log.append(action={"kind": "shell", "target": "ls"}, decision="allow", rule_id="r", reason="one")
    log.append(action={"kind": "shell", "target": "rm -rf /"}, decision="deny", rule_id="r", reason="two")
    return path


def test_verify_reports_a_clean_chain(log_path, capsys) -> None:
    code = main(["verify", "--audit", str(log_path)])

    out = capsys.readouterr()
    assert code == EXIT_ALLOW
    assert "OK" in out.out
    assert "2 record(s)" in out.out


def test_verify_detects_an_edited_record(log_path, capsys) -> None:
    lines = log_path.read_text(encoding="utf-8").splitlines()
    edited = json.loads(lines[1])
    edited["decision"] = "allow"
    lines[1] = json.dumps(edited, sort_keys=True)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    code = main(["verify", "--audit", str(log_path)])

    out = capsys.readouterr()
    assert code == EXIT_DENY
    assert "FAIL" in out.err
    assert "record 1" in out.err


def test_verify_detects_a_deleted_record(log_path) -> None:
    lines = log_path.read_text(encoding="utf-8").splitlines()
    log_path.write_text(lines[0] + "\n" + lines[1] + "\n", encoding="utf-8")
    log_path.write_text(lines[0] + "\n", encoding="utf-8")

    code = main(["verify", "--audit", str(log_path)])

    assert code == EXIT_DENY


def test_verify_is_machine_readable(log_path, capsys) -> None:
    code = main(["verify", "--audit", str(log_path), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_ALLOW
    assert payload["ok"] is True
    assert payload["records"] == 2
    assert payload["key_from_env"] is True


def test_verify_missing_log_is_a_usage_error(tmp_path, capsys) -> None:
    code = main(["verify", "--audit", str(tmp_path / "nope.jsonl")])

    assert code == EXIT_USAGE
    assert "no audit log" in capsys.readouterr().err


def test_verify_warns_when_the_key_is_missing(log_path, monkeypatch, capsys) -> None:
    """Without the key the seals cannot match, so the warning must be loud."""
    monkeypatch.delenv("SEATBELT_AUDIT_KEY", raising=False)

    code = main(["verify", "--audit", str(log_path)])

    out = capsys.readouterr()
    assert code == EXIT_DENY
    assert "SEATBELT_AUDIT_KEY is not set" in out.err