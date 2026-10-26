"""`seatbelt run` end to end, as a subprocess.

These tests exercise the real console entry point so the wiring between policy,
execution and the audit log is covered, not just the pieces.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

KEY = "0123456789abcdef" * 4


def seatbelt(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    merged = {**os.environ, "SEATBELT_AUDIT_KEY": KEY}
    if env:
        merged.update(env)
    return subprocess.run(
        [sys.executable, "-m", "seatbelt.cli", *argv],
        capture_output=True,
        text=True,
        env=merged,
        stdin=subprocess.DEVNULL,
        timeout=timeout,
    )


def audit_records(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_cmd(workspace: Path, audit: Path, *command: str, extra: list[str] | None = None):
    argv = ["run", "--workspace", str(workspace), "--audit", str(audit)]
    argv.extend(extra or [])
    argv.append("--")
    argv.extend(command)
    return seatbelt(argv)


def test_allowed_command_runs_and_is_audited(tmp_path) -> None:
    audit = tmp_path / "audit.jsonl"

    result = run_cmd(tmp_path, audit, "echo hello > out.txt; cat out.txt")

    assert result.returncode == 0
    assert result.stdout.strip() == "hello"
    assert (tmp_path / "out.txt").read_text(encoding="utf-8").strip() == "hello"

    records = audit_records(audit)
    assert len(records) == 1
    assert records[0]["decision"] == "allow"
    assert records[0]["rule_id"] == "shell.readonly"
    assert records[0]["exit_code"] == 0
    assert isinstance(records[0]["duration_ms"], int)


def test_denied_command_exits_126_and_does_not_run(tmp_path) -> None:
    audit = tmp_path / "audit.jsonl"
    target = tmp_path / "pwned.txt"

    result = run_cmd(tmp_path, audit, f"sudo touch {target}")

    assert result.returncode == 126
    assert "shell.privilege" in result.stderr
    assert "privilege escalation" in result.stderr
    assert not target.exists()

    records = audit_records(audit)
    assert records[0]["decision"] == "deny"
    assert records[0]["exit_code"] == 126


def test_ask_without_a_terminal_is_denied(tmp_path) -> None:
    audit = tmp_path / "audit.jsonl"

    result = run_cmd(tmp_path, audit, "python3 -c 'print(1)'")

    assert result.returncode == 126
    assert "no human available" in result.stderr
    assert audit_records(audit)[0]["decision"] == "deny"


def test_ask_can_be_approved_explicitly(tmp_path) -> None:
    audit = tmp_path / "audit.jsonl"

    result = run_cmd(tmp_path, audit, "python3 -c 'print(42)'", extra=["--yes"])

    assert result.returncode == 0
    assert result.stdout.strip() == "42"
    record = audit_records(audit)[0]
    assert record["decision"] == "allow"
    assert record["evidence"]["approved_from_ask"] is True


def test_child_environment_has_no_seatbelt_variables(tmp_path) -> None:
    audit = tmp_path / "audit.jsonl"

    result = run_cmd(
        tmp_path,
        audit,
        "env",
        extra=[],
    )

    assert result.returncode == 0
    assert "SEATBELT_" not in result.stdout


def test_command_timeout_is_reported_and_audited(tmp_path) -> None:
    audit = tmp_path / "audit.jsonl"

    result = run_cmd(tmp_path, audit, "sleep 5", extra=["--timeout", "0.3"])

    assert result.returncode == 124
    assert "timed out" in result.stderr
    record = audit_records(audit)[0]
    assert record["exit_code"] == 124
    assert record["evidence"]["timed_out"] is True


def test_output_cap_is_enforced_and_reported(tmp_path) -> None:
    audit = tmp_path / "audit.jsonl"

    result = run_cmd(tmp_path, audit, "seq 1 5000", extra=["--max-output", "32"])

    assert result.returncode == 0
    assert "output truncated" in result.stderr
    assert len(result.stdout.encode()) <= 32


def test_audit_chain_verifies_after_several_runs(tmp_path) -> None:
    audit = tmp_path / "audit.jsonl"
    run_cmd(tmp_path, audit, "echo one")
    run_cmd(tmp_path, audit, "rm -rf /")
    run_cmd(tmp_path, audit, "echo two")

    from seatbelt.audit import AuditLog

    log = AuditLog(path=audit, key=bytes.fromhex(KEY))
    assert len(log) == 3
    assert log.verify().ok


def test_cwd_is_the_declared_workspace(tmp_path) -> None:
    workspace = tmp_path / "project"
    workspace.mkdir()
    audit = tmp_path / "audit.jsonl"

    result = run_cmd(workspace, audit, "pwd")

    assert result.stdout.strip() == str(workspace)


def test_relative_write_lands_in_the_workspace(tmp_path) -> None:
    audit = tmp_path / "audit.jsonl"

    result = run_cmd(tmp_path, audit, "echo hi > notes.txt")

    assert result.returncode == 0
    assert (tmp_path / "notes.txt").exists()


def test_deny_still_writes_an_audit_record_when_quiet(tmp_path) -> None:
    audit = tmp_path / "audit.jsonl"

    run_cmd(tmp_path, audit, "rm -rf /")

    records = audit_records(audit)
    assert len(records) == 1
    assert records[0]["rule_id"] == "shell.rm_recursive"
    assert records[0]["reason"]