"""Execution: exact string, workspace cwd, stripped env, time and output caps."""

from __future__ import annotations

import os

from seatbelt.runner import TIMEOUT_EXIT_CODE, execute


def run(tmp_path, command: str, **kwargs):
    return execute(command, cwd=str(tmp_path), **(kwargs or {}))


def test_runs_the_exact_string_that_was_checked(tmp_path) -> None:
    """Spacing, quoting and operators must reach the shell untouched."""
    result = run(tmp_path, "printf '%s' '  a  b  '")

    assert result.stdout == "  a  b  "
    assert result.exit_code == 0


def test_shell_operators_are_honoured(tmp_path) -> None:
    result = run(tmp_path, "echo one && echo two | tr a-z A-Z")

    assert result.stdout.splitlines() == ["one", "TWO"]


def test_relative_paths_land_in_the_declared_cwd(tmp_path) -> None:
    result = run(tmp_path, "echo hi > out.txt")

    assert result.exit_code == 0
    assert (tmp_path / "out.txt").read_text(encoding="utf-8").strip() == "hi"


def test_exit_code_is_passed_through(tmp_path) -> None:
    assert run(tmp_path, "exit 7").exit_code == 7


def test_seatbelt_variables_are_stripped_from_the_child_env(tmp_path) -> None:
    env = {**os.environ, "SEATBELT_AUDIT_KEY": "secret", "KEEP_ME": "yes"}

    result = run(tmp_path, "env", env=env)

    assert "SEATBELT_AUDIT_KEY" in env
    assert "SEATBELT_" not in result.stdout
    assert "KEEP_ME=yes" in result.stdout


def test_stdin_is_closed_so_a_command_cannot_wait_forever(tmp_path) -> None:
    result = run(tmp_path, "read line; echo done", timeout=3)

    assert result.exit_code == 0
    assert result.stdout.strip() == "done"


def test_timeout_kills_the_process_group(tmp_path) -> None:
    result = run(tmp_path, "sleep 5", timeout=0.3)

    assert result.timed_out is True
    assert result.exit_code == TIMEOUT_EXIT_CODE
    assert result.duration_ms < 4000


def test_timeout_kills_children_too(tmp_path) -> None:
    # A background child would outlive a naive kill and keep the pipe open.
    result = run(tmp_path, "sleep 30 & wait", timeout=0.3)

    assert result.timed_out is True


def test_output_is_capped_per_stream(tmp_path) -> None:
    result = run(tmp_path, "seq 1 5000", max_output=64)

    assert result.truncated is True
    assert len(result.stdout.encode()) <= 64


def test_large_stderr_is_also_capped(tmp_path) -> None:
    result = run(tmp_path, "seq 1 5000 >&2", max_output=32)

    assert result.truncated is True
    assert len(result.stderr.encode()) <= 32


def test_duration_is_recorded(tmp_path) -> None:
    result = run(tmp_path, "sleep 0.2")

    assert result.duration_ms >= 150