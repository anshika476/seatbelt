"""The Claude Code hook: translation, fail-closed behaviour, output shape."""

from __future__ import annotations

import argparse
import io
import json

import pytest

from seatbelt.action import ToolKind
from seatbelt.cases import default_policy_path
from seatbelt.hook import action_from_payload, evaluate_payload, main, run_hook
from seatbelt.policy import Decision, EvalContext, Policy

POLICY = Policy.load(default_policy_path())


def ctx(tmp_path, **kwargs) -> EvalContext:
    return EvalContext(
        workspace=str(tmp_path), cwd=str(tmp_path), home=str(tmp_path), **kwargs
    )


def hook_args(tmp_path, **kwargs) -> argparse.Namespace:
    return argparse.Namespace(
        policy=None,
        workspace=str(tmp_path),
        cwd=None,
        audit=kwargs.get("audit"),
    )


def payload(**fields):
    base = {"hook_event_name": "PreToolUse", "cwd": "/tmp"}
    base.update(fields)
    return base


# --------------------------------------------------------------------------- #
# Translation
# --------------------------------------------------------------------------- #


def test_bash_becomes_a_shell_action(tmp_path) -> None:
    action, note = action_from_payload(
        payload(tool_name="Bash", tool_input={"command": "rm -rf /"}),
        workspace=str(tmp_path),
        cwd=str(tmp_path),
    )

    assert action is not None
    assert action.kind is ToolKind.SHELL
    assert action.target == "rm -rf /"
    assert note == ""


def test_write_becomes_a_file_write_with_resolved_path(tmp_path) -> None:
    action, _ = action_from_payload(
        payload(tool_name="Write", tool_input={"file_path": "notes.md", "content": "hi"}),
        workspace=str(tmp_path),
        cwd=str(tmp_path),
    )

    assert action is not None
    assert action.kind is ToolKind.FILE_WRITE
    assert action.args["escapes_workspace"] is False


def test_read_becomes_a_file_read(tmp_path) -> None:
    action, _ = action_from_payload(
        payload(tool_name="Read", tool_input={"file_path": "README.md"}),
        workspace=str(tmp_path),
        cwd=str(tmp_path),
    )

    assert action is not None
    assert action.kind is ToolKind.FILE_READ


def test_webfetch_becomes_a_net_action(tmp_path) -> None:
    action, _ = action_from_payload(
        payload(tool_name="WebFetch", tool_input={"url": "https://pypi.org/simple/"}),
        workspace=str(tmp_path),
        cwd=str(tmp_path),
    )

    assert action is not None
    assert action.kind is ToolKind.NET
    assert action.args["host"] == "pypi.org"


def test_mcp_tool_name_is_shortened(tmp_path) -> None:
    action, _ = action_from_payload(
        payload(tool_name="mcp__github__search_issues", tool_input={"q": "x"}),
        workspace=str(tmp_path),
        cwd=str(tmp_path),
    )

    assert action is not None
    assert action.kind is ToolKind.MCP
    assert action.target == "search_issues"


def test_unknown_tool_yields_no_action(tmp_path) -> None:
    action, note = action_from_payload(
        payload(tool_name="Teleport", tool_input={}),
        workspace=str(tmp_path),
        cwd=str(tmp_path),
    )

    assert action is None
    assert "unrecognised tool" in note


# --------------------------------------------------------------------------- #
# Decisions
# --------------------------------------------------------------------------- #


def test_unknown_tool_fails_closed_to_ask(tmp_path) -> None:
    evaluation, action = evaluate_payload(
        payload(tool_name="Teleport", tool_input={}), POLICY, ctx(tmp_path)
    )

    assert action is None
    assert evaluation.decision is Decision.ASK
    assert evaluation.verdict.rule_id == "hook.unknown_tool"


def test_bash_deny_is_translated(tmp_path) -> None:
    evaluation, _ = evaluate_payload(
        payload(tool_name="Bash", tool_input={"command": "rm -rf /"}), POLICY, ctx(tmp_path)
    )

    assert evaluation.decision is Decision.DENY


# --------------------------------------------------------------------------- #
# Process behaviour
# --------------------------------------------------------------------------- #


def _stdin(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(text))


def test_hook_denies_with_json_and_exit_two(tmp_path, monkeypatch, capsys) -> None:
    _stdin(
        monkeypatch,
        json.dumps(payload(tool_name="Bash", tool_input={"command": "rm -rf /"})),
    )

    code = run_hook(hook_args(tmp_path))

    out = json.loads(capsys.readouterr().out)
    assert code == 2
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "delete" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_hook_allows_with_exit_zero(tmp_path, monkeypatch, capsys) -> None:
    _stdin(monkeypatch, json.dumps(payload(tool_name="Bash", tool_input={"command": "ls"})))

    code = run_hook(hook_args(tmp_path))

    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_hook_asks_for_inline_code(tmp_path, monkeypatch, capsys) -> None:
    _stdin(
        monkeypatch,
        json.dumps(payload(tool_name="Bash", tool_input={"command": "python -c 'print(1)'"})),
    )

    code = run_hook(hook_args(tmp_path))

    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_unreadable_payload_asks_rather_than_failing_open(tmp_path, monkeypatch, capsys) -> None:
    _stdin(monkeypatch, "{not json")

    code = run_hook(hook_args(tmp_path))

    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "unreadable" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_empty_payload_asks(tmp_path, monkeypatch, capsys) -> None:
    _stdin(monkeypatch, "")

    code = run_hook(hook_args(tmp_path))

    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_hook_writes_an_audit_record(tmp_path, monkeypatch, capsys) -> None:
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("SEATBELT_AUDIT_KEY", "0123456789abcdef0123456789abcdef")
    _stdin(monkeypatch, json.dumps(payload(tool_name="Bash", tool_input={"command": "ls"})))

    run_hook(hook_args(tmp_path, audit=str(audit)))
    capsys.readouterr()

    from seatbelt.audit import AuditLog

    log = AuditLog(path=audit)
    assert len(log) == 1
    assert log.verify().ok
    assert log.records[0].decision == "allow"


def test_main_parses_arguments(tmp_path, monkeypatch, capsys) -> None:
    _stdin(monkeypatch, json.dumps(payload(tool_name="Bash", tool_input={"command": "ls"})))

    code = main(["--workspace", str(tmp_path), "--audit", str(tmp_path / "a.jsonl")])

    assert code == 0
    assert "permissionDecision" in capsys.readouterr().out