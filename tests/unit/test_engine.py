"""Engine probes: path resolution, hidden writes, created files, merging."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from seatbelt.action import (
    ToolKind,
    normalize_file,
    normalize_net,
    normalize_shell,
)
from seatbelt.cases import default_policy_path
from seatbelt.engine import Engine, effective_command, resolve_path
from seatbelt.policy import Decision, EvalContext, Policy
from seatbelt.shellparse import parse


@pytest.fixture(scope="module")
def policy() -> Policy:
    return Policy.load(default_policy_path())


def make_engine(policy: Policy, workspace: Path, home: Path | None = None) -> Engine:
    ctx = EvalContext(
        workspace=str(workspace),
        home=str(home or workspace.parent),
        cwd=str(workspace),
        policy_path=str(policy.source),
        audit_path=str(workspace / ".seatbelt" / "audit.jsonl"),
    )
    return Engine(policy, ctx)


def check(engine: Engine, command: str):
    action, _ = normalize_shell(command, cwd=engine.ctx.cwd)
    return engine.evaluate(action)


# --------------------------------------------------------------------------- #
# Path resolution
# --------------------------------------------------------------------------- #


def test_tilde_is_expanded_against_context_home(tmp_path) -> None:
    ctx = EvalContext(workspace=str(tmp_path), home=str(tmp_path), cwd=str(tmp_path))
    resolved, note = resolve_path("~/.ssh/id_rsa", ctx)

    assert note == ""
    assert resolved == os.path.realpath(tmp_path / ".ssh" / "id_rsa")


def test_home_variable_is_expanded(tmp_path) -> None:
    ctx = EvalContext(workspace=str(tmp_path), home=str(tmp_path), cwd=str(tmp_path))
    assert resolve_path("$HOME/.bashrc", ctx)[0] == os.path.realpath(tmp_path / ".bashrc")
    assert resolve_path("${HOME}/.bashrc", ctx)[0] == os.path.realpath(tmp_path / ".bashrc")


def test_relative_paths_use_the_tracked_cwd(tmp_path) -> None:
    (tmp_path / "src").mkdir()
    ctx = EvalContext(workspace=str(tmp_path), home=str(tmp_path), cwd=str(tmp_path / "src"))

    assert resolve_path("app.py", ctx)[0] == os.path.realpath(tmp_path / "src" / "app.py")


def test_traversal_is_normalized_before_matching(tmp_path) -> None:
    (tmp_path / "src").mkdir()
    ctx = EvalContext(workspace=str(tmp_path), home=str(tmp_path), cwd=str(tmp_path / "src"))

    resolved, _ = resolve_path("../../etc/passwd", ctx)

    assert resolved == os.path.realpath(tmp_path.parent / "etc" / "passwd")


def test_symlink_escape_is_resolved(tmp_path) -> None:
    workspace = tmp_path / "project"
    workspace.mkdir()
    secret = tmp_path / "outside" / "creds"
    secret.parent.mkdir()
    secret.write_text("token", encoding="utf-8")
    (workspace / "link").symlink_to(secret.parent)

    ctx = EvalContext(workspace=str(workspace), home=str(tmp_path), cwd=str(workspace))
    resolved, _ = resolve_path("link/creds", ctx)

    assert resolved == os.path.realpath(secret)
    assert not resolved.startswith(os.path.realpath(workspace))


def test_unresolved_variable_yields_no_path(tmp_path) -> None:
    ctx = EvalContext(workspace=str(tmp_path), home=str(tmp_path), cwd=str(tmp_path))
    resolved, note = resolve_path("$UNKNOWN/file", ctx)

    assert resolved is None
    assert "unresolved variable" in note


# --------------------------------------------------------------------------- #
# Command forms
# --------------------------------------------------------------------------- #


def test_absolute_and_busybox_forms_reduce_to_one_name(tmp_path) -> None:
    engine = make_engine(Policy.load(default_policy_path()), tmp_path)

    for command in ("/bin/rm -rf /tmp/x", "busybox rm -rf /tmp/x"):
        evaluation = check(engine, command)
        assert evaluation.decision is Decision.DENY, command


def test_find_delete_is_a_write_probe(tmp_path) -> None:
    engine = make_engine(Policy.load(default_policy_path()), tmp_path)
    evaluation = check(engine, "find /tmp -name '*.log' -delete")

    assert evaluation.decision is Decision.DENY
    assert evaluation.verdict.rule_id == "shell.find_delete"


# --------------------------------------------------------------------------- #
# Hidden writes
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "command",
    [
        "echo x > ~/.bashrc",
        "echo x >> ~/.bashrc",
        "echo x | tee -a ~/.bashrc",
        "dd if=/dev/zero of=~/.bashrc",
        "mv /tmp/payload ~/.bashrc",
    ],
)
def test_write_forms_all_hit_the_protected_rule(tmp_path, command: str) -> None:
    engine = make_engine(Policy.load(default_policy_path()), tmp_path, home=tmp_path)
    evaluation = check(engine, command)

    assert evaluation.decision is Decision.DENY, command
    assert evaluation.verdict.rule_id == "protected.path"


def test_moving_a_key_away_is_denied(tmp_path) -> None:
    engine = make_engine(Policy.load(default_policy_path()), tmp_path, home=tmp_path)
    evaluation = check(engine, "mv ~/.ssh/id_rsa /tmp/key")

    assert evaluation.decision is Decision.DENY


def test_write_redirect_inside_workspace_is_allowed(tmp_path) -> None:
    engine = make_engine(Policy.load(default_policy_path()), tmp_path)
    evaluation = check(engine, "echo hi > notes.txt")

    assert evaluation.decision is Decision.ALLOW


# --------------------------------------------------------------------------- #
# Inline code and unreadable commands
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "command",
    [
        "python -c 'print(1)'",
        "node -e 'console.log(1)'",
        "perl -e 'unlink q(/tmp/x)'",
    ],
)
def test_inline_interpreter_code_asks(tmp_path, command: str) -> None:
    engine = make_engine(Policy.load(default_policy_path()), tmp_path)
    evaluation = check(engine, command)

    assert evaluation.decision is Decision.ASK
    assert evaluation.verdict.rule_id == "shell.inline_code"


def test_unparseable_shell_asks(tmp_path) -> None:
    engine = make_engine(Policy.load(default_policy_path()), tmp_path)
    evaluation = check(engine, "cat <<EOF")

    assert evaluation.decision is Decision.ASK
    assert evaluation.verdict.rule_id == "shell.unparsed"


def test_unparseable_shell_c_body_asks(tmp_path) -> None:
    """A ``bash -c`` whose body cannot be read must not look confident."""
    assert parse("bash -c 'cat <<EOF'").confident is False

    engine = make_engine(Policy.load(default_policy_path()), tmp_path)
    evaluation = check(engine, "bash -c 'cat <<EOF'")

    assert evaluation.decision is Decision.ASK


# --------------------------------------------------------------------------- #
# Agent-created files
# --------------------------------------------------------------------------- #


def test_executing_a_file_the_session_created_asks(tmp_path) -> None:
    engine = make_engine(Policy.load(default_policy_path()), tmp_path)

    first = check(engine, "echo 'echo hi' > build.sh")
    assert first.decision is Decision.ALLOW
    assert str(tmp_path / "build.sh") in engine.ctx.created_files

    second = check(engine, "./build.sh")
    assert second.decision is Decision.ASK
    assert second.verdict.rule_id == "shell.agent_created_exec"


def test_executing_an_unrelated_script_does_not_claim_created(tmp_path) -> None:
    engine = make_engine(Policy.load(default_policy_path()), tmp_path)
    check(engine, "echo x > other.sh")

    evaluation = check(engine, "./build.sh")

    assert evaluation.verdict.rule_id != "shell.agent_created_exec"


# --------------------------------------------------------------------------- #
# Budget and merging
# --------------------------------------------------------------------------- #


def test_exhausted_budget_denies_before_probing(tmp_path) -> None:
    policy = Policy.load(default_policy_path())
    ctx = EvalContext(workspace=str(tmp_path), home=str(tmp_path), budget_usd=1.0, spent_usd=2.0)
    engine = Engine(policy, ctx)

    evaluation = check(engine, "ls")

    assert evaluation.decision is Decision.DENY
    assert evaluation.verdict.rule_id == "spend.budget"


def test_deny_in_any_probe_wins_the_merge(tmp_path) -> None:
    engine = make_engine(Policy.load(default_policy_path()), tmp_path)
    evaluation = check(engine, "echo hi && rm -rf /tmp/x")

    assert evaluation.decision is Decision.DENY
    assert any(verdict.decision is Decision.ALLOW for _, verdict in evaluation.probes)


def test_net_action_uses_host_rules(tmp_path) -> None:
    engine = make_engine(Policy.load(default_policy_path()), tmp_path)
    known = engine.evaluate(normalize_net("https://pypi.org/simple/"))
    unknown = engine.evaluate(normalize_net("https://evil.example/x"))

    assert known.decision is Decision.ALLOW
    assert unknown.decision is Decision.ASK


def test_file_action_outside_workspace_asks(tmp_path) -> None:
    engine = make_engine(Policy.load(default_policy_path()), tmp_path)
    action = normalize_file(
        ToolKind.FILE_WRITE, "/opt/app/config", workspace=str(tmp_path), cwd=str(tmp_path)
    )

    assert engine.evaluate(action).decision is Decision.ASK