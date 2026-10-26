"""Policy semantics: precedence, gating, protected paths, validation."""

from __future__ import annotations

import pytest

from seatbelt.action import ToolKind
from seatbelt.cases import default_policy_path
from seatbelt.policy import (
    Decision,
    EvalContext,
    Policy,
    PolicyError,
    Probe,
)


def ctx(tmp_path=None, **kwargs) -> EvalContext:
    workspace = str(tmp_path) if tmp_path else "/home/dev/project"
    return EvalContext(workspace=workspace, home=kwargs.pop("home", "/home/dev"), **kwargs)


def shell(name: str, argv=None, detail="command", **kwargs) -> Probe:
    return Probe(
        ToolKind.SHELL,
        name,
        argv=tuple(argv or (name,)),
        detail=detail,
        **kwargs,
    )


def policy_with(*rules, default="ask", protected=()) -> Policy:
    return Policy.from_dict(
        {"version": 1, "default": default, "protected": list(protected), "rules": list(rules)}
    )


# --------------------------------------------------------------------------- #
# Precedence
# --------------------------------------------------------------------------- #


def test_deny_beats_allow_regardless_of_order() -> None:
    policy = policy_with(
        {"id": "a.allow", "match": {"kind": "shell", "command": ["rm"]}, "decision": "allow"},
        {"id": "a.deny", "match": {"kind": "shell", "command": ["rm"]}, "decision": "deny"},
    )
    verdict = policy.evaluate(shell("rm"), ctx())
    assert verdict.decision is Decision.DENY
    assert verdict.rule_id == "a.deny"
    assert set(verdict.matches) == {"a.allow", "a.deny"}


def test_fallback_ask_does_not_outrank_a_specific_allow() -> None:
    policy = policy_with(
        {"id": "net.registries", "match": {"kind": "net", "host": ["pypi.org"]}, "decision": "allow"},
        {"id": "net.outbound", "match": {"kind": "net"}, "decision": "ask", "fallback": True},
    )
    known = policy.evaluate(Probe(ToolKind.NET, "pypi.org"), ctx())
    unknown = policy.evaluate(Probe(ToolKind.NET, "evil.example"), ctx())

    assert known.decision is Decision.ALLOW
    assert unknown.decision is Decision.ASK
    assert unknown.rule_id == "net.outbound"


def test_no_match_uses_the_policy_default() -> None:
    policy = policy_with(default="deny")
    verdict = policy.evaluate(shell("something-else"), ctx())
    assert verdict.decision is Decision.DENY
    assert verdict.rule_id == "policy.default"


# --------------------------------------------------------------------------- #
# Gating of special probes
# --------------------------------------------------------------------------- #


def test_allow_rule_does_not_cover_inline_code_by_default() -> None:
    policy = policy_with(
        {"id": "py.allow", "match": {"kind": "shell", "command": ["python"]}, "decision": "allow"},
    )
    verdict = policy.evaluate(shell("python", detail="inline-code", inline_code=True), ctx())
    assert verdict.decision is Decision.ASK


def test_allow_rule_can_opt_in_to_inline_code() -> None:
    policy = policy_with(
        {
            "id": "py.inline.allowed",
            "match": {
                "kind": "shell",
                "command": ["python"],
                "flags_any": ["^-c$"],
                "allow_inline": True,
            },
            "decision": "allow",
        },
    )
    verdict = policy.evaluate(
        shell("python", argv=("python", "-c", "print(1)"), detail="inline-code", inline_code=True),
        ctx(),
    )
    assert verdict.decision is Decision.ALLOW


def test_allow_rule_does_not_cover_unparsed_commands() -> None:
    policy = policy_with(
        {"id": "cat.allow", "match": {"kind": "shell", "command": ["cat"]}, "decision": "allow"},
    )
    verdict = policy.evaluate(shell("cat", detail="unparsed", unparsed=True), ctx())
    assert verdict.decision is Decision.ASK


def test_allow_rule_does_not_cover_agent_created_execution() -> None:
    policy = policy_with(
        {"id": "sh.allow", "match": {"kind": "shell", "command": ["./build.sh"]}, "decision": "allow"},
    )
    verdict = policy.evaluate(shell("./build.sh", detail="agent-created", agent_created=True), ctx())
    assert verdict.decision is Decision.ASK


# --------------------------------------------------------------------------- #
# Protected paths
# --------------------------------------------------------------------------- #


def test_write_to_protected_path_is_denied(tmp_path) -> None:
    policy = policy_with(protected=["~/.bashrc"])
    from seatbelt.engine import resolve_path

    context = ctx(tmp_path, home=str(tmp_path))
    resolved, _ = resolve_path("~/.bashrc", context)
    verdict = policy.evaluate(
        Probe(ToolKind.FILE_WRITE, resolved, resolved=resolved), context
    )
    assert verdict.decision is Decision.DENY
    assert verdict.rule_id == "protected.path"


def test_protected_glob_covers_nested_files(tmp_path) -> None:
    policy = policy_with(protected=["~/.ssh/**"])
    from seatbelt.engine import resolve_path

    context = ctx(tmp_path, home=str(tmp_path))
    resolved, _ = resolve_path("~/.ssh/authorized_keys", context)
    verdict = policy.evaluate(
        Probe(ToolKind.FILE_WRITE, resolved, resolved=resolved), context
    )
    assert verdict.decision is Decision.DENY


def test_reads_of_protected_paths_are_not_denied_by_this_rule(tmp_path) -> None:
    policy = policy_with(
        {"id": "read.allow", "match": {"kind": "file_read"}, "decision": "allow"},
        protected=["~/.ssh/**"],
    )
    from seatbelt.engine import resolve_path

    context = ctx(tmp_path, home=str(tmp_path))
    resolved, _ = resolve_path("~/.ssh/id_rsa", context)
    verdict = policy.evaluate(
        Probe(ToolKind.FILE_READ, resolved, resolved=resolved), context
    )
    assert verdict.decision is Decision.ALLOW


def test_policy_file_protects_itself(tmp_path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("version: 1\n", encoding="utf-8")
    policy = policy_with()
    context = ctx(tmp_path, home=str(tmp_path), policy_path=str(policy_file))

    verdict = policy.evaluate(
        Probe(ToolKind.FILE_WRITE, str(policy_file), resolved=str(policy_file)), context
    )

    assert verdict.decision is Decision.DENY
    assert verdict.rule_id == "protected.path"


def test_audit_log_protects_itself(tmp_path) -> None:
    audit = tmp_path / "audit.jsonl"
    policy = policy_with()
    context = ctx(tmp_path, home=str(tmp_path), audit_path=str(audit))

    verdict = policy.evaluate(
        Probe(ToolKind.FILE_WRITE, str(audit), resolved=str(audit)), context
    )

    assert verdict.decision is Decision.DENY


# --------------------------------------------------------------------------- #
# Matchers
# --------------------------------------------------------------------------- #


def test_flags_all_requires_every_pattern(tmp_path) -> None:
    policy = policy_with(
        {
            "id": "py.m",
            "match": {"kind": "shell", "command": ["python"], "flags_all": ["^-m$", "^pytest$"]},
            "decision": "allow",
        }
    )
    good = policy.evaluate(shell("python", argv=("python", "-m", "pytest")), ctx())
    bad = policy.evaluate(shell("python", argv=("python", "-m", "pip")), ctx())

    assert good.decision is Decision.ALLOW
    assert bad.decision is Decision.ASK


def test_within_workspace_matcher(tmp_path) -> None:
    policy = policy_with(
        {"id": "w.in", "match": {"kind": "file_write", "within_workspace": True}, "decision": "allow"},
        {"id": "w.out", "match": {"kind": "file_write", "within_workspace": False}, "decision": "ask"},
    )
    inside = str(tmp_path / "src" / "a.py")
    outside = str(tmp_path.parent / "elsewhere.py")

    assert policy.evaluate(Probe(ToolKind.FILE_WRITE, inside, resolved=inside), ctx(tmp_path)).decision is Decision.ALLOW
    assert policy.evaluate(Probe(ToolKind.FILE_WRITE, outside, resolved=outside), ctx(tmp_path)).decision is Decision.ASK


def test_host_glob_is_case_insensitive(tmp_path) -> None:
    policy = policy_with(
        {"id": "net.reg", "match": {"kind": "net", "host": ["*.npmjs.org"]}, "decision": "allow"}
    )
    verdict = policy.evaluate(Probe(ToolKind.NET, "Registry.NPMJS.org"), ctx(tmp_path))
    assert verdict.decision is Decision.ALLOW


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def test_unknown_rule_key_is_rejected() -> None:
    with pytest.raises(PolicyError, match="unknown keys"):
        policy_with({"id": "x", "match": {"kind": "shell"}, "decision": "ask", "typo": 1})


def test_unknown_match_key_is_rejected() -> None:
    with pytest.raises(PolicyError, match="unknown match keys"):
        policy_with({"id": "x", "match": {"kind": "shell", "comand": ["rm"]}, "decision": "ask"})


def test_unknown_kind_is_rejected() -> None:
    with pytest.raises(PolicyError, match="unknown kind"):
        policy_with({"id": "x", "match": {"kind": "telepathy"}, "decision": "ask"})


def test_bad_regex_is_rejected() -> None:
    with pytest.raises(PolicyError, match="bad regex"):
        policy_with({"id": "x", "match": {"kind": "shell", "flags_any": ["("]}, "decision": "ask"})


def test_duplicate_rule_ids_are_rejected() -> None:
    with pytest.raises(PolicyError, match="duplicate"):
        policy_with(
            {"id": "dup", "match": {"kind": "shell"}, "decision": "ask"},
            {"id": "dup", "match": {"kind": "shell"}, "decision": "deny"},
        )


def test_unknown_version_is_rejected() -> None:
    with pytest.raises(PolicyError, match="unsupported policy version"):
        Policy.from_dict({"version": 99, "rules": []})


def test_missing_policy_file_is_an_error(tmp_path) -> None:
    with pytest.raises(PolicyError, match="not found"):
        Policy.load(tmp_path / "nope.yaml")


# --------------------------------------------------------------------------- #
# The shipped policy
# --------------------------------------------------------------------------- #


def test_shipped_policy_loads_and_has_unique_ids() -> None:
    policy = Policy.load(default_policy_path())
    assert len(policy.rules) > 20
    assert len({rule.id for rule in policy.rules}) == len(policy.rules)


def test_shipped_policy_protects_startup_and_key_paths() -> None:
    policy = Policy.load(default_policy_path())
    joined = " ".join(policy.protected)
    for pattern in ("~/.bashrc", "~/.ssh/**", "~/.aws/**", "/etc/cron*"):
        assert pattern in joined