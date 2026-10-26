"""Claude Code PreToolUse hook.

A hook is the smallest way to put Seatbelt in front of a real agent: Claude Code
sends the tool call as JSON on stdin before the tool runs, and reads a
permission decision from stdout.

Input (abridged)::

    {"hook_event_name": "PreToolUse",
     "tool_name": "Bash",
     "tool_input": {"command": "rm -rf /"},
     "cwd": "/home/dev/project"}

Output::

    {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": "recursive or forced delete"}}

``permissionDecision`` is ``allow``, ``ask`` or ``deny``. ``ask`` is passed
through to the harness, which knows how to prompt a human — this frontend has no
terminal of its own.

Deny is signalled twice: in the JSON and with exit code 2 (the harness's
blocking exit). A harness that understands only one of the two still blocks.
Anything unreadable, unknown, or missing fails closed to ``ask``.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Mapping

from .action import (
    Action,
    ToolKind,
    normalize_file,
    normalize_mcp,
    normalize_net,
    normalize_shell,
)
from .audit import AuditLog, default_audit_path
from .cases import default_policy_path
from .engine import Engine, Evaluation
from .policy import Decision, EvalContext, Policy, Probe, Verdict

#: Tool names that read or write a file at a known path.
READ_TOOLS = frozenset({"Read", "NotebookRead"})
WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})
#: Tool names that reach the network.
NET_TOOLS = frozenset({"WebFetch", "WebSearch"})
MCP_PREFIX = "mcp__"


def _first(mapping: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def action_from_payload(
    payload: Mapping[str, Any], *, workspace: str, cwd: str
) -> tuple[Action | None, str]:
    """Translate one harness tool call into an Action.

    Returns ``(action, note)``; ``action`` is ``None`` when the tool is not one
    this frontend understands, and the caller then asks.
    """
    tool_name = str(payload.get("tool_name") or "")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, Mapping):
        tool_input = {}

    if tool_name == "Bash":
        command = _first(tool_input, "command", "cmd")
        if not command:
            return None, "Bash call without a command"
        action, _ = normalize_shell(command, cwd=cwd, tool_name=tool_name)
        return action, ""

    if tool_name in READ_TOOLS or tool_name in WRITE_TOOLS:
        path = _first(tool_input, "file_path", "path", "notebook_path")
        if not path:
            return None, f"{tool_name} call without a path"
        kind = ToolKind.FILE_READ if tool_name in READ_TOOLS else ToolKind.FILE_WRITE
        contents = tool_input.get("content") or tool_input.get("new_string")
        action = normalize_file(
            kind,
            path,
            workspace=workspace,
            cwd=cwd,
            tool_name=tool_name,
            contents=contents if isinstance(contents, str) else None,
        )
        return action, ""

    if tool_name in NET_TOOLS:
        url = _first(tool_input, "url", "query")
        if tool_name == "WebSearch" and not url.startswith(("http://", "https://")):
            return None, "WebSearch has no host to check"
        return normalize_net(url or "", tool_name=tool_name), ""

    if tool_name.startswith(MCP_PREFIX):
        parts = tool_name.split("__")
        short = parts[-1] if parts else tool_name
        return normalize_mcp(short, dict(tool_input)), ""

    return None, f"unrecognised tool {tool_name or '<none>'!r}"


def evaluate_payload(
    payload: Mapping[str, Any],
    policy: Policy,
    ctx: EvalContext,
) -> tuple[Evaluation, Action | None]:
    """Adjudicate a hook payload, failing closed on anything unrecognised."""
    cwd = _first(payload, "cwd", "current_dir") or ctx.cwd
    ctx.cwd = cwd
    engine = Engine(policy, ctx)
    action, note = action_from_payload(payload, workspace=ctx.workspace, cwd=cwd)
    if action is None:
        # An unknown tool is a question, never an allow, whatever the rules say.
        return Evaluation(Verdict(Decision.ASK, "hook.unknown_tool", note), ()), None
    return engine.evaluate(action), action


def _output(decision: Decision, reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision.value,
            "permissionDecisionReason": reason,
        }
    }


def run_hook(args: argparse.Namespace) -> int:
    policy = Policy.load(args.policy or default_policy_path())
    audit_path = default_audit_path() if args.audit is None else args.audit

    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
        if not isinstance(payload, Mapping):
            raise ValueError("hook payload must be a JSON object")
    except (ValueError, json.JSONDecodeError) as exc:
        # Fail closed: an unreadable request is a question, not an allow.
        print(
            json.dumps(_output(Decision.ASK, f"unreadable hook payload: {exc}")),
            file=sys.stdout,
        )
        print(f"seatbelt: unreadable hook payload: {exc}", file=sys.stderr)
        return 0

    # The harness tells us where it is running, which is a better workspace than
    # a hardcoded default: without it, "inside the workspace" would mean "~".
    payload_cwd = _first(payload, "cwd", "current_dir")
    workspace = args.workspace or payload_cwd or policy.workspace
    cwd = args.cwd or payload_cwd or workspace
    ctx = EvalContext(
        workspace=workspace,
        cwd=cwd,
        policy_path=str(policy.source),
        audit_path=audit_path or "",
    )

    evaluation, action = evaluate_payload(payload, policy, ctx)
    decision = evaluation.decision
    reason = evaluation.verdict.reason

    if audit_path:
        try:
            log = AuditLog(path=audit_path)
            log.append(
                action=(action.to_dict() if action else {"kind": "unknown", "target": payload.get("tool_name", "")}),
                decision=decision.value,
                rule_id=evaluation.verdict.rule_id,
                reason=reason,
                evidence={"hook": "PreToolUse", "exit_code": None},
            )
        except OSError as exc:
            print(f"seatbelt: cannot write the audit log: {exc}", file=sys.stderr)

    print(json.dumps(_output(decision, reason)))
    if decision is Decision.DENY:
        print(f"seatbelt: deny ({evaluation.verdict.rule_id}): {reason}", file=sys.stderr)
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="seatbelt hook")
    parser.add_argument("--policy")
    parser.add_argument("--workspace")
    parser.add_argument("--cwd")
    parser.add_argument("--audit")
    return run_hook(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())