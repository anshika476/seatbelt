"""Command line entry point.

Frontends (``run``, ``check``, ``hook``, ``parse``, ``policy``) are thin: they
normalize a call, ask the engine for a verdict, and report it. All judgement
lives behind the engine, so every frontend reports the same rule ids.

Exit codes for ``run`` and ``check``:
    0    allow (for ``run``: the command's own exit code is passed through)
    1    deny
    2    usage or policy error
    3    ask
    126  denied at execution time (also: ask with no human available)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Sequence

from . import __version__
from .action import normalize_shell
from .audit import AuditLog, child_env, default_audit_path
from .cases import default_cases_path, default_policy_path, load_cases, run_cases
from .engine import Engine, Evaluation
from .policy import Decision, EvalContext, Policy, PolicyError
from .runner import DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_TIMEOUT_S, execute
from .shellparse import parse

EXIT_ALLOW = 0
EXIT_DENY = 1
EXIT_USAGE = 2
EXIT_ASK = 3
EXIT_DENIED_EXEC = 126

#: Where audit records go unless told otherwise. Outside the workspace on
#: purpose: the workspace is writable by the agent, the audit trail is not.
DEFAULT_AUDIT_PATH = "~/.seatbelt/audit.jsonl"


def _cmd_version() -> int:
    print(f"seatbelt {__version__}")
    return EXIT_ALLOW


def _cmd_parse(argv: Sequence[str]) -> int:
    tokens = _strip_leading_dashes(argv)
    command = " ".join(tokens)
    if not command.strip():
        print("error: nothing to parse", file=sys.stderr)
        return EXIT_USAGE
    result = parse(command)
    print(json.dumps(result.to_dict(), indent=2))
    return EXIT_ALLOW if result.confident else EXIT_ASK


def _strip_leading_dashes(argv: Sequence[str]) -> list[str]:
    tokens = list(argv)
    if tokens and tokens[0] == "--":
        tokens = tokens[1:]
    return tokens


def _load_policy(path: str | None) -> Policy:
    return Policy.load(path or default_policy_path())


def _audit_path(override: str | None) -> str:
    return os.path.expanduser(override) if override else default_audit_path()


def _context(args: argparse.Namespace, policy: Policy, audit_path: str) -> EvalContext:
    workspace = args.workspace or policy.workspace
    return EvalContext(
        workspace=workspace,
        cwd=args.cwd or workspace,
        policy_path=str(policy.source),
        audit_path=audit_path,
        budget_usd=getattr(args, "budget", None),
    )


def _cmd_check(args: argparse.Namespace) -> int:
    command = " ".join(_strip_leading_dashes(args.shell_command))
    if not command.strip():
        print("error: nothing to check", file=sys.stderr)
        return EXIT_USAGE

    policy = _load_policy(args.policy)
    ctx = _context(args, policy, _audit_path(args.audit))
    action, _ = normalize_shell(command, cwd=ctx.cwd)
    evaluation = Engine(policy, ctx).evaluate(action)

    if args.json:
        print(json.dumps(evaluation.to_dict(), indent=2))
    else:
        print(f"{evaluation.decision.value.upper():5} {evaluation.verdict.rule_id}")
        print(f"      {evaluation.verdict.reason}")

    return {
        "allow": EXIT_ALLOW,
        "deny": EXIT_DENY,
        "ask": EXIT_ASK,
    }[evaluation.decision.value]


# --------------------------------------------------------------------------- #
# run
# --------------------------------------------------------------------------- #


def _preview(evaluation: Evaluation, command: str) -> None:
    print(f"seatbelt: approval needed ({evaluation.verdict.rule_id})", file=sys.stderr)
    print(f"  reason : {evaluation.verdict.reason}", file=sys.stderr)
    print(f"  command: {command}", file=sys.stderr)
    for probe, verdict in evaluation.probes:
        if verdict.decision is not Decision.ALLOW:
            print(
                f"  probe  : {probe.kind.value} {probe.target or probe.resolved} "
                f"-> {verdict.decision.value} ({verdict.rule_id})",
                file=sys.stderr,
            )


def _ask_human(evaluation: Evaluation, command: str, args: argparse.Namespace) -> tuple[bool, str]:
    """Decide an ``ask``. No human means no, which is the whole point."""
    if args.yes:
        return True, "approved by --yes"
    if not sys.stdin.isatty():
        return False, "no human available (stdin is not a terminal)"
    _preview(evaluation, command)
    try:
        answer = input("run it? [y/N] ").strip().lower()
    except EOFError:
        return False, "no human available (stdin closed)"
    if answer in {"y", "yes"}:
        return True, "approved by a human"
    return False, "declined by a human"


def _record(
    log: AuditLog,
    action,
    decision: str,
    rule_id: str,
    reason: str,
    *,
    exit_code: int | None,
    duration_ms: int | None,
    evidence: dict,
) -> bool:
    """Append one audit record. Returns False when the log could not be written."""
    try:
        log.append(
            action=action.to_dict(),
            decision=decision,
            rule_id=rule_id,
            reason=reason,
            evidence=evidence,
            exit_code=exit_code,
            duration_ms=duration_ms,
        )
        return True
    except OSError as exc:
        print(f"seatbelt: cannot write the audit log: {exc}", file=sys.stderr)
        return False


def _refuse(log: AuditLog, action, evaluation: Evaluation, note: str, evidence: dict) -> int:
    reason = evaluation.verdict.reason if not note else f"{evaluation.verdict.reason}; {note}"
    label = "deny" if evaluation.decision is Decision.DENY else "ask"
    print(
        f"seatbelt: {label} ({evaluation.verdict.rule_id}): {reason}",
        file=sys.stderr,
    )
    _record(
        log,
        action,
        "deny",
        evaluation.verdict.rule_id,
        reason,
        exit_code=EXIT_DENIED_EXEC,
        duration_ms=0,
        evidence={**evidence, "verdict": evaluation.decision.value},
    )
    return EXIT_DENIED_EXEC


def _cmd_run(args: argparse.Namespace) -> int:
    command = " ".join(_strip_leading_dashes(args.shell_command))
    if not command.strip():
        print("error: nothing to run", file=sys.stderr)
        return EXIT_USAGE

    policy = _load_policy(args.policy)
    audit_path = _audit_path(args.audit)
    ctx = _context(args, policy, audit_path)
    action, _ = normalize_shell(command, cwd=ctx.cwd)
    evaluation = Engine(policy, ctx).evaluate(action)
    log = AuditLog(path=audit_path)
    evidence = {"command": command, "cwd": ctx.cwd, "workspace": ctx.workspace}

    if evaluation.decision is Decision.DENY:
        return _refuse(log, action, evaluation, "", evidence)

    approved = True
    note = ""
    if evaluation.decision is Decision.ASK:
        approved, note = _ask_human(evaluation, command, args)
        if not approved:
            return _refuse(log, action, evaluation, note, evidence)

    try:
        result = execute(
            command,
            cwd=ctx.cwd,
            timeout=args.timeout,
            max_output=args.max_output,
            env=child_env(),
        )
    except OSError as exc:
        print(f"seatbelt: could not execute: {exc}", file=sys.stderr)
        _record(
            log, action, "allow", evaluation.verdict.rule_id, f"execution failed: {exc}",
            exit_code=EXIT_DENIED_EXEC, duration_ms=0, evidence={**evidence, "error": str(exc)},
        )
        return EXIT_DENIED_EXEC

    if result.stdout:
        sys.stdout.write(result.stdout)
        sys.stdout.flush()
    if result.stderr:
        sys.stderr.write(result.stderr)
        sys.stderr.flush()
    if result.truncated:
        print("seatbelt: output truncated", file=sys.stderr)
    if result.timed_out:
        print(f"seatbelt: timed out after {args.timeout}s", file=sys.stderr)

    recorded = _record(
        log,
        action,
        "allow",
        evaluation.verdict.rule_id,
        f"{evaluation.verdict.reason}; {note}" if note else evaluation.verdict.reason,
        exit_code=result.exit_code,
        duration_ms=result.duration_ms,
        evidence={
            **evidence,
            "verdict": evaluation.decision.value,
            "approved_from_ask": evaluation.decision is Decision.ASK,
            "timed_out": result.timed_out,
            "truncated": result.truncated,
        },
    )
    if not recorded:
        # An unlogged action is an unaccountable action; the command already
        # ran, so the honest response is a distinct exit code, not silence.
        return EXIT_DENIED_EXEC
    return result.exit_code


# --------------------------------------------------------------------------- #
# policy test
# --------------------------------------------------------------------------- #


def _cmd_policy_test(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)
    cases = load_cases(args.cases or default_cases_path())
    results = run_cases(policy, cases)

    if not args.quiet:
        width = max(len(result.case.name) for result in results)
        for result in results:
            mark = "ok  "
            if result.case.is_known_gap:
                mark = "xfail" if not result.as_expected else "xpass"
            elif not result.as_expected:
                mark = "FAIL"
            print(
                f"{mark}  {result.case.name.ljust(width)}  "
                f"expected={result.case.expected:5} actual={result.decision:5} "
                f"rule={result.rule_id}"
            )
            if result.counts_as_failure:
                print(f"        {result.reason}")

    failures = [result for result in results if result.counts_as_failure]
    gaps = [result for result in results if result.case.is_known_gap]
    print(
        f"\n{len(results) - len(failures)}/{len(results)} cases behave as specified, "
        f"{len(failures)} failure(s), {len(gaps)} known gap(s)"
    )
    if gaps and not args.quiet:
        for result in gaps:
            print(f"  gap: {result.case.name} — {result.case.xfail}")
    return EXIT_ALLOW if not failures else EXIT_DENY


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #


def _add_policy_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy", help="policy YAML (default: the shipped policy)")
    parser.add_argument("--workspace", help="workspace root (default: from policy)")
    parser.add_argument("--cwd", help="working directory for relative paths")
    parser.add_argument("--audit", help=f"audit log path (default: {DEFAULT_AUDIT_PATH})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="seatbelt",
        description="Action guardrails for AI agents.",
    )
    parser.add_argument("--version", action="version", version=f"seatbelt {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("version", help="print the installed version")

    parse_parser = subparsers.add_parser(
        "parse",
        help="parse a shell command and print the tree policy will see",
    )
    parse_parser.add_argument("shell_command", nargs=argparse.REMAINDER)

    check_parser = subparsers.add_parser(
        "check", help="adjudicate a shell command without running it"
    )
    _add_policy_options(check_parser)
    check_parser.add_argument("--budget", type=float, help="spend budget in USD")
    check_parser.add_argument("--json", action="store_true", help="emit the full evaluation")
    check_parser.add_argument("shell_command", nargs=argparse.REMAINDER)

    run_parser = subparsers.add_parser(
        "run", help="adjudicate a shell command and, if allowed, execute it"
    )
    _add_policy_options(run_parser)
    run_parser.add_argument("--yes", action="store_true", help="auto-approve ask decisions")
    run_parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT_S, help="wall-clock limit in seconds"
    )
    run_parser.add_argument(
        "--max-output",
        type=int,
        default=DEFAULT_MAX_OUTPUT_BYTES,
        help="bytes captured per stream",
    )
    run_parser.add_argument("shell_command", nargs=argparse.REMAINDER)

    hook_parser = subparsers.add_parser(
        "hook",
        help="Claude Code PreToolUse hook: JSON on stdin, verdict JSON on stdout",
    )
    _add_policy_options(hook_parser)

    policy_parser = subparsers.add_parser("policy", help="policy tooling")
    policy_sub = policy_parser.add_subparsers(dest="policy_command", required=True)
    test_parser = policy_sub.add_parser("test", help="run the declarative policy corpus")
    test_parser.add_argument("--policy", help="policy YAML (default: the shipped policy)")
    test_parser.add_argument("--cases", help="case corpus JSON (default: the shipped corpus)")
    test_parser.add_argument("--quiet", action="store_true", help="summary only")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "version":
            return _cmd_version()
        if args.command == "parse":
            return _cmd_parse(args.shell_command)
        if args.command == "check":
            return _cmd_check(args)
        if args.command == "run":
            return _cmd_run(args)
        if args.command == "hook":
            from .hook import run_hook

            return run_hook(args)
        if args.command == "policy" and args.policy_command == "test":
            return _cmd_policy_test(args)
    except PolicyError as exc:
        print(f"seatbelt: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())