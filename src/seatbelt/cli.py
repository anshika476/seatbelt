"""Command line entry point.

Frontends (``check``, ``parse``, ``policy``) are thin: they normalize a call,
ask the engine for a verdict, and report it. All judgement lives behind the
engine, so every frontend reports the same rule ids.

Exit codes:
    0  allow
    1  deny
    2  usage or policy error
    3  ask (including "the command could not be read with confidence")
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import __version__
from .action import normalize_shell
from .cases import default_cases_path, default_policy_path, load_cases, run_cases
from .engine import Engine
from .policy import EvalContext, Policy, PolicyError
from .shellparse import parse

EXIT_ALLOW = 0
EXIT_DENY = 1
EXIT_USAGE = 2
EXIT_ASK = 3


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


def _cmd_version() -> int:
    print(f"seatbelt {__version__}")
    return EXIT_ALLOW


def _cmd_parse(argv: Sequence[str]) -> int:
    tokens = list(argv)
    if tokens and tokens[0] == "--":
        tokens = tokens[1:]
    command = " ".join(tokens)
    if not command.strip():
        print("error: nothing to parse", file=sys.stderr)
        return EXIT_USAGE
    result = parse(command)
    print(json.dumps(result.to_dict(), indent=2))
    return EXIT_ALLOW if result.confident else EXIT_ASK


def _load_policy(path: str | None) -> Policy:
    return Policy.load(path or default_policy_path())


def _cmd_check(args: argparse.Namespace) -> int:
    tokens = list(args.shell_command)
    if tokens and tokens[0] == "--":
        tokens = tokens[1:]
    command = " ".join(tokens)
    if not command.strip():
        print("error: nothing to check", file=sys.stderr)
        return EXIT_USAGE

    policy = _load_policy(args.policy)
    workspace = args.workspace or policy.workspace
    ctx = EvalContext(
        workspace=workspace,
        cwd=args.cwd or workspace,
        policy_path=str(policy.source),
        audit_path=args.audit or "",
        budget_usd=args.budget,
    )
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
            line = (
                f"{mark}  {result.case.name.ljust(width)}  "
                f"expected={result.case.expected:5} actual={result.decision:5} "
                f"rule={result.rule_id}"
            )
            print(line)
            if result.counts_as_failure:
                print(f"        {result.reason}")

    failures = [result for result in results if result.counts_as_failure]
    gaps = [result for result in results if result.case.is_known_gap]
    passed = len(results) - len(failures)
    print(
        f"\n{passed}/{len(results)} cases behave as specified, "
        f"{len(failures)} failure(s), {len(gaps)} known gap(s)"
    )
    if gaps and not args.quiet:
        for result in gaps:
            print(f"  gap: {result.case.name} — {result.case.xfail}")
    return EXIT_ALLOW if not failures else EXIT_DENY


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #


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
        description=(
            "Print the parsed command as JSON. Exits 3 when the parser is not "
            "confident, which the engine treats as 'ask', never 'allow'."
        ),
    )
    parse_parser.add_argument(
        "shell_command",
        nargs=argparse.REMAINDER,
        help="the command to parse, for example: seatbelt parse -- rm -rf /",
    )

    check_parser = subparsers.add_parser(
        "check",
        help="adjudicate a shell command without running it",
        description="Print the verdict for a command. Exits 0 allow, 1 deny, 3 ask.",
    )
    check_parser.add_argument("--policy", help="policy YAML (default: the shipped policy)")
    check_parser.add_argument("--workspace", help="workspace root (default: from policy)")
    check_parser.add_argument("--cwd", help="working directory for relative paths")
    check_parser.add_argument("--audit", help="audit log path to protect")
    check_parser.add_argument("--budget", type=float, help="spend budget in USD")
    check_parser.add_argument("--json", action="store_true", help="emit the full evaluation")
    check_parser.add_argument(
        "shell_command",
        nargs=argparse.REMAINDER,
        help="the command to check, for example: seatbelt check -- rm -rf /",
    )

    policy_parser = subparsers.add_parser("policy", help="policy tooling")
    policy_sub = policy_parser.add_subparsers(dest="policy_command", required=True)
    test_parser = policy_sub.add_parser(
        "test", help="run the declarative policy corpus"
    )
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
        if args.command == "policy" and args.policy_command == "test":
            return _cmd_policy_test(args)
    except PolicyError as exc:
        print(f"seatbelt: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())