"""Command line entry point.

Frontends (``run``, ``hook``, ``mcp``) are thin: they normalize a call, ask the
engine for a verdict, then either execute or refuse. All of the judgement lives
behind the engine, so every frontend reports the same rule ids.

``parse`` exists for debugging and for the golden tests: it prints the tree the
policy engine will see, plus whether the parser trusts its own reading.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import __version__
from .shellparse import parse

#: Exit code for a command the parser could not confidently understand.
#: Distinct from a policy denial so callers can tell "ask" from "deny".
EXIT_UNSURE = 3


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

    return parser


def _cmd_version() -> int:
    print(f"seatbelt {__version__}")
    return 0


def _cmd_parse(argv: Sequence[str]) -> int:
    tokens = list(argv)
    if tokens and tokens[0] == "--":
        tokens = tokens[1:]
    command = " ".join(tokens)
    if not command.strip():
        print("error: nothing to parse", file=sys.stderr)
        return 2

    result = parse(command)
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.confident else EXIT_UNSURE


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "version":
        return _cmd_version()
    if args.command == "parse":
        return _cmd_parse(args.shell_command)
    return 2


if __name__ == "__main__":
    sys.exit(main())
