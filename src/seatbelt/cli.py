"""Command line entry point.

Frontends (``run``, ``hook``, ``mcp``) are thin: they normalize a call, ask the
engine for a verdict, then either execute or refuse. All of the judgement lives
behind the engine, so every frontend reports the same rule ids.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="seatbelt",
        description="Action guardrails for AI agents.",
    )
    parser.add_argument("--version", action="version", version=f"seatbelt {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("version", help="print the installed version")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "version":
        print(f"seatbelt {__version__}")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
