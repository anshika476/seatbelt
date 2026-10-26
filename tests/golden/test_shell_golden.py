"""Golden tests for the shell parser.

Each case asserts two things: what the parser is allowed to believe (confidence)
and what it must expose to policy. Bypass cases are first-class here — a parser
that only handles well-formed commands is worthless as a security control.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from seatbelt.shellparse import flatten, parse, pipes_into_shell

CASES_PATH = Path(__file__).parent / "shell_cases.json"
CASES = json.loads(CASES_PATH.read_text(encoding="utf-8"))["cases"]


def _ids() -> list[str]:
    return [case["name"] for case in CASES]


@pytest.mark.parametrize("case", CASES, ids=_ids())
def test_golden_case(case: dict) -> None:
    result = parse(case["command"])

    assert result.confident is case["confident"], (
        f"confidence mismatch for {case['command']!r}: notes={result.notes}"
    )

    if "note_contains" in case:
        joined = " | ".join(result.notes)
        assert case["note_contains"] in joined, f"expected note {case['note_contains']!r} in {joined!r}"

    if "pipes_into_shell" in case:
        assert bool(pipes_into_shell(result.root)) is case["pipes_into_shell"]

    exposed = [list(command.argv) for command in flatten(result.root)]
    for expected in case.get("exposes", []):
        assert any(argv[: len(expected)] == expected for argv in exposed), (
            f"expected {expected!r} to be exposed for {case['command']!r}; got {exposed}"
        )


def test_every_case_has_a_unique_name() -> None:
    names = _ids()
    assert len(names) == len(set(names))


def test_no_command_is_silently_dropped() -> None:
    """A confident parse must yield at least one command."""
    for case in CASES:
        result = parse(case["command"])
        if result.confident:
            assert flatten(result.root), f"{case['command']!r} parsed confidently but produced nothing"
