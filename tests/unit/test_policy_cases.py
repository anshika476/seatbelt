"""The declarative corpus, run exactly as `seatbelt policy test` runs it.

Cases marked as known gaps use strict xfail: when one starts passing, the suite
fails and forces the marker to be removed, which keeps the gap list honest.
"""

from __future__ import annotations

import pytest

from seatbelt.cases import default_cases_path, default_policy_path, load_cases, run_case
from seatbelt.policy import Policy

POLICY = Policy.load(default_policy_path())
CASES = load_cases(default_cases_path())

#: Kept in sync with docs/BUILD_LOG.md. Raising this without a fixture is a bug.
#: `chmod +s` left this list when it became a deny rule; multi-letter symbolic
#: chmod modes joined it, because shlex splits them and they are reported
#: unparsed rather than guessed at.
EXPECTED_KNOWN_GAPS = 4


def _ids() -> list[str]:
    return [case.name for case in CASES.cases]


@pytest.mark.parametrize("case", CASES.cases, ids=_ids())
def test_corpus_case(case, request: pytest.FixtureRequest) -> None:
    if case.is_known_gap:
        request.node.add_marker(
            pytest.mark.xfail(strict=True, reason=case.xfail or "known gap")
        )

    result = run_case(POLICY, CASES, case)

    assert result.decision == case.expected, (
        f"{case.name}: expected {case.expected}, got {result.decision} "
        f"({result.rule_id}: {result.reason})"
    )
    if case.rule:
        assert result.rule_id == case.rule, (
            f"{case.name}: expected rule {case.rule}, got {result.rule_id}"
        )


def test_corpus_has_unique_names() -> None:
    names = _ids()
    assert len(names) == len(set(names))


def test_known_gap_count_is_documented() -> None:
    gaps = [case for case in CASES.cases if case.is_known_gap]

    assert len(gaps) == EXPECTED_KNOWN_GAPS, [case.name for case in gaps]
    assert all(case.xfail for case in gaps), "every gap needs a reason"