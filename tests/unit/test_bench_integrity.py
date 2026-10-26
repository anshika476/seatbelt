"""Bench integrity: infrastructure failures must not be scored as results."""

from __future__ import annotations

import json

import pytest

from bench.agent import run_agent
from bench.runner import (
    EXIT_INVALID_RUNS,
    INVALID_RATE_LIMIT,
    RunResult,
    invalid_rate_exceeded,
    invalid_runs,
    invalid_warning,
    summarise,
    write_markdown,
)
from bench.scenario import Scenario
from bench.sandbox import Effects


def make_result(
    scenario_id: str,
    kind: str,
    arm: str,
    *,
    attack: bool = False,
    done: bool = False,
    friction: bool = False,
    status: str = "valid",
    reason: str = "",
) -> RunResult:
    scenario = Scenario(
        id=scenario_id, name=scenario_id, kind=kind, task="t", expect={"x": 1}
    )
    return RunResult(
        scenario=scenario,
        arm=arm,
        run_index=1,
        effects=Effects(),
        attack_succeeded=attack,
        benign_completed=done,
        benign_friction=friction,
        status=status,
        invalid_reason=reason,
    )


# --------------------------------------------------------------------------- #
# Exclusion from rates
# --------------------------------------------------------------------------- #


def test_invalid_attack_run_is_not_counted_as_a_blocked_attack() -> None:
    """The bug: an HTTP error looked like a successful defence."""
    results = [
        make_result("a1", "attack", "none", status="invalid", reason="HTTP 530"),
        make_result("a2", "attack", "none", attack=True),
    ]

    summary = summarise(results)["none"]

    assert summary.attack_runs == 1
    assert summary.attack_successes == 1
    assert summary.asr == 1.0


def test_invalid_benign_run_is_not_counted_as_a_failed_task() -> None:
    results = [
        make_result("b1", "benign", "none", status="invalid", reason="timeout"),
        make_result("b2", "benign", "none", done=True),
    ]

    summary = summarise(results)["none"]

    assert summary.benign_runs == 1
    assert summary.benign_completed == 1
    assert summary.benign_rate == 1.0


def test_invalid_runs_are_listed() -> None:
    results = [
        make_result("a1", "attack", "none"),
        make_result("a2", "attack", "none", status="invalid", reason="HTTP 530"),
    ]

    assert [r.scenario.id for r in invalid_runs(results)] == ["a2"]


def test_all_invalid_leaves_no_rates() -> None:
    results = [
        make_result("a1", "attack", "none", status="invalid", reason="boom"),
    ]

    assert summarise(results) == {}


# --------------------------------------------------------------------------- #
# Warning and exit code
# --------------------------------------------------------------------------- #


def test_warning_names_the_count_and_the_cause() -> None:
    results = [
        make_result("a1", "attack", "none", status="invalid", reason="HTTP 530"),
        make_result("a2", "attack", "none"),
    ]

    warning = invalid_warning(results)

    assert warning is not None
    assert "1 of 2 runs invalid" in warning
    assert "infrastructure" in warning


def test_no_warning_when_everything_is_valid() -> None:
    results = [make_result("a1", "attack", "none")]
    assert invalid_warning(results) is None


def test_more_than_five_percent_invalid_fails_the_run() -> None:
    # 2 of 30 is 6.7%, over the limit.
    results = [
        make_result("a1", "attack", "none", status="invalid", reason="HTTP 530"),
        make_result("a2", "attack", "none", status="invalid", reason="HTTP 530"),
    ] + [make_result(f"ok{i}", "attack", "none") for i in range(28)]

    assert invalid_rate_exceeded(results) is True


def test_five_percent_or_less_is_tolerated() -> None:
    # 1 of 30 is 3.3%.
    results = [make_result("a1", "attack", "none", status="invalid", reason="HTTP 530")] + [
        make_result(f"ok{i}", "attack", "none") for i in range(29)
    ]

    assert invalid_rate_exceeded(results) is False
    assert INVALID_RATE_LIMIT == 0.05


def test_exactly_five_percent_is_not_over_the_limit() -> None:
    results = [make_result("a1", "attack", "none", status="invalid", reason="x")] + [
        make_result(f"ok{i}", "attack", "none") for i in range(19)
    ]

    assert invalid_rate_exceeded(results) is False


def test_no_runs_is_not_an_error() -> None:
    assert invalid_rate_exceeded([]) is False
    assert invalid_warning([]) is None


def test_exit_code_is_distinct_from_zero() -> None:
    assert EXIT_INVALID_RUNS != 0


# --------------------------------------------------------------------------- #
# Transcript status
# --------------------------------------------------------------------------- #


class ExplodingClient:
    def chat(self, messages):
        raise RuntimeError("HTTP 530: origin is unreachable")


class RecordingTools:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def call(self, tool: str, args):
        self.calls.append((tool, dict(args)))
        return "ok"


def test_model_error_marks_the_transcript_as_infrastructure() -> None:
    run = run_agent(ExplodingClient(), RecordingTools(), "task", arm="none", max_steps=3)  # type: ignore[arg-type]

    assert run.finished is False
    assert "model call failed" in run.error
    assert "HTTP 530" in run.error
    assert run.to_dict()["error"]


def test_a_normal_finish_has_no_error() -> None:
    class Ok:
        def chat(self, messages):
            return '{"final": "done"}'

    run = run_agent(Ok(), RecordingTools(), "task", arm="none", max_steps=3)  # type: ignore[arg-type]

    assert run.finished is True
    assert run.error == ""


def test_report_lists_invalid_runs_and_excludes_them() -> None:
    results = [
        make_result("a1", "attack", "none", status="invalid", reason="HTTP 530"),
        make_result("a2", "attack", "none", attack=True),
    ]
    path = pytest.importorskip("pathlib").Path("/tmp/_seatbelt_invalid_report.md")

    write_markdown(results, path, meta={"mode": "live", "set": "dev", "runs": 1, "generated": "now"})
    text = path.read_text(encoding="utf-8")

    assert "invalid runs: 1 of 2" in text
    assert "## Invalid runs" in text
    assert "HTTP 530" in text
    # The attack rate is computed from the one valid run only.
    assert "(1/1)" in text
    assert "(0/1)" not in text


def test_csv_rows_carry_the_status() -> None:
    result = make_result("a1", "attack", "none", status="invalid", reason="HTTP 530")
    row = result.to_row()

    assert row["status"] == "invalid"
    assert row["invalid_reason"] == "HTTP 530"
