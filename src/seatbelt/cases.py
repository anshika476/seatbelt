"""Declarative policy cases, shared by `seatbelt policy test` and the test suite.

One corpus, two consumers: the CLI proves the installed default policy behaves,
and pytest runs the same file so a rule change cannot silently regress. Cases
marked ``xfail`` are known gaps — the expectation records what *should* happen,
so when the gap is closed the case starts passing and pytest's strict xfail
turns that into a signal to remove the marker.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Iterable

from .action import ToolKind, normalize_file, normalize_mcp, normalize_net, normalize_shell
from .engine import Engine
from .policy import EvalContext, Policy


@dataclass(frozen=True, slots=True)
class Case:
    name: str
    tool: str
    value: str
    expected: str
    rule: str | None = None
    cwd: str | None = None
    xfail: str | None = None

    @property
    def is_known_gap(self) -> bool:
        return self.xfail is not None


@dataclass(frozen=True, slots=True)
class CaseSet:
    workspace: str
    home: str
    cases: tuple[Case, ...]

    def __len__(self) -> int:
        return len(self.cases)


@dataclass(frozen=True, slots=True)
class CaseResult:
    case: Case
    decision: str
    rule_id: str
    reason: str

    @property
    def as_expected(self) -> bool:
        if self.decision != self.case.expected:
            return False
        if self.case.rule and self.rule_id != self.case.rule:
            return False
        return True

    @property
    def counts_as_failure(self) -> bool:
        if self.case.is_known_gap:
            return False
        return not self.as_expected


def _data_path(name: str) -> Path:
    return Path(str(resources.files("seatbelt").joinpath("data", name)))


def default_policy_path() -> Path:
    return _data_path("default.yaml")


def default_cases_path() -> Path:
    return _data_path("cases.json")


def _case_from_dict(raw: dict[str, Any]) -> Case:
    return Case(
        name=str(raw["name"]),
        tool=str(raw["tool"]),
        value=str(raw.get("command") or raw.get("path") or raw.get("url") or raw.get("name") or ""),
        expected=str(raw["decision"]),
        rule=raw.get("rule"),
        cwd=raw.get("cwd"),
        xfail=raw.get("xfail"),
    )


def load_cases(path: str | Path | None = None) -> CaseSet:
    source = Path(path) if path else default_cases_path()
    data = json.loads(Path(source).read_text(encoding="utf-8"))
    return CaseSet(
        workspace=str(data["workspace"]),
        home=str(data["home"]),
        cases=tuple(_case_from_dict(raw) for raw in data["cases"]),
    )


def build_context(
    cases: CaseSet, case: Case, policy_path: str | Path
) -> EvalContext:
    workspace = cases.workspace
    return EvalContext(
        workspace=workspace,
        home=cases.home,
        cwd=case.cwd or workspace,
        policy_path=str(policy_path),
        audit_path=str(Path(workspace) / ".seatbelt" / "audit.jsonl"),
    )


def run_case(policy: Policy, cases: CaseSet, case: Case) -> CaseResult:
    from .action import Action

    ctx = build_context(cases, case, policy.source)
    engine = Engine(policy, ctx)

    action: Action
    if case.tool == "shell":
        action, _ = normalize_shell(case.value, cwd=ctx.cwd)
    elif case.tool in {"file_read", "file_write"}:
        action = normalize_file(
            ToolKind.FILE_READ if case.tool == "file_read" else ToolKind.FILE_WRITE,
            case.value,
            workspace=ctx.workspace,
            cwd=ctx.cwd,
        )
    elif case.tool == "net":
        action = normalize_net(case.value)
    elif case.tool == "mcp":
        action = normalize_mcp(case.value, {})
    else:
        raise ValueError(f"case {case.name!r}: unknown tool {case.tool!r}")

    evaluation = engine.evaluate(action)
    return CaseResult(
        case=case,
        decision=evaluation.verdict.decision.value,
        rule_id=evaluation.verdict.rule_id,
        reason=evaluation.verdict.reason,
    )


def run_cases(
    policy: Policy, cases: CaseSet, only: Iterable[str] | None = None
) -> list[CaseResult]:
    wanted = set(only) if only else None
    results = []
    for case in cases.cases:
        if wanted and case.name not in wanted:
            continue
        results.append(run_case(policy, cases, case))
    return results