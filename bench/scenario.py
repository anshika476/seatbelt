"""Scenario loading and validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

BENCH_ROOT = Path(__file__).resolve().parent
SCENARIO_ROOT = BENCH_ROOT / "scenarios"

KINDS = {"attack", "benign"}


class ScenarioError(ValueError):
    """A scenario file is missing, malformed or unsafe."""


@dataclass(frozen=True, slots=True)
class Scenario:
    id: str
    name: str
    kind: str
    task: str
    category: str = "uncategorised"
    notes: str = ""
    workspace: Mapping[str, str] = field(default_factory=dict)
    home: Mapping[str, str] = field(default_factory=dict)
    pages: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    listener: Mapping[str, str] = field(default_factory=dict)
    expect: Mapping[str, Any] = field(default_factory=dict)
    max_steps: int = 8
    source: str = ""

    @property
    def is_attack(self) -> bool:
        return self.kind == "attack"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "category": self.category,
            "max_steps": self.max_steps,
            "expect": dict(self.expect),
        }


def _text(mapping: Mapping[str, Any] | None, key: str) -> dict[str, str]:
    value = (mapping or {}).get(key)
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ScenarioError(f"{key} must be a mapping of relative path to text")
    return {str(k): str(v) for k, v in value.items()}


def _reject_unsafe_paths(scenario_id: str, paths: Mapping[str, str], label: str) -> None:
    for relative in paths:
        candidate = Path(relative)
        if candidate.is_absolute():
            raise ScenarioError(
                f"{scenario_id}: {label} path {relative!r} must be relative to the sandbox"
            )
        if ".." in candidate.parts:
            raise ScenarioError(
                f"{scenario_id}: {label} path {relative!r} may not traverse out of the sandbox"
            )


def load_scenario(path: Path) -> Scenario:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ScenarioError(f"{path.name}: not valid YAML: {exc}") from exc
    if not isinstance(data, Mapping):
        raise ScenarioError(f"{path.name}: scenario must be a mapping")

    scenario_id = str(data.get("id") or path.stem)
    kind = str(data.get("kind") or "")
    if kind not in KINDS:
        raise ScenarioError(f"{scenario_id}: kind must be one of {sorted(KINDS)}")

    task = str(data.get("task") or "").strip()
    if not task:
        raise ScenarioError(f"{scenario_id}: task is required")

    expect = data.get("expect") or {}
    if not isinstance(expect, Mapping):
        raise ScenarioError(f"{scenario_id}: expect must be a mapping")
    if not expect:
        raise ScenarioError(
            f"{scenario_id}: expect is required — success must be an observable effect"
        )

    workspace = _text(data, "workspace")
    home = _text(data, "home")
    _reject_unsafe_paths(scenario_id, workspace, "workspace")
    _reject_unsafe_paths(scenario_id, home, "home")

    pages = data.get("pages") or {}
    if not isinstance(pages, Mapping):
        raise ScenarioError(f"{scenario_id}: pages must be a mapping of URL to page")

    listener = data.get("listener") or {}
    if not isinstance(listener, Mapping):
        raise ScenarioError(f"{scenario_id}: listener must be a mapping of path to body")

    return Scenario(
        id=scenario_id,
        name=str(data.get("name") or scenario_id),
        kind=kind,
        task=task,
        category=str(data.get("category") or "uncategorised"),
        notes=str(data.get("notes") or ""),
        workspace=workspace,
        home=home,
        pages={str(k): dict(v or {}) for k, v in pages.items()},
        listener={str(k): str(v) for k, v in listener.items()},
        expect=dict(expect),
        max_steps=int(data.get("max_steps") or 8),
        source=str(path),
    )


def load_set(name: str) -> list[Scenario]:
    """Load a scenario set by directory name: ``dev`` or ``holdout``."""
    directory = SCENARIO_ROOT / name
    if not directory.is_dir():
        raise ScenarioError(f"no scenario set at {directory}")
    scenarios = [load_scenario(path) for path in sorted(directory.glob("*.yaml"))]
    ids = [scenario.id for scenario in scenarios]
    duplicates = {value for value in ids if ids.count(value) > 1}
    if duplicates:
        raise ScenarioError(f"duplicate scenario ids in {name}: {sorted(duplicates)}")
    return scenarios


def load_all_sets() -> dict[str, list[Scenario]]:
    sets: dict[str, list[Scenario]] = {}
    for directory in sorted(SCENARIO_ROOT.iterdir()):
        if directory.is_dir() and any(directory.glob("*.yaml")):
            sets[directory.name] = load_set(directory.name)
    return sets