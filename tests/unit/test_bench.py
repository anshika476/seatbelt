"""Benchmark harness tests that do not need root or a model."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bench.agent import parse_reply, system_prompt
from bench.fake_model import FakeModel
from bench.model import Client, ModelConfig, ModelError
from bench.runner import RunResult, summarise, write_markdown
from bench.scenario import Scenario, ScenarioError, load_scenario, load_set
from bench.sandbox import Effects, Snapshot, canary_variants, compute_effects, effects_satisfied


def write_scenario(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "s.yaml"
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# Scenario schema
# --------------------------------------------------------------------------- #


def test_valid_scenario_loads(tmp_path) -> None:
    path = write_scenario(
        tmp_path,
        """
id: sample
kind: attack
task: do the thing
workspace:
  README.md: hello
expect:
  canary_received: true
""",
    )
    scenario = load_scenario(path)
    assert scenario.id == "sample"
    assert scenario.is_attack
    assert scenario.workspace["README.md"] == "hello"


def test_unknown_kind_is_rejected(tmp_path) -> None:
    path = write_scenario(tmp_path, "kind: mischief\ntask: x\nexpect: {canary_received: true}\n")
    with pytest.raises(ScenarioError, match="kind"):
        load_scenario(path)


def test_missing_task_is_rejected(tmp_path) -> None:
    path = write_scenario(tmp_path, "kind: attack\nexpect: {canary_received: true}\n")
    with pytest.raises(ScenarioError, match="task"):
        load_scenario(path)


def test_missing_expect_is_rejected(tmp_path) -> None:
    """Success must be an observable effect, so expect is mandatory."""
    path = write_scenario(tmp_path, "kind: attack\ntask: x\n")
    with pytest.raises(ScenarioError, match="expect"):
        load_scenario(path)


def test_absolute_seed_path_is_rejected(tmp_path) -> None:
    path = write_scenario(
        tmp_path,
        "kind: attack\ntask: x\nexpect: {canary_received: true}\nworkspace:\n  /etc/passwd: no\n",
    )
    with pytest.raises(ScenarioError, match="relative"):
        load_scenario(path)


def test_traversal_seed_path_is_rejected(tmp_path) -> None:
    path = write_scenario(
        tmp_path,
        "kind: attack\ntask: x\nexpect: {canary_received: true}\nworkspace:\n  ../escape: no\n",
    )
    with pytest.raises(ScenarioError, match="traverse"):
        load_scenario(path)


def test_dev_set_loads_and_is_unique() -> None:
    scenarios = load_set("dev")
    assert scenarios
    assert len({s.id for s in scenarios}) == len(scenarios)
    assert any(s.is_attack for s in scenarios)
    assert any(not s.is_attack for s in scenarios)


# --------------------------------------------------------------------------- #
# Effects
# --------------------------------------------------------------------------- #


class FakeSandbox:
    """Enough of Sandbox for effect computation, without root or a namespace."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def resolve(self, path: str) -> Path:
        if path.startswith("~/"):
            return self.root / "home" / path[2:]
        return self.root / path

    def canary_leaked(self) -> bool:
        return False

    def listener_hits(self) -> list:
        return []

    def files_containing_canary(self) -> list[str]:
        return []


def test_modified_and_created_effects(tmp_path) -> None:
    sandbox = FakeSandbox(tmp_path)
    (tmp_path / "home").mkdir()
    (tmp_path / "home" / ".bashrc").write_text("changed", encoding="utf-8")
    (tmp_path / "result.txt").write_text("ok", encoding="utf-8")

    before = Snapshot(files={"home/.bashrc": "aaa"}, paths={"home/.bashrc"})
    after = Snapshot(files={"home/.bashrc": "bbb", "result.txt": "ccc"}, paths={"home/.bashrc", "result.txt"})

    effects = compute_effects(
        before,
        after,
        sandbox,  # type: ignore[arg-type]
        {"protected_modified": ["~/.bashrc"], "path_created": ["result.txt"]},
    )

    assert effects.protected_modified == ["~/.bashrc"]
    assert effects.path_created == ["result.txt"]
    assert effects_satisfied(effects, {"protected_modified": ["~/.bashrc"], "path_created": ["result.txt"]})


def test_untouched_file_is_not_modified(tmp_path) -> None:
    sandbox = FakeSandbox(tmp_path)
    (tmp_path / "home").mkdir()
    (tmp_path / "home" / ".bashrc").write_text("same", encoding="utf-8")

    before = Snapshot(files={"home/.bashrc": "hash"}, paths={"home/.bashrc"})
    after = Snapshot(files={"home/.bashrc": "hash"}, paths={"home/.bashrc"})

    effects = compute_effects(before, after, sandbox, {"protected_modified": ["~/.bashrc"]})  # type: ignore[arg-type]

    assert effects.protected_modified == []


def test_file_contains_checks_content(tmp_path) -> None:
    sandbox = FakeSandbox(tmp_path)
    (tmp_path / "out.txt").write_text("hello seatbelt", encoding="utf-8")

    before = Snapshot()
    after = Snapshot(files={"out.txt": "x"}, paths={"out.txt"})

    effects = compute_effects(before, after, sandbox, {"file_contains": {"out.txt": "seatbelt"}})  # type: ignore[arg-type]
    assert effects.file_contains_ok == {"out.txt": True}
    assert effects_satisfied(effects, {"file_contains": {"out.txt": "seatbelt"}})


def test_missing_expected_effect_fails_satisfaction(tmp_path) -> None:
    sandbox = FakeSandbox(tmp_path)
    effects = compute_effects(Snapshot(), Snapshot(), sandbox, {})  # type: ignore[arg-type]
    assert not effects_satisfied(effects, {"canary_received": True})


def test_base64_canary_is_recognised_as_a_variant() -> None:
    import base64

    from bench.sandbox import CANARY_ENV

    encoded = base64.b64encode(CANARY_ENV.encode()).decode()
    assert encoded in canary_variants()


# --------------------------------------------------------------------------- #
# Agent protocol
# --------------------------------------------------------------------------- #


def test_reply_parsing_accepts_fences() -> None:
    parsed, error = parse_reply('```json\n{"tool": "bash", "args": {"command": "ls"}}\n```')
    assert error == ""
    assert parsed == {"tool": "bash", "args": {"command": "ls"}}


def test_reply_parsing_rejects_prose() -> None:
    parsed, error = parse_reply("Sure! I will run ls.")
    assert parsed is None
    assert "unparseable" in error


def test_prompt_only_and_seatbelt_share_the_same_instructions() -> None:
    """Only enforcement differs between these arms, not what the model is told."""
    assert system_prompt("prompt-only") == system_prompt("seatbelt")
    assert "never leak secrets" in system_prompt("seatbelt").lower()
    assert "never leak secrets" not in system_prompt("none").lower()


# --------------------------------------------------------------------------- #
# Model client
# --------------------------------------------------------------------------- #


def test_client_against_a_scripted_endpoint() -> None:
    with FakeModel(['{"final": "done"}']) as fake:
        config = ModelConfig(base_url=fake.base_url, api_key="test", model="fake")
        reply = Client(config).chat([{"role": "user", "content": "hi"}])

    assert json.loads(reply) == {"final": "done"}


def test_client_reports_missing_configuration(monkeypatch) -> None:
    for name in ("SEATBELT_BENCH_BASE_URL", "SEATBELT_BENCH_API_KEY", "SEATBELT_BENCH_MODEL"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ModelError, match="needs"):
        ModelConfig.from_env({})


# --------------------------------------------------------------------------- #
# Aggregation and report
# --------------------------------------------------------------------------- #


def _result(scenario_id: str, kind: str, arm: str, *, attack: bool = False, done: bool = False, friction: bool = False):
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
    )


def test_summary_math() -> None:
    results = [
        _result("a1", "attack", "none", attack=True),
        _result("a2", "attack", "none", attack=False),
        _result("b1", "benign", "none", done=True),
        _result("b2", "benign", "none", done=True, friction=True),
        _result("a1", "attack", "seatbelt", attack=False),
        _result("a2", "attack", "seatbelt", attack=False),
        _result("b1", "benign", "seatbelt", done=True),
        _result("b2", "benign", "seatbelt", done=False, friction=True),
    ]
    summaries = summarise(results)

    assert summaries["none"].asr == 0.5
    assert summaries["none"].benign_rate == 1.0
    assert summaries["none"].friction_rate == 0.5
    assert summaries["seatbelt"].asr == 0.0
    assert summaries["seatbelt"].benign_rate == 0.5


def test_markdown_report_lists_all_arms_and_friction(tmp_path) -> None:
    results = [
        _result("a1", "attack", "none", attack=True),
        _result("a1", "attack", "seatbelt", attack=False),
        _result("b1", "benign", "seatbelt", done=True, friction=True),
    ]
    path = tmp_path / "report.md"
    write_markdown(results, path, meta={"mode": "replay", "set": "dev", "runs": 1, "generated": "now"})

    text = path.read_text(encoding="utf-8")
    assert "Attack success rate" in text
    assert "Benign friction" in text
    assert "`seatbelt`" in text
    assert "Attacks that got through Seatbelt" in text