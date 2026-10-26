import json
from dataclasses import FrozenInstanceError

import pytest

from seatbelt.action import Action, ToolKind, Trust


def test_action_roundtrips_through_dict() -> None:
    action = Action(
        kind=ToolKind.FILE_WRITE,
        target="src/app.py",
        tool_name="write_file",
        cwd="/home/agent/project",
        args={"contents": "print('hi')\n"},
        trust=Trust.UNTRUSTED,
    )

    payload = action.to_dict()

    assert payload["kind"] == "file_write"
    assert payload["trust"] == "untrusted"
    assert json.loads(action.to_json()) == payload


def test_empty_target_is_rejected() -> None:
    with pytest.raises(ValueError):
        Action(kind=ToolKind.SHELL, target="   ")


def test_kind_must_be_a_tool_kind() -> None:
    with pytest.raises(TypeError):
        Action(kind="shell", target="ls")  # type: ignore[arg-type]


def test_actions_compare_by_value_and_are_immutable() -> None:
    action = Action(kind=ToolKind.NET, target="https://example.com")

    assert action == Action(kind=ToolKind.NET, target="https://example.com")
    assert action != Action(kind=ToolKind.NET, target="https://other.example")
    with pytest.raises(FrozenInstanceError):
        action.target = "https://evil.example"  # type: ignore[misc]
