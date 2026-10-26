"""Shapes emitted by qwen2.5:14b: {tool: {args}} and bare arguments."""

from __future__ import annotations

import pytest

from bench.agent import classify_reply, extract_call, system_prompt


# --------------------------------------------------------------------------- #
# {"<known_tool>": {args}}
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "tool", "args"),
    [
        ({"bash": {"command": "cat README.md"}}, "bash", {"command": "cat README.md"}),
        ({"read_file": {"path": "README.md"}}, "read_file", {"path": "README.md"}),
        ({"fetch": {"url": "https://docs.example/x"}}, "fetch", {"url": "https://docs.example/x"}),
        ({"write_file": {"path": "a.txt", "content": "hi"}}, "write_file", {"path": "a.txt", "content": "hi"}),
    ],
)
def test_single_key_tool_shape(value, tool, args) -> None:
    call, error = extract_call(value)
    assert error == ""
    assert call == {"tool": tool, "args": args}


def test_unknown_single_key_is_rejected() -> None:
    call, error = extract_call({"teleport": {"to": "mars"}})
    assert call is None
    assert "no tool name" in error


def test_single_known_key_without_object_is_rejected() -> None:
    call, error = extract_call({"bash": "cat README.md"})
    assert call is None
    assert "must be an object" in error


def test_two_tool_keys_are_rejected() -> None:
    """Two candidate tools in one object is ambiguous, so it is refused."""
    value = {"bash": {"command": "ls"}, "fetch": {"url": "https://docs.example"}}
    call, error = extract_call(value)
    assert call is None
    assert error


def test_reply_with_a_tool_key_and_another_key_uses_the_documented_shape() -> None:
    call, error = extract_call({"tool": "bash", "args": {"command": "ls"}, "extra": 1})
    assert error == ""
    assert call == {"tool": "bash", "args": {"command": "ls"}}


# --------------------------------------------------------------------------- #
# Bare arguments
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "tool"),
    [
        ({"command": "pip install -r requirements.txt"}, "bash"),
        ({"url": "https://docs.example/x"}, "fetch"),
        ({"path": "README.md"}, "read_file"),
        ({"path": "out.txt", "content": "hi"}, "write_file"),
    ],
)
def test_bare_arguments_resolve_when_unambiguous(value, tool) -> None:
    call, error = extract_call(value)
    assert error == ""
    assert call == {"tool": tool, "args": value}


def test_ambiguous_bare_arguments_are_rejected() -> None:
    """Two tools taking the same argument set cannot be told apart."""
    call, error = extract_call(
        {"x": 1}, required={"alpha": ("x",), "beta": ("x",)}
    )
    assert call is None
    assert "ambiguous" in error


def test_bare_arguments_matching_nothing_are_rejected() -> None:
    call, error = extract_call({"destination": "/tmp"})
    assert call is None
    assert "no tool name" in error


def test_bare_arguments_that_only_partly_match_are_rejected() -> None:
    """{"path"} is read_file; adding an unknown key matches no tool exactly."""
    call, error = extract_call({"path": "x", "mode": "append"})
    assert call is None
    assert "no tool name" in error


# --------------------------------------------------------------------------- #
# Through the classifier
# --------------------------------------------------------------------------- #


def test_classifier_accepts_the_new_shapes() -> None:
    for reply in (
        '{"bash": {"command": "cat README.md"}}',
        '{"command": "cat README.md"}',
        '{"fetch": {"url": "https://docs.example/x"}}',
    ):
        kind, payload, error = classify_reply(reply)
        assert kind == "call", (reply, kind, error)
        assert payload is not None


def test_classifier_still_rejects_unknown_shapes() -> None:
    kind, payload, error = classify_reply('{"destination": "/tmp"}')
    assert kind == "error"
    assert payload is None
    assert error


# --------------------------------------------------------------------------- #
# Prompt
# --------------------------------------------------------------------------- #


def test_prompt_states_the_exact_format() -> None:
    prompt = system_prompt("none")

    assert '{"tool": "<tool name>", "args": {...}}' in prompt
    assert "exactly one JSON object and nothing else" in prompt
    assert '{"tool": "read_file", "args": {"path": "README.md"}}' in prompt


def test_prompt_lists_every_tool_with_its_argument_names() -> None:
    prompt = system_prompt("none")

    for name, args in (
        ("bash", "command"),
        ("read_file", "path"),
        ("write_file", "path, content"),
        ("fetch", "url"),
    ):
        assert f"- {name}  args: {args}" in prompt


def test_base_prompt_is_identical_across_arms() -> None:
    base = system_prompt("none")
    assert base in system_prompt("prompt-only")
    assert base in system_prompt("seatbelt")
    assert "never leak secrets" not in base