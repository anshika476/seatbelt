"""Live reply parsing: lenient about shape, strict about what it will execute.

qwen2.5:14b appends prose or a second object after its tool call, which made the
old parser fail with "Extra data" and turned every step into an unknown tool.
These tests pin the lenient reading and the fail-closed rule that survives it.
"""

from __future__ import annotations

import json

from bench.agent import classify_reply, extract_call, parse_reply, run_agent

CALL = '{"tool": "bash", "args": {"command": "ls"}}'


# --------------------------------------------------------------------------- #
# Object extraction
# --------------------------------------------------------------------------- #


def test_plain_object_parses() -> None:
    value, error = parse_reply(CALL)
    assert error == ""
    assert value == {"tool": "bash", "args": {"command": "ls"}}


def test_trailing_text_is_ignored() -> None:
    """The qwen failure: a correct call followed by commentary."""
    value, error = parse_reply(CALL + "\n\nI will now list the files.")

    assert error == ""
    assert value is not None
    assert value["tool"] == "bash"


def test_two_objects_yield_the_first() -> None:
    value, error = parse_reply(CALL + '\n{"final": "done"}')

    assert error == ""
    assert value == {"tool": "bash", "args": {"command": "ls"}}


def test_json_code_fence_is_stripped() -> None:
    value, error = parse_reply(f"```json\n{CALL}\n```")

    assert error == ""
    assert value is not None
    assert value["tool"] == "bash"


def test_plain_code_fence_is_stripped() -> None:
    value, error = parse_reply(f"```\n{CALL}\n```")
    assert value is not None and value["tool"] == "bash"


def test_leading_prose_before_the_object_is_tolerated() -> None:
    value, error = parse_reply(f"Here is the call:\n{CALL}")
    assert value is not None and value["tool"] == "bash"


def test_garbage_is_an_error() -> None:
    value, error = parse_reply("Sure! I will run ls for you.")
    assert value is None
    assert "no JSON object" in error


def test_unterminated_object_is_an_error() -> None:
    value, error = parse_reply('{"tool": "bash", "args": {')
    assert value is None
    assert "unparseable" in error


def test_json_array_is_not_an_object() -> None:
    value, error = parse_reply('[{"tool": "bash"}]')
    assert value is None


# --------------------------------------------------------------------------- #
# Key variants
# --------------------------------------------------------------------------- #


def test_name_and_parameters_are_accepted() -> None:
    call, error = extract_call({"name": "bash", "parameters": {"command": "ls"}})
    assert error == ""
    assert call == {"tool": "bash", "args": {"command": "ls"}}


def test_arguments_as_a_json_string_is_decoded() -> None:
    call, error = extract_call(
        {"tool": "bash", "arguments": json.dumps({"command": "ls -la"})}
    )

    assert error == ""
    assert call == {"tool": "bash", "args": {"command": "ls -la"}}


def test_openai_function_shape_is_accepted() -> None:
    call, error = extract_call(
        {"function": {"name": "bash", "arguments": '{"command": "pwd"}'}}
    )

    assert error == ""
    assert call == {"tool": "bash", "args": {"command": "pwd"}}


def test_missing_args_means_empty_args() -> None:
    call, error = extract_call({"tool": "ls"})
    assert call == {"tool": "ls", "args": {}}
    assert error == ""


# --------------------------------------------------------------------------- #
# Fail-closed
# --------------------------------------------------------------------------- #


def test_missing_tool_name_is_an_error() -> None:
    call, error = extract_call({"args": {"command": "ls"}})
    assert call is None
    assert "no tool name" in error


def test_tool_name_must_be_a_string() -> None:
    call, error = extract_call({"tool": 42, "args": {}})
    assert call is None
    assert "not a string" in error


def test_arguments_string_must_be_valid_json() -> None:
    call, error = extract_call({"tool": "bash", "arguments": "command=ls"})
    assert call is None
    assert "not JSON" in error


def test_arguments_must_be_an_object() -> None:
    call, error = extract_call({"tool": "bash", "arguments": ["ls"]})
    assert call is None
    assert "not an object" in error


def test_reply_with_neither_call_nor_final_is_an_error() -> None:
    kind, payload, error = classify_reply('{"thought": "I should list files"}')
    assert kind == "error"
    assert payload is None
    assert error


def test_final_is_recognised() -> None:
    kind, payload, error = classify_reply('{"final": "all done"}')
    assert (kind, payload, error) == ("final", {"final": "all done"}, "")


def test_tool_call_wins_over_final_in_the_same_object() -> None:
    kind, payload, _ = classify_reply('{"tool": "bash", "args": {}, "final": "done"}')
    assert kind == "call"
    assert payload["tool"] == "bash"


# --------------------------------------------------------------------------- #
# Agent loop
# --------------------------------------------------------------------------- #


class ScriptedClient:
    def __init__(self, replies: list[str]) -> None:
        self.replies = list(replies)
        self.calls = 0

    def chat(self, messages):
        reply = self.replies[min(self.calls, len(self.replies) - 1)]
        self.calls += 1
        self.last_messages = messages
        return reply


class RecordingTools:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def call(self, tool: str, args):
        self.calls.append((tool, dict(args)))
        return f"result of {tool}"


def test_trailing_text_runs_the_call() -> None:
    client = ScriptedClient([CALL + "\nNow I will check the directory.", '{"final": "done"}'])
    tools = RecordingTools()

    run = run_agent(client, tools, "list files", arm="none", max_steps=3)  # type: ignore[arg-type]

    assert tools.calls == [("bash", {"command": "ls"})]
    assert run.steps[0].tool == "bash"


def test_one_correction_is_sent_and_the_run_continues() -> None:
    client = ScriptedClient(["Sure, I will list the files.", CALL, '{"final": "done"}'])
    tools = RecordingTools()

    run = run_agent(client, tools, "list files", arm="none", max_steps=3)  # type: ignore[arg-type]

    assert tools.calls == [("bash", {"command": "ls"})]
    assert run.finished
    assert run.steps[0].parse_error
    assert client.calls == 3


def test_correction_does_not_consume_a_step() -> None:
    """A bad reply plus good ones still leaves the full step budget for work."""
    client = ScriptedClient(["nope", CALL, CALL, '{"final": "done"}'])
    tools = RecordingTools()

    run = run_agent(client, tools, "list files", arm="none", max_steps=2)  # type: ignore[arg-type]

    # Two tool calls fit in a budget of two even though the model wasted a reply.
    assert len(tools.calls) == 2
    assert run.finished is False  # the final answer would have been step three


def test_second_failure_ends_the_run_without_executing() -> None:
    client = ScriptedClient(["garbage", "still garbage", CALL])
    tools = RecordingTools()

    run = run_agent(client, tools, "list files", arm="none", max_steps=5)  # type: ignore[arg-type]

    assert tools.calls == []
    assert run.finished is False
    assert client.calls == 2


def test_raw_reply_is_kept_in_the_transcript() -> None:
    client = ScriptedClient([CALL, '{"final": "done"}'])
    tools = RecordingTools()

    run = run_agent(client, tools, "list files", arm="none", max_steps=3)  # type: ignore[arg-type]
    payload = run.to_dict()

    assert payload["steps"][0]["reply"].startswith('{"tool": "bash"')
    assert payload["steps"][0]["tool"] == "bash"