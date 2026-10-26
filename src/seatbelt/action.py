"""Normalized representation of a tool call.

Policy code never inspects raw tool payloads. Every call an agent attempts is
first reduced to an :class:`Action`, so one rule set governs shell, file,
network and MCP calls without special-casing each agent framework.

Normalization is deliberately lossy in one direction only: it may add
structure (a parsed command tree, an absolute path), but it must never drop
information a policy could need. When a payload cannot be normalized, the
caller is expected to fail closed rather than guess.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class ToolKind(str, Enum):
    """The kinds of action Seatbelt knows how to adjudicate."""

    SHELL = "shell"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NET = "net"
    MCP = "mcp"


class Trust(str, Enum):
    """Provenance of the data carried by an action.

    ``TRUSTED`` is data the user supplied or that came from the repository.
    ``UNTRUSTED`` is anything the agent read from the outside world: web pages,
    issue bodies, files outside the workspace. ``SECRET`` marks a value that
    must never leave the machine.
    """

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    SECRET = "secret"


@dataclass(frozen=True, slots=True)
class Action:
    """A single tool call, normalized.

    Attributes:
        kind: Which family of action this is.
        target: The thing acted upon. A command string for ``SHELL``, a path
            for file kinds, a URL for ``NET``, a tool name for ``MCP``.
        tool_name: The agent-facing tool that produced this call, kept for
            audit and reporting.
        cwd: Working directory the call would run in, used to resolve relative
            paths and to decide whether a write stays inside the workspace.
        args: Structured arguments (an HTTP body, an MCP argument object, a
            file's proposed contents). Empty when the target carries it all.
        trust: Provenance of the arguments, propagated from taint tracking.

    Actions compare by value. They are not reliably hashable — ``args`` is a
    mapping — so use :meth:`to_json` when a stable key is needed.
    """

    kind: ToolKind
    target: str
    tool_name: str = ""
    cwd: str = "."
    args: Mapping[str, Any] = field(default_factory=dict)
    trust: Trust = Trust.TRUSTED

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ToolKind):
            raise TypeError(f"kind must be a ToolKind, got {type(self.kind).__name__}")
        if not self.target or not self.target.strip():
            raise ValueError("target must be a non-empty string")
        if not isinstance(self.trust, Trust):
            raise TypeError(f"trust must be a Trust, got {type(self.trust).__name__}")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe view, used by the audit log and the report."""
        return {
            "kind": self.kind.value,
            "target": self.target,
            "tool_name": self.tool_name,
            "cwd": self.cwd,
            "args": dict(self.args),
            "trust": self.trust.value,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False)
