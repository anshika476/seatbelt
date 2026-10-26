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
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Mapping
from urllib.parse import urlsplit

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance for type checkers
    from .shellparse import ParseResult

#: URLs embedded in a shell command. ``shlex`` splits ``https`` ``:`` ``//host``
#: into separate tokens because ``:`` and ``/`` are punctuation, so the raw
#: command is scanned for URLs instead of trying to reassemble them.
_URL_RE = re.compile(r"https?://[^\s'\"<>|;)]+")


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


# --------------------------------------------------------------------------- #
# Normalizers
# --------------------------------------------------------------------------- #
#
# Each normalizer turns a framework's payload into an Action plus whatever
# extra facts policy needs. They are pure: no filesystem writes, no network.
# Path normalizers do touch the filesystem to resolve symlinks, because a rule
# that compares strings would otherwise be defeated by a symlink out of the
# workspace.


def _resolve_path(path: str, cwd: str) -> str:
    """Resolve a possibly relative, possibly traversing path to an absolute one."""
    expanded = os.path.expanduser(path)
    if not os.path.isabs(expanded):
        expanded = os.path.join(cwd, expanded)
    return os.path.realpath(expanded)


def _within(path: str, root: str) -> bool:
    """True when ``path`` is ``root`` or sits beneath it."""
    try:
        return os.path.commonpath([path, root]) == os.path.commonpath([root, root])
    except ValueError:
        # Different drives on Windows, or a mix of absolute and relative.
        return False


def normalize_file(
    kind: ToolKind,
    path: str,
    *,
    workspace: str,
    cwd: str = ".",
    tool_name: str = "",
    contents: str | None = None,
) -> Action:
    """Normalize a file read or write.

    The action's target is the resolved path, so policy never has to reason
    about ``..`` or symlinks. Two facts travel in ``args``: ``escapes_workspace``
    and whether the raw path contained a traversal component, which is worth
    surfacing in the audit trail even when the final path is benign.
    """
    if kind not in (ToolKind.FILE_READ, ToolKind.FILE_WRITE):
        raise ValueError(f"normalize_file does not handle {kind.value}")

    resolved = _resolve_path(path, cwd)
    workspace_root = os.path.realpath(workspace)
    args: dict[str, Any] = {
        "resolved": resolved,
        "escapes_workspace": not _within(resolved, workspace_root),
        "has_traversal": ".." in path.replace("\\", "/").split("/"),
    }
    if contents is not None:
        args["contents"] = contents
        args["size"] = len(contents)
    return Action(
        kind=kind,
        target=resolved,
        tool_name=tool_name,
        cwd=cwd,
        args=args,
    )


def normalize_shell(
    command: str,
    *,
    cwd: str = ".",
    tool_name: str = "shell",
) -> tuple[Action, "ParseResult"]:
    """Normalize a shell command, returning the action and its parse result.

    The action's target is the raw command line: policy needs the original
    string for reporting, and the parsed tree for decisions. The parse result
    is returned separately because confidence is a property of the reading, not
    of the action.
    """
    from .shellparse import parse

    result = parse(command)
    return (
        Action(
            kind=ToolKind.SHELL,
            target=command,
            tool_name=tool_name,
            cwd=cwd,
            args={
                "confident": result.confident,
                "notes": list(result.notes),
                "urls": _URL_RE.findall(command),
            },
        ),
        result,
    )


def normalize_net(
    url: str,
    *,
    method: str = "GET",
    body: str = "",
    tool_name: str = "http",
    cwd: str = ".",
) -> Action:
    """Normalize an outbound HTTP request.

    Host and scheme are extracted here so the domain allowlist and the taint
    matcher both work from parsed parts rather than from substring searches of
    the whole URL.
    """
    parts = urlsplit(url)
    return Action(
        kind=ToolKind.NET,
        target=url,
        tool_name=tool_name,
        cwd=cwd,
        args={
            "method": method.upper(),
            "scheme": parts.scheme,
            "host": parts.hostname or "",
            "port": parts.port,
            "path": parts.path,
            "query": parts.query,
            "body": body,
        },
    )


def normalize_mcp(
    tool_name: str,
    arguments: Mapping[str, Any],
    *,
    cwd: str = ".",
) -> Action:
    """Normalize an MCP tool call.

    MCP arguments are opaque to Seatbelt, so the target is the tool name and the
    arguments travel verbatim for the taint matcher to scan.
    """
    return Action(
        kind=ToolKind.MCP,
        target=tool_name,
        tool_name=tool_name,
        cwd=cwd,
        args={"arguments": dict(arguments)},
    )

