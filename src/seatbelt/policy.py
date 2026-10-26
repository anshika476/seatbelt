"""Deterministic policy engine.

Rules are YAML and are evaluated by **severity, not position**: any matching
deny wins, then any ask, then any allow, then the policy default. Authoring
order therefore cannot accidentally shadow a deny with an allow.

Three kinds of probe carry risk that a plain rule should not be able to wave
through — inline interpreter code, commands the parser could not read, and
execution of a file the agent itself just created. An ``allow`` rule only
covers those when it opts in explicitly with ``allow_inline``,
``allow_unparsed`` or ``allow_agent_created``. ``deny`` and ``ask`` rules match
them normally.

Nothing here calls a model. Given the same probe and context, the same verdict
comes out, which is what makes the benchmark meaningful.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from .action import ToolKind


class PolicyError(Exception):
    """Raised when a policy file is missing, malformed or inconsistent."""


class Decision(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"

    @property
    def severity(self) -> int:
        return {"allow": 0, "ask": 1, "deny": 2}[self.value]

    @classmethod
    def parse(cls, value: str) -> "Decision":
        try:
            return cls(str(value).lower())
        except ValueError as exc:
            raise PolicyError(f"unknown decision {value!r}: expected allow, ask or deny") from exc


@dataclass(frozen=True, slots=True)
class Probe:
    """One question put to the policy.

    A shell command produces many probes: one per command in the tree, one per
    redirect target, one per ``tee``/``dd``/``mv`` destination, and so on. The
    engine merges their verdicts.
    """

    kind: ToolKind
    target: str
    argv: tuple[str, ...] = ()
    detail: str = "command"
    resolved: str = ""
    inline_code: bool = False
    unparsed: bool = False
    agent_created: bool = False
    contents: str = ""


@dataclass
class EvalContext:
    """Everything the policy needs to know about where the agent is running."""

    workspace: str
    home: str = field(default_factory=lambda: os.path.expanduser("~"))
    cwd: str = "."
    policy_path: str = ""
    audit_path: str = ""
    created_files: set[str] = field(default_factory=set)
    created_contents: dict[str, str] = field(default_factory=dict)
    spent_usd: float = 0.0
    budget_usd: float | None = None
    secrets: Any = None
    taint: Any = None
    strict: bool = False
    secret_read: bool = False

    @property
    def clean_session(self) -> bool:
        """True until the session has read anything it does not control.

        "Clean" is deliberately narrow: no untrusted content, and no credential.
        A session that read either has lost the right to have its own scripts
        executed without a question.
        """
        return not self.strict and not self.secret_read


@dataclass(frozen=True, slots=True)
class Verdict:
    decision: Decision
    rule_id: str
    reason: str
    matches: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Rule:
    """One YAML rule. Every populated matcher is ANDed with the others."""

    id: str
    decision: Decision
    reason: str = ""
    kind: str | None = None
    command: tuple[str, ...] = ()
    path: tuple[str, ...] = ()
    host: tuple[str, ...] = ()
    tool: tuple[str, ...] = ()
    detail: tuple[str, ...] = ()
    flags_any: tuple[re.Pattern[str], ...] = ()
    flags_all: tuple[re.Pattern[str], ...] = ()
    flags_none: tuple[re.Pattern[str], ...] = ()
    within_workspace: bool | None = None
    allow_inline: bool = False
    allow_unparsed: bool = False
    allow_agent_created: bool = False
    fallback: bool = False

    # -- matching --------------------------------------------------------- #

    def matches(self, probe: Probe, ctx: EvalContext) -> bool:
        if self.kind and self.kind != probe.kind.value:
            return False
        if self.detail and probe.detail not in self.detail:
            return False
        if self.command and not any(
            fnmatch.fnmatchcase(probe.target, pattern) for pattern in self.command
        ):
            return False
        if self.tool and not any(
            fnmatch.fnmatchcase(probe.target, pattern) for pattern in self.tool
        ):
            return False
        if self.host and not any(
            fnmatch.fnmatchcase(probe.target.lower(), pattern.lower()) for pattern in self.host
        ):
            return False
        if self.path and not any(
            fnmatch.fnmatchcase(probe.resolved or probe.target, _expand(pattern, ctx.home))
            for pattern in self.path
        ):
            return False
        if self.within_workspace is not None:
            inside = _within(probe.resolved or probe.target, ctx.workspace)
            if inside is not self.within_workspace:
                return False
        if self.flags_any and not any(
            pattern.search(token) for pattern in self.flags_any for token in probe.argv
        ):
            return False
        if self.flags_all:
            for pattern in self.flags_all:
                if not any(pattern.search(token) for token in probe.argv):
                    return False
        if self.flags_none and any(
            pattern.search(token) for pattern in self.flags_none for token in probe.argv
        ):
            return False
        return True


def _expand(pattern: str, home: str) -> str:
    """Expand ``~`` and ``$HOME`` at match time, when home is known."""
    if pattern == "~":
        return os.path.realpath(home)
    if pattern.startswith("~/"):
        return os.path.join(os.path.realpath(home), pattern[2:])
    return pattern.replace("$HOME", os.path.realpath(home))


def _within(path: str, root: str) -> bool:
    if not path or not root:
        return False
    try:
        return os.path.commonpath([os.path.realpath(path), os.path.realpath(root)]) == os.path.realpath(root)
    except ValueError:
        return False


def _as_tuple(value: Any, field_name: str, rule_id: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        return tuple(value)
    raise PolicyError(f"rule {rule_id!r}: {field_name} must be a string or list of strings")


def _compile_all(value: Any, field_name: str, rule_id: str) -> tuple[re.Pattern[str], ...]:
    patterns = _as_tuple(value, field_name, rule_id)
    try:
        return tuple(re.compile(pattern) for pattern in patterns)
    except re.error as exc:
        raise PolicyError(f"rule {rule_id!r}: bad regex in {field_name}: {exc}") from exc


_ALLOWED_RULE_KEYS = {
    "id",
    "match",
    "decision",
    "reason",
    "description",
    "fallback",
}
_ALLOWED_MATCH_KEYS = {
    "kind",
    "command",
    "path",
    "host",
    "tool",
    "detail",
    "flags_any",
    "flags_all",
    "flags_none",
    "within_workspace",
    "allow_inline",
    "allow_unparsed",
    "allow_agent_created",
}


def _rule_from_dict(raw: Mapping[str, Any], index: int) -> Rule:
    rule_id = str(raw.get("id") or f"rule[{index}]")
    unknown = set(raw) - _ALLOWED_RULE_KEYS
    if unknown:
        raise PolicyError(f"rule {rule_id!r}: unknown keys {sorted(unknown)}")
    match = raw.get("match") or {}
    if not isinstance(match, Mapping):
        raise PolicyError(f"rule {rule_id!r}: match must be a mapping")
    unknown = set(match) - _ALLOWED_MATCH_KEYS
    if unknown:
        raise PolicyError(f"rule {rule_id!r}: unknown match keys {sorted(unknown)}")
    kind = match.get("kind")
    if kind is not None and kind not in {k.value for k in ToolKind}:
        raise PolicyError(f"rule {rule_id!r}: unknown kind {kind!r}")
    return Rule(
        id=rule_id,
        decision=Decision.parse(raw.get("decision", "ask")),
        reason=str(raw.get("reason") or raw.get("description") or rule_id),
        kind=kind,
        command=_as_tuple(match.get("command"), "command", rule_id),
        path=_as_tuple(match.get("path"), "path", rule_id),
        host=_as_tuple(match.get("host"), "host", rule_id),
        tool=_as_tuple(match.get("tool"), "tool", rule_id),
        detail=_as_tuple(match.get("detail"), "detail", rule_id),
        flags_any=_compile_all(match.get("flags_any"), "flags_any", rule_id),
        flags_all=_compile_all(match.get("flags_all"), "flags_all", rule_id),
        flags_none=_compile_all(match.get("flags_none"), "flags_none", rule_id),
        within_workspace=match.get("within_workspace"),
        allow_inline=bool(match.get("allow_inline", False)),
        allow_unparsed=bool(match.get("allow_unparsed", False)),
        allow_agent_created=bool(match.get("allow_agent_created", False)),
        fallback=bool(raw.get("fallback", False)),
    )


class Policy:
    """A loaded rule set."""

    def __init__(
        self,
        rules: Iterable[Rule],
        *,
        default: Decision = Decision.ASK,
        protected: Iterable[str] = (),
        workspace: str = "~",
        source: str = "<memory>",
    ) -> None:
        self.rules = tuple(rules)
        self.default = default
        self.protected = tuple(protected)
        self.workspace = workspace
        self.source = source
        self._by_id = {rule.id: rule for rule in rules}
        ids = [rule.id for rule in self.rules]
        duplicates = {rule_id for rule_id in ids if ids.count(rule_id) > 1}
        if duplicates:
            raise PolicyError(f"duplicate rule ids: {sorted(duplicates)}")

    # -- loading ---------------------------------------------------------- #

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        path = Path(path)
        if not path.is_file():
            raise PolicyError(f"policy file not found: {path}")
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise PolicyError(f"policy file is not valid YAML: {exc}") from exc
        policy = cls.from_dict(data, source=str(path))
        return policy

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, source: str = "<memory>") -> "Policy":
        if not isinstance(data, Mapping):
            raise PolicyError("policy must be a mapping")
        version = data.get("version", 1)
        if version != 1:
            raise PolicyError(f"unsupported policy version {version!r}: this build reads version 1")
        raw_rules = data.get("rules") or []
        if not isinstance(raw_rules, list):
            raise PolicyError("rules must be a list")
        rules = [_rule_from_dict(raw, index) for index, raw in enumerate(raw_rules)]
        protected_block = data.get("protected") or {}
        if isinstance(protected_block, Mapping):
            protected = _as_tuple(protected_block.get("paths"), "protected.paths", "<policy>")
        else:
            protected = _as_tuple(protected_block, "protected", "<policy>")
        return cls(
            rules,
            default=Decision.parse(data.get("default", "ask")),
            protected=protected,
            workspace=str(data.get("workspace") or "~"),
            source=source,
        )

    # -- evaluation ------------------------------------------------------- #

    def is_fallback(self, rule_id: str) -> bool:
        """True when ``rule_id`` is a catch-all rather than a specific rule.

        Used when merging probe verdicts: at equal severity a specific rule
        explains the outcome better than "anything else is a question".
        """
        rule = self._by_id.get(rule_id)
        return bool(rule and rule.fallback)

    def protected_match(self, path: str, ctx: EvalContext) -> str | None:
        """Return the pattern that protects ``path``, if any.

        The policy file and the audit log protect themselves; they are added
        here rather than written into YAML so a policy cannot forget them.
        """
        candidates = list(self.protected)
        for extra in (ctx.policy_path, ctx.audit_path):
            if extra:
                candidates.append(os.path.realpath(extra))
        for pattern in candidates:
            expanded = _expand(pattern, ctx.home)
            if fnmatch.fnmatchcase(path, expanded):
                return pattern
        return None

    def evaluate(self, probe: Probe, ctx: EvalContext) -> Verdict:
        if probe.kind is ToolKind.FILE_WRITE and probe.resolved:
            blocked = self.protected_match(probe.resolved, ctx)
            if blocked is not None:
                return Verdict(
                    Decision.DENY,
                    "protected.path",
                    f"write to a protected path ({blocked})",
                    ("protected.path",),
                )

        matches: list[Rule] = []
        for rule in self.rules:
            if not rule.matches(probe, ctx):
                continue
            if rule.decision is Decision.ALLOW:
                if probe.inline_code and not rule.allow_inline:
                    continue
                if probe.unparsed and not rule.allow_unparsed:
                    continue
                if probe.agent_created and not rule.allow_agent_created:
                    continue
            matches.append(rule)

        if not matches:
            return Verdict(
                self.default,
                "policy.default",
                f"no rule matched; policy default is {self.default.value}",
            )

        # A fallback rule ("anything else is a question") must not outrank a
        # specific allow, so it only counts when nothing else matched.
        specific = [rule for rule in matches if not rule.fallback]
        considered = specific or matches

        # Highest severity wins; ties go to the rule written first.
        ranked = sorted(
            enumerate(considered), key=lambda pair: (-pair[1].decision.severity, pair[0])
        )
        winner = ranked[0][1]
        return Verdict(
            winner.decision,
            winner.id,
            winner.reason,
            tuple(rule.id for rule in matches),
        )