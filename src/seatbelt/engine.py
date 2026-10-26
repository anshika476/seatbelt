"""The adjudication pipeline: one Action in, one merged Verdict out.

The policy engine only understands probes — small, already-resolved questions.
This module is what turns an agent's tool call into those probes: it expands the
shell tree, resolves every path, and notices the shapes that hide an action
(``tee``, ``dd of=``, ``mv`` onto a protected file, ``find -delete``,
``busybox rm``, an interpreter fed code inline, a file the agent just wrote).

Merging follows the same precedence as the policy: deny beats ask beats allow.
A probe that cannot be resolved is itself an ``unparsed`` probe, so an
unresolvable path degrades to a question rather than an allow.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit

from .action import Action, ToolKind
from .policy import Decision, EvalContext, Policy, Probe, Verdict
from .shellparse import Command, ParseResult, flatten, parse, pipes_into_shell

#: Interpreters that can execute code handed to them directly.
INTERPRETERS = frozenset(
    {"python", "python3", "node", "deno", "bun", "perl", "ruby", "php", "lua", "Rscript"}
)

#: Flag that means "the next argument is code, not a file".
INLINE_FLAGS = {
    "python": ("-c",),
    "python3": ("-c",),
    "node": ("-e", "--eval", "-p", "--print"),
    "deno": ("eval",),
    "bun": ("-e", "--eval"),
    "perl": ("-e", "-E"),
    "ruby": ("-e",),
    "php": ("-r",),
    "lua": ("-e",),
    "Rscript": ("-e",),
}

#: Redirection operators that create or overwrite a file.
WRITE_REDIRECT_OPS = frozenset({">", ">>", ">|", "&>", "&>>", "1>", "1>>", "2>", "0>"})

#: Commands whose final argument is the destination path.
COPY_COMMANDS = frozenset({"cp", "mv", "install", "ln", "rsync"})

#: Flags that name the file a downloader should write.
DOWNLOAD_FLAGS = {
    "curl": ("-o", "--output"),
    "wget": ("-O", "--output-document"),
}

#: Commands that copy to a remote host over the network.
REMOTE_COPY_COMMANDS = frozenset({"rsync", "scp"})


def resolve_path(raw: str, ctx: EvalContext) -> tuple[str | None, str]:
    """Expand and normalize a path against the context.

    Returns ``(resolved, note)``. ``resolved`` is ``None`` when the path cannot
    be known statically — an unresolved variable, for example — and the caller
    turns that into an ``unparsed`` probe rather than guessing.
    """
    text = (raw or "").strip()
    if not text:
        return None, "empty path"
    home = os.path.realpath(os.path.expanduser(ctx.home))
    if text == "~":
        text = home
    elif text.startswith("~/"):
        text = os.path.join(home, text[2:])
    text = text.replace("${HOME}", home).replace("$HOME", home)
    if "$" in text:
        return None, f"unresolved variable in path: {raw}"
    if not os.path.isabs(text):
        text = os.path.join(os.path.abspath(ctx.cwd), text)
    return os.path.realpath(text), ""


def effective_command(command: Command) -> tuple[str, tuple[str, ...]]:
    """Return the command that will actually run, and its full argv.

    ``/bin/rm`` becomes ``rm``; ``busybox rm -rf x`` becomes ``rm -rf x``. Policy
    matches the effective name so there is one spelling of ``rm``, not five.
    """
    argv = command.argv
    if not argv:
        return "", ()
    name = os.path.basename(argv[0])
    if name == "busybox" and len(argv) > 1 and not argv[1].startswith("-"):
        return os.path.basename(argv[1]), tuple(argv[1:])
    return name, tuple(argv)


def _non_flags(args: Iterable[str]) -> list[str]:
    return [arg for arg in args if arg and not arg.startswith("-")]


def _last_non_flag(args: Iterable[str]) -> str | None:
    values = _non_flags(args)
    return values[-1] if values else None


def _first_non_flag(args: Iterable[str]) -> str | None:
    values = _non_flags(args)
    return values[0] if values else None


def _is_write_redirect(op: str) -> bool:
    return op in WRITE_REDIRECT_OPS or (op.endswith(">") and ">&" not in op)


def _has_inline_flag(name: str, argv: tuple[str, ...]) -> bool:
    flags = INLINE_FLAGS.get(name, ())
    return any(token in flags for token in argv[1:])


def download_target(name: str, argv: tuple[str, ...]) -> str | None:
    """Return the file a downloader was told to write, if any.

    ``curl -o path`` and ``wget -O path`` save to a named file without a shell
    redirect, so this is the only place the guardian learns the file exists.
    """
    flags = DOWNLOAD_FLAGS.get(name)
    if not flags:
        return None
    for index, token in enumerate(argv[1:], start=1):
        if token in flags:
            return argv[index + 1] if index + 1 < len(argv) else None
        for flag in flags:
            if token.startswith(flag + "="):
                value = token[len(flag) + 1 :]
                return value or None
        if len(token) > 2 and token[:2] in flags and token.startswith("-") and not token.startswith("--"):
            return token[2:]
    return None


def remote_host_from_argv(argv: tuple[str, ...]) -> str | None:
    """Find the remote host in an rsync/scp argv.

    The tokenizer splits ``user@host:/path`` at the colon because ``:`` is
    punctuation, so the host is usually the token immediately before a lone
    ``:``. A quoted destination keeps its colon and is handled by
    :func:`remote_host`.
    """
    for index, token in enumerate(argv):
        if token == ":" and 0 < index < len(argv) - 1:
            head = argv[index - 1]
            if head and not head.startswith(("-", "/")):
                candidate = head.rsplit("@", 1)[-1]
                if candidate:
                    return candidate
        if index > 0:
            candidate = remote_host(token)
            if candidate:
                return candidate
    return None


def remote_host(target: str) -> str | None:
    """Extract the host from an rsync/scp destination.

    Handles ``user@host:/path``, ``host:path`` and ``rsync://host/module``.
    A local path with no colon, or a URL with ``//``, is not a remote target.
    """
    if not target or target.startswith(("/", "./", "../", "~")):
        return None
    if "://" in target:
        parsed = urlsplit(target)
        return parsed.hostname or None
    if ":" not in target:
        return None
    head, _, _path = target.partition(":")
    if not head or "/" in head:
        return None
    return head.rsplit("@", 1)[-1] or None


@dataclass(frozen=True, slots=True)
class Evaluation:
    """A merged verdict plus the probes that produced it."""

    verdict: Verdict
    probes: tuple[tuple[Probe, Verdict], ...] = ()

    @property
    def decision(self) -> Decision:
        return self.verdict.decision

    def to_dict(self) -> dict[str, object]:
        return {
            "decision": self.verdict.decision.value,
            "rule_id": self.verdict.rule_id,
            "reason": self.verdict.reason,
            "matched_rules": list(self.verdict.matches),
            "probes": [
                {
                    "kind": probe.kind.value,
                    "target": probe.target,
                    "resolved": probe.resolved,
                    "detail": probe.detail,
                    "decision": verdict.decision.value,
                    "rule_id": verdict.rule_id,
                }
                for probe, verdict in self.probes
            ],
        }


class Engine:
    """Turns actions into probes, asks the policy, merges the answers."""

    def __init__(self, policy: Policy, ctx: EvalContext) -> None:
        self.policy = policy
        self.ctx = ctx
        self.ctx.cwd = os.path.abspath(ctx.cwd)
        self.ctx.workspace = os.path.realpath(ctx.workspace)

    # -- public ----------------------------------------------------------- #

    def evaluate(self, action: Action) -> Evaluation:
        if self.ctx.budget_usd is not None and self.ctx.spent_usd >= self.ctx.budget_usd:
            verdict = Verdict(
                Decision.DENY,
                "spend.budget",
                f"spend budget exhausted ({self.ctx.spent_usd:.2f} of {self.ctx.budget_usd:.2f})",
            )
            return Evaluation(verdict)

        probes = self._shell_probes(action) if action.kind is ToolKind.SHELL else self._single_probe(action)
        return self._merge(probes)

    # -- probes ----------------------------------------------------------- #

    def _single_probe(self, action: Action) -> list[Probe]:
        if action.kind in (ToolKind.FILE_READ, ToolKind.FILE_WRITE):
            resolved, note = resolve_path(action.target, self.ctx)
            if resolved is None:
                return [Probe(action.kind, action.target, detail="unresolved-path", unparsed=True)]
            return [
                Probe(
                    action.kind,
                    resolved,
                    detail="file",
                    resolved=resolved,
                )
            ]
        if action.kind is ToolKind.NET:
            host = str(action.args.get("host") or "")
            return [Probe(ToolKind.NET, host, detail="request", resolved=action.target)]
        if action.kind is ToolKind.MCP:
            return [Probe(ToolKind.MCP, action.target, detail="tool-call", resolved=action.target)]
        return [Probe(action.kind, action.target)]

    def _shell_probes(self, action: Action) -> list[Probe]:
        result = parse(action.target)
        probes: list[Probe] = []

        if not result.confident:
            target = "<unparsed>"
            for command in flatten(result.root):
                name, _ = effective_command(command)
                if name:
                    target = name
                    break
            probes.append(Probe(ToolKind.SHELL, target, detail="unparsed", unparsed=True))

        for producer, shell in pipes_into_shell(result.root):
            probes.append(
                Probe(
                    ToolKind.SHELL,
                    shell,
                    argv=(shell,),
                    detail="pipe-to-shell",
                )
            )

        for url in action.args.get("urls") or []:
            host = urlsplit(str(url)).hostname or ""
            probes.append(Probe(ToolKind.NET, host, detail="url", resolved=str(url)))

        commands = flatten(result.root)
        downloads = self._download_paths(commands)

        for command in commands:
            probes.extend(self._probes_for_command(command, downloads))

        return probes

    def _download_paths(self, commands: list[Command]) -> set[str]:
        """Files this command line downloads, resolved.

        Collected before evaluation so ``curl -o x && ./x`` is recognised as
        downloading and then running the same file, even though the download
        has not happened yet when the exec probe is built.
        """
        paths: set[str] = set()
        for command in commands:
            name, argv = effective_command(command)
            target = download_target(name, argv)
            if not target:
                continue
            resolved, _ = resolve_path(target, self.ctx)
            if resolved:
                paths.add(resolved)
        return paths

    def _probes_for_command(self, command: Command, downloads: set[str] | None = None) -> list[Probe]:
        downloads = downloads or set()
        name, argv = effective_command(command)
        if not name:
            return []

        probes = [Probe(ToolKind.SHELL, name, argv=argv, detail="command")]

        if name in INTERPRETERS and _has_inline_flag(name, argv):
            probes.append(
                Probe(
                    ToolKind.SHELL,
                    name,
                    argv=argv,
                    detail="inline-code",
                    inline_code=True,
                )
            )

        # A downloader writing a named file is a write, even without '>'.
        target = download_target(name, argv)
        if target:
            probes.extend(self._path_probes(target, "download-output"))

        # rsync/scp move data to another host: that is egress.
        if name in REMOTE_COPY_COMMANDS:
            host = remote_host_from_argv(argv)
            if host:
                probes.append(Probe(ToolKind.NET, host, detail="remote-copy", resolved=""))

        for redirect in command.redirects:
            if _is_write_redirect(redirect.op):
                probes.extend(self._path_probes(redirect.target, "redirect"))

        if name == "tee":
            for target in _non_flags(argv[1:]):
                probes.extend(self._path_probes(target, "tee"))

        if name == "dd":
            for token in argv[1:]:
                if token.startswith("of="):
                    probes.extend(self._path_probes(token[3:], "dd"))

        if name in COPY_COMMANDS:
            destination = _last_non_flag(argv[1:])
            if destination:
                probes.extend(self._path_probes(destination, f"{name}-target"))
            if name == "mv":
                source = _first_non_flag(argv[1:])
                if source:
                    probes.extend(self._path_probes(source, "mv-source"))

        if name == "find" and "-delete" in argv:
            root = _first_non_flag(argv[1:]) or "."
            probes.extend(self._path_probes(root, "find-delete"))

        probes.extend(self._agent_created_probes(name, argv, command, downloads))

        return probes

    def _agent_created_probes(
        self,
        name: str,
        argv: tuple[str, ...],
        command: Command,
        downloads: set[str] | None = None,
    ) -> list[Probe]:
        """Flag execution of a file this session wrote or downloaded.

        A script the agent just created is exactly the shape of a
        download-and-run chain, so running one is a question even when the path
        is ordinary.
        """
        available = set(self.ctx.created_files) | (downloads or set())
        candidates: list[str] = []
        if argv and ("/" in argv[0] or argv[0].startswith(".")):
            candidates.append(argv[0])
        if name in {"bash", "sh", "zsh", "dash"} and "-c" not in argv and len(argv) > 1:
            candidates.append(argv[1])

        probes: list[Probe] = []
        for candidate in candidates:
            resolved, _ = resolve_path(candidate, self.ctx)
            if resolved and resolved in available:
                probes.append(
                    Probe(
                        ToolKind.SHELL,
                        candidate,
                        argv=argv,
                        detail="agent-created",
                        agent_created=True,
                    )
                )
        return probes

    def _path_probes(self, raw: str, detail: str) -> list[Probe]:
        resolved, note = resolve_path(raw, self.ctx)
        if resolved is None:
            return [
                Probe(
                    ToolKind.FILE_WRITE,
                    raw,
                    detail="unresolved-path",
                    unparsed=True,
                )
            ]
        return [Probe(ToolKind.FILE_WRITE, resolved, detail=detail, resolved=resolved)]

    # -- merging ---------------------------------------------------------- #

    def _merge(self, probes: list[Probe]) -> Evaluation:
        if not probes:
            return Evaluation(
                Verdict(Decision.ASK, "policy.default", "nothing to evaluate"), ()
            )

        evaluated: list[tuple[Probe, Verdict]] = []
        for probe in probes:
            verdict = self.policy.evaluate(probe, self.ctx)
            evaluated.append((probe, verdict))
            if probe.kind is ToolKind.FILE_WRITE and verdict.decision is Decision.ALLOW:
                if probe.resolved:
                    self.ctx.created_files.add(probe.resolved)

        # Highest severity wins. On a tie, a specific rule explains the outcome
        # better than the policy default or a catch-all fallback, so it wins;
        # otherwise the earlier probe wins.
        def rank(verdict: Verdict) -> tuple[int, bool, bool]:
            return (
                verdict.decision.severity,
                verdict.rule_id != "policy.default",
                not self.policy.is_fallback(verdict.rule_id),
            )

        best_index = 0
        best_key = rank(evaluated[0][1])
        for index, (_, verdict) in enumerate(evaluated[1:], start=1):
            key = rank(verdict)
            if key > best_key:
                best_index = index
                best_key = key
        return Evaluation(evaluated[best_index][1], tuple(evaluated))