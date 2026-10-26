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

import json
import os
from dataclasses import dataclass, replace
from typing import Iterable
from urllib.parse import urlsplit

from .action import Action, ToolKind
from .policy import Decision, EvalContext, Policy, Probe, Verdict
from .shellparse import (
    SHELLS,
    Command,
    ParseResult,
    flatten,
    parse,
    pipes_into_shell,
)

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

#: Patterns that make a script more than inert when it is run.
#:
#: This is a screen, not a sandbox. It exists so a session that has read nothing
#: hostile can edit-and-run its own small scripts without a human in the loop,
#: while anything that reaches for the network or for credentials still asks.
EGRESS_INDICATORS = (
    "http://",
    "https://",
    "urllib",
    "requests",
    "httpx",
    "socket",
    "http.client",
    "subprocess",
    "os.system",
    "popen",
    "curl",
    "wget",
    "b64decode",
    "base64",
    ".env",
    "id_rsa",
    ".ssh",
    "os.environ",
    "getenv",
    "open(",
)


def looks_inert(contents: str) -> bool:
    """True when a script contains nothing that could move data out.

    Conservative on purpose: no captured contents means "not inert", so a file
    created by a shell redirect is still a question.
    """
    if not contents.strip():
        return False
    lowered = contents.lower()
    return not any(indicator in lowered for indicator in EGRESS_INDICATORS)


#: What a pre-existing script must not contain before it may run.
#:
#: Narrower than ``EGRESS_INDICATORS`` on purpose: a pre-existing script that
#: opens a workspace file is ordinary code, while one that reaches for ``~/.ssh``,
#: posts over the network, reads the environment wholesale or evaluates a dynamic
#: string is not. The point of the screen is to answer "could this script move a
#: credential off the machine", not "does it touch the filesystem".
SCRIPT_SCREEN_INDICATORS = (
    # Credential locations, including the ways a script builds them at runtime.
    ".ssh",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    ".aws",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials",
    ".env",
    "expanduser",
    "path.home",
    "os.getenv",
    "os.environ",
    # Network primitives.
    "urllib",
    "requests",
    "httpx",
    "http.client",
    "urlopen",
    "socket",
    "curl",
    "wget",
    "subprocess",
    "check_output",
    "check_call",
    "popen",
    "os.system",
    # Encoding a payload is the first step of getting it out.
    "base64",
    "b64encode",
    "b64decode",
    "hexlify",
    # Dynamic execution, i.e. a payload we cannot read.
    "eval(",
    "exec(",
)

#: Files larger than this are asked about rather than parsed.
MAX_SCREEN_BYTES = 256 * 1024

#: Interpreter flags that consume the following argument, so the flag's value is
#: not mistaken for the script path.
INTERPRETER_VALUE_FLAGS = {"-W", "-X", "-Q", "--require"}

#: Interpreter flags that mean "run this string or module, not a file".
INTERPRETER_NO_SCRIPT_FLAGS = frozenset(
    {"-c", "-m", "-e", "-E", "--eval", "-p", "--print", "-r"}
)

#: Directories whose contents are system commands, not project scripts.
SYSTEM_BIN_PREFIXES = (
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/local/bin/",
)


def screen_script(path: str) -> tuple[str, str]:
    """Read a pre-existing script and decide whether it may run.

    Returns ``(status, reason)`` with status ``ok``, ``unsafe`` or ``unreadable``.
    Every failure mode is ``unreadable`` and therefore a question: a script we
    cannot read is a script we cannot vouch for.
    """
    if not os.path.isfile(path):
        return "unreadable", "not a regular file"
    try:
        size = os.path.getsize(path)
        if size > MAX_SCREEN_BYTES:
            return "unreadable", f"larger than {MAX_SCREEN_BYTES} bytes"
        with open(path, "rb") as handle:
            raw = handle.read(MAX_SCREEN_BYTES + 1)
    except OSError as exc:
        return "unreadable", f"cannot read: {exc.strerror or exc}"

    if b"\x00" in raw:
        return "unreadable", "binary content"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return "unreadable", "not UTF-8 text"

    lowered = text.lower()
    hits = sorted({indicator for indicator in SCRIPT_SCREEN_INDICATORS if indicator in lowered})
    if hits:
        return "unsafe", "references " + ", ".join(hits[:4])

    if path.endswith(".py"):
        try:
            compile(text, path, "exec")
        except SyntaxError as exc:
            return "unreadable", f"not valid Python: {exc.msg}"

    return "ok", ""


#: Commands that put data on the wire. Used only to decide whether a shell
#: command is an egress candidate worth scanning for secrets and taint.
EGRESS_COMMANDS = frozenset(
    {
        "curl",
        "wget",
        "nc",
        "ncat",
        "netcat",
        "ssh",
        "scp",
        "rsync",
        "sftp",
        "telnet",
        "socat",
        "ftp",
        "http",
        "https",
    }
)


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


def _within(path: str, root: str) -> bool:
    """True when ``path`` is ``root`` or underneath it."""
    if not path or not root:
        return False
    try:
        root_path = os.path.realpath(root)
        return os.path.commonpath([os.path.realpath(path), root_path]) == root_path
    except ValueError:
        return False


#: Modes that only add execute permission, and only inside the workspace.
SAFE_CHMOD_MODES = frozenset({"+x", "u+x", "a+x", "755", "0755", "700", "0700"})

#: Permission letters a symbolic chmod mode can contain.
PERM_LETTERS = frozenset("rwxXst")


def _chmod_mode_and_targets(args: list[str]) -> tuple[str | None, list[str], bool]:
    """Split ``chmod`` arguments into a mode string and target paths.

    ``shlex`` in POSIX mode splits ``+x`` into ``+`` and ``x``, so the symbolic
    mode has to be reassembled here. Only the fragments that ``shlex`` actually
    produced are joined: an operator, plus a single permission letter, plus an
    optional leading ``u``/``g``/``o``/``a``. A leftover permission fragment
    after the mode means the mode was multi-letter (``+rwx``) and we did not read
    it correctly, so the call is reported as unparsed rather than guessed at.
    """
    tokens = [arg for arg in args if not arg.startswith("-") or arg.startswith("-R")]
    # Drop the mode's own -R flag; it is checked separately.
    tokens = [arg for arg in tokens if arg not in ("-R", "--recursive")]
    if len(tokens) < 2:
        return None, tokens, False

    assembled: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        next_token = tokens[index + 1] if index + 1 < len(tokens) else ""

        if token in {"+", "-", "="} and len(next_token) == 1 and next_token in PERM_LETTERS:
            assembled.append(token + next_token)
            index += 2
            continue
        if (
            len(token) == 1
            and token in "ugoa"
            and next_token in {"+", "-", "="}
            and index + 2 < len(tokens)
            and len(tokens[index + 2]) == 1
            and tokens[index + 2] in PERM_LETTERS
        ):
            assembled.append(token + next_token + tokens[index + 2])
            index += 3
            continue
        break

    if not assembled:
        # A numeric mode, or something we do not model.
        return tokens[0], tokens[1:], False

    mode = "".join(assembled)
    rest = tokens[index:]

    if rest and len(rest[0]) == 1 and rest[0] in PERM_LETTERS:
        # `chmod +rwx f` tokenises as + r w x f: we read "+r" and the remaining
        # letters look like paths. Refuse rather than chmod the wrong files.
        return mode, rest, True

    return mode, rest, False


def _is_setuid_mode(mode: str) -> bool:
    """True for setuid, setgid and sticky modes, in symbolic or numeric form."""
    text = mode.strip()
    if not text:
        return False
    if text[0] in "+-" or any(prefix in text for prefix in ("u+", "g+", "o+", "a+")):
        return any(letter in text for letter in "st")
    if text.isdigit():
        digits = text.lstrip("0") or "0"
        return digits[0] in {"1", "2", "4"}
    return False


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


def _first_positional(args: Iterable[str], value_flags: Iterable[str] = ()) -> str | None:
    """First argument that is not a flag, skipping values of value-taking flags."""
    tokens = list(args)
    with_value = set(value_flags)
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            index += 1
            continue
        if token.startswith("-") and token != "-":
            if "=" not in token and token in with_value:
                index += 2
                continue
            index += 1
            continue
        return token
    return None


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
    injection: Any = None

    @property
    def decision(self) -> Decision:
        return self.verdict.decision

    def to_dict(self) -> dict[str, object]:
        return {
            "decision": self.verdict.decision.value,
            "rule_id": self.verdict.rule_id,
            "reason": self.verdict.reason,
            "matched_rules": list(self.verdict.matches),
            "injection": self.injection.to_dict() if self.injection is not None else None,
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
        probes.extend(self._egress_probes(action))
        evaluation = self._merge(probes)

        # The detector may only move an allow to an ask. A deny stays a deny, and
        # an ask never becomes an allow because a model thought the text was fine.
        signal = self.ctx.injection
        if (
            evaluation.decision is Decision.ALLOW
            and signal is not None
            and getattr(signal, "fired", False)
            and self._is_egress(action)
        ):
            verdict = Verdict(
                Decision.ASK,
                "injection.escalation",
                f"injection signal {signal.score:.2f} in text from this session "
                f"({signal.span[:80]!r}); egress needs a human",
            )
            return Evaluation(verdict, evaluation.probes, injection=signal)
        return Evaluation(evaluation.verdict, evaluation.probes, injection=signal)

    # -- taint and secrets ------------------------------------------------ #

    def observe_output(self, action: Action, text: str) -> None:
        """Record what a read returned, so later egress can be judged.

        The engine only sees calls *before* they run, so taint has to be fed
        from the outside: a frontend calls this with the fetched page, the file
        contents, or the command's stdout.
        """
        if not text:
            return

        if self.ctx.taint is not None:
            if action.kind is ToolKind.NET:
                self.ctx.taint.add(action.target or "network", text)
                self.ctx.strict = True
            elif action.kind is ToolKind.FILE_READ:
                if not _within(action.target, self.ctx.workspace):
                    self.ctx.taint.add(action.target, text)
                    self.ctx.strict = True

        if self.ctx.secrets is not None and action.kind is ToolKind.FILE_READ:
            name = os.path.basename(action.target)
            if name == ".env" or name.startswith(".env."):
                self.ctx.secrets.discover_dotenv(action.target)
            if self._is_secret_path(action.target):
                # The agent has now seen a credential. Everything it writes
                # afterwards is suspect, and its own scripts stop being trusted.
                self.ctx.secret_read = True

        if self.ctx.detector is not None:
            self._run_detector(action, text)

    def _run_detector(self, action: Action, text: str) -> None:
        """Scan what the agent just read. A firing signal taints the session."""
        try:
            signal = self.ctx.detector.scan(text)
        except Exception as exc:  # noqa: BLE001 - a detector must never break a run
            self.ctx.injection = None
            self.ctx.injection_error = f"{type(exc).__name__}: {exc}"[:200]
            return
        self.ctx.last_signal = signal
        if getattr(signal, "fired", False):
            self.ctx.injection = signal
            self.ctx.strict = True
            if self.ctx.taint is not None:
                self.ctx.taint.add(action.target or "untrusted", text)

    def _is_secret_path(self, path: str) -> bool:
        name = os.path.basename(path)
        if name == ".env" or name.startswith(".env."):
            return True
        if self.ctx.secrets is None:
            return False
        resolved = os.path.realpath(path)
        return any(
            resolved == protected for _, protected in self.ctx.secrets.protected_paths
        )

    def _egress_probes(self, action: Action) -> list[Probe]:
        """Look for secrets and tainted text in what is about to leave."""
        if not self._is_egress(action):
            return []
        text = self._payload_text(action)
        if not text:
            return []

        probes: list[Probe] = []
        if self.ctx.secrets is not None:
            label = self.ctx.secrets.contains(text)
            if label:
                probes.append(
                    Probe(action.kind, f"secret:{label}", detail="secret-egress")
                )
            path_label = self.ctx.secrets.referenced_path(text)
            if path_label:
                probes.append(
                    Probe(action.kind, f"secret-file:{path_label}", detail="secret-egress")
                )
        if self.ctx.taint is not None:
            source = self.ctx.taint.match(text)
            if source:
                probes.append(
                    Probe(action.kind, f"tainted:{source}", detail="tainted-egress")
                )
        return probes

    def _is_egress(self, action: Action) -> bool:
        if action.kind in (ToolKind.NET, ToolKind.MCP):
            return True
        if action.kind is ToolKind.FILE_WRITE:
            resolved, _ = resolve_path(action.target, self.ctx)
            return bool(resolved and not _within(resolved, self.ctx.workspace))
        if action.kind is ToolKind.SHELL:
            if action.args.get("urls"):
                return True
            for command in flatten(parse(action.target).root):
                name, _ = effective_command(command)
                if name in EGRESS_COMMANDS:
                    return True
        return False

    def _payload_text(self, action: Action) -> str:
        if action.kind is ToolKind.NET:
            return " ".join(
                str(part)
                for part in (
                    action.target,
                    action.args.get("body") or "",
                    action.args.get("query") or "",
                )
                if part
            )
        if action.kind is ToolKind.SHELL:
            return action.target
        if action.kind is ToolKind.FILE_WRITE:
            contents = action.args.get("contents")
            parts = [action.target]
            if isinstance(contents, str):
                parts.append(contents)
            return " ".join(parts)
        if action.kind is ToolKind.MCP:
            return action.target + " " + json.dumps(
                action.args.get("arguments") or {}, sort_keys=True, default=str
            )
        return ""

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
                    contents=str(action.args.get("contents") or ""),
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

        probes: list[Probe] = []
        # Placed first so that when a verdict is a tie, "this is a script we
        # screened" explains the outcome rather than the generic command rule.
        script_probes = self._script_probes(name, argv, downloads)
        probes.extend(script_probes)
        clean_script = any(p.detail == "agent-created-clean" for p in script_probes)

        chmod_probes = self._chmod_probes(name, argv)
        probes.extend(chmod_probes)

        if not clean_script and not chmod_probes and not script_probes:
            probes.append(Probe(ToolKind.SHELL, name, argv=argv, detail="command"))

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

        return probes

    def _chmod_probes(self, name: str, argv: tuple[str, ...]) -> list[Probe]:
        """Path-aware probes for ``chmod``.

        ``chmod`` is the only common command whose safety depends on both the
        mode and the path, so it gets its own probe rather than a name match.
        The path goes through the same resolution as everything else, which is
        what keeps ``chmod +x ~/.bashrc`` and a symlink out of the workspace
        from being treated as ordinary file operations.
        """
        if name != "chmod":
            return []

        mode, targets, unparsed = _chmod_mode_and_targets(argv[1:])
        recursive = any(arg in ("-R", "--recursive") for arg in argv[1:])
        if unparsed or mode is None:
            if not targets:
                return []
            return [
                Probe(ToolKind.FILE_WRITE, target, detail="unresolved-path", unparsed=True)
                for target in targets
            ]

        if _is_setuid_mode(mode):
            detail = "chmod-setuid"
        elif recursive:
            detail = "chmod-recursive"
        elif mode in SAFE_CHMOD_MODES:
            detail = "chmod-safe"
        else:
            # 644, 777 and friends keep the generic command rules, which already
            # deny world-writable modes and ask about the rest.
            return []

        probes: list[Probe] = []
        for target in targets:
            resolved, _ = resolve_path(target, self.ctx)
            if resolved is None:
                probes.append(
                    Probe(ToolKind.FILE_WRITE, target, detail="unresolved-path", unparsed=True)
                )
                continue
            probes.append(Probe(ToolKind.FILE_WRITE, resolved, detail=detail, resolved=resolved))
        return probes

    def _script_probes(
        self,
        name: str,
        argv: tuple[str, ...],
        downloads: set[str] | None = None,
    ) -> list[Probe]:
        """Decide a script run on provenance plus contents.

        Two ways a script may run:

        1. **The session created it.** Its contents were captured at write time,
           so the screen runs on exactly what was written. A clean session and
           inert contents allow it; taint, a credential read, or anything that
           could move data asks.
        2. **It already existed.** Its *current* contents are read and screened
           now. This is the case that regressed: `python3 tools/bootstrap.py` is
           not the agent's file, and nothing had looked inside it.

        Anything else — unreadable, oversized, binary, unparseable — asks.
        """
        candidate = self._script_path(name, argv)
        if candidate is None:
            return []

        resolved, _ = resolve_path(candidate, self.ctx)
        if resolved is None:
            return [
                Probe(
                    ToolKind.SHELL,
                    candidate,
                    argv=argv,
                    detail="script-unreadable",
                    unparsed=True,
                )
            ]

        produced = set(self.ctx.created_files) | (downloads or set())
        if resolved in produced or resolved in (downloads or set()):
            contents = self.ctx.created_contents.get(resolved, "")
            detail = (
                "agent-created-clean"
                if self.ctx.clean_session and looks_inert(contents)
                else "agent-created"
            )
            return [
                Probe(
                    ToolKind.SHELL,
                    candidate,
                    argv=argv,
                    detail=detail,
                    agent_created=True,
                )
            ]

        status, reason = screen_script(resolved)
        detail = {
            "ok": "script-screened",
            "unsafe": "script-unsafe",
        }.get(status, "script-unreadable")
        return [
            Probe(
                ToolKind.SHELL,
                candidate,
                argv=argv,
                detail=detail,
                note=f"{candidate}: {reason}" if reason else "",
            )
        ]

    def _script_path(self, name: str, argv: tuple[str, ...]) -> str | None:
        """The file a command will execute as a script, if it executes one."""
        if name in SHELLS and "-c" not in argv and len(argv) > 1:
            return argv[1]
        if name in INTERPRETERS:
            if any(token in INTERPRETER_NO_SCRIPT_FLAGS for token in argv[1:]):
                # -c/-e run a string, -m runs a module: not a file to screen.
                return None
            return _first_positional(argv[1:], INTERPRETER_VALUE_FLAGS)
        if argv and ("/" in argv[0] or argv[0].startswith(".")):
            resolved, _ = resolve_path(argv[0], self.ctx)
            # `/bin/rm` is a system command with a path, not a project script.
            if resolved and not resolved.startswith(SYSTEM_BIN_PREFIXES):
                return argv[0]
        return None

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
                if probe.resolved and not probe.detail.startswith("chmod"):
                    # chmod does not create a file, so it must not make one look
                    # session-created to the agent-created check.
                    self.ctx.created_files.add(probe.resolved)
                    if probe.contents:
                        # Remembered so that running this file later can be
                        # judged on what it actually contains.
                        self.ctx.created_contents[probe.resolved] = probe.contents

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
        winner_index = best_index
        winner_probe, winner_verdict = evaluated[winner_index]
        # Name the thing that matched. "a secret appears in outbound data" is
        # useless in an audit record; "env:AWS_SECRET_ACCESS_KEY" is not.
        suffix = winner_probe.note
        if not suffix and winner_probe.target.startswith(
            ("secret:", "secret-file:", "tainted:", "agent-created:")
        ):
            suffix = winner_probe.target
        if suffix:
            winner_verdict = replace(
                winner_verdict,
                reason=f"{winner_verdict.reason} [{suffix}]",
            )
        return Evaluation(winner_verdict, tuple(evaluated))