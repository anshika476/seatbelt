"""A small, deliberately incomplete bash parser.

Policy cannot be written against strings. ``rm -rf`` is trivial to match and
trivial to evade: ``rm -r -f``, ``r""m -rf``, ``bash -c "rm -rf ~"``,
``$(echo rm) -rf``, ``VAR=rm; $VAR -rf``. Decisions are therefore made on the
tree this module produces.

The parser is intentionally **not** a complete bash implementation. It
understands the shapes that matter for adjudication — lists, pipelines,
redirects, command substitution, backticks, leading assignments, and the
wrappers that hide a command (``bash -c``, ``sudo``, ``env``, ``xargs``,
``timeout``, ``eval``) — and it reports *confidence* for everything else.

The contract that matters: when the parser is not confident, the engine must
resolve the call to ``ask``, never ``allow``. Losing confidence is a supported
outcome, not a bug; silently guessing would be the bug.

Known limitations are listed in ``docs/BUILD_LOG.md`` and are visible here as
the places this module sets ``confident = False``.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, field
from typing import Iterator, Sequence

#: Beyond this depth of substitution we stop trusting our own reading.
MAX_NESTING = 3

#: Upper bound on wrapper expansions, so a crafted command cannot loop.
MAX_EXPANSIONS = 64

PUNCTUATION = "();<>|&"

LIST_OPS = frozenset({";", "&&", "||", "&", "\n"})
PIPE_OPS = frozenset({"|", "|&"})
REDIRECT_OPS = frozenset({">", ">>", "<", ">|", "&>", "&>>", "<&", ">&", "<>", "<<<"})

#: ``<<`` is a heredoc: the body is a separate language we do not read.
HEREDOC_OP = "<<"

#: Shells that execute a string handed to them.
SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "ash", "fish"})

#: Commands that run another command given as their arguments.
WRAPPERS = frozenset(
    {
        "sudo",
        "doas",
        "env",
        "timeout",
        "nice",
        "nohup",
        "command",
        "exec",
        "time",
        "stdbuf",
        "xargs",
        "chroot",
        "setsid",
        "ionice",
        "unbuffer",
    }
)

#: Wrapper options that consume the following argument.
_WRAPPER_OPT_WITH_ARG = {
    "sudo": {"-u", "-g", "-p", "-C", "-h", "-r", "-t", "-U", "-T", "-D"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-C", "-S"},
    "nice": {"-n"},
    "stdbuf": {"-i", "-o", "-e"},
    "xargs": {"-I", "-n", "-P", "-L", "-s", "-d", "-E", "-a", "-e"},
    "ionice": {"-c", "-n", "-p"},
    "timeout": {"-s", "-k"},
}


# --------------------------------------------------------------------------- #
# Tree
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Redirect:
    """A redirection attached to a command."""

    op: str
    target: str

    def to_dict(self) -> dict[str, str]:
        return {"op": self.op, "target": self.target}


@dataclass(frozen=True, slots=True)
class Command:
    """One simple command: argv, redirections and leading assignments.

    ``inline`` holds substitutions that were hiding inside a single quoted word
    (``echo "$(rm -rf /)"``). They are kept separate from ``argv`` because the
    word itself is what would be executed, but policy still needs to see the
    command they would run.
    """

    argv: tuple[str, ...]
    redirects: tuple[Redirect, ...] = ()
    assignments: tuple[tuple[str, str], ...] = ()
    raw: str = ""
    inline: tuple["Node", ...] = ()

    @property
    def name(self) -> str:
        """The command name with any directory component removed."""
        return os.path.basename(self.argv[0]) if self.argv else ""

    def to_dict(self) -> dict[str, object]:
        return {
            "type": "command",
            "name": self.name,
            "argv": list(self.argv),
            "redirects": [r.to_dict() for r in self.redirects],
            "assignments": {k: v for k, v in self.assignments},
            "inline": [node.to_dict() for node in self.inline],
            "raw": self.raw,
        }


@dataclass(frozen=True, slots=True)
class Substitution:
    """``$(...)`` or ``` `...` ``` nested inside a command."""

    style: str
    source: str
    inner: "Node | None" = None

    def to_dict(self) -> dict[str, object]:
        return {
            "type": "substitution",
            "style": self.style,
            "source": self.source,
            "inner": self.inner.to_dict() if self.inner else None,
        }


@dataclass(frozen=True, slots=True)
class Pipeline:
    """Commands joined by ``|`` or ``|&``."""

    parts: tuple["Node", ...]
    ops: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "type": "pipeline",
            "ops": list(self.ops),
            "parts": [p.to_dict() for p in self.parts],
        }


@dataclass(frozen=True, slots=True)
class List:
    """Commands joined by ``;``, ``&&``, ``||`` or ``&``."""

    items: tuple["Node", ...]
    ops: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "type": "list",
            "ops": list(self.ops),
            "items": [i.to_dict() for i in self.items],
        }


Node = Command | Substitution | Pipeline | List


@dataclass(frozen=True, slots=True)
class ParseResult:
    """A parsed command plus how much the parser trusts its own reading."""

    root: Node | None
    confident: bool
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "root": self.root.to_dict() if self.root else None,
            "confident": self.confident,
            "notes": list(self.notes),
            "commands": [list(c.argv) for c in flatten(self.root)],
            "pipes_into_shell": [
                {"producer": a, "shell": b} for a, b in pipes_into_shell(self.root)
            ],
        }


# --------------------------------------------------------------------------- #
# Tokenizing
# --------------------------------------------------------------------------- #


def tokenize(text: str) -> list[str]:
    """Split a command line into words and operators.

    ``shlex`` in POSIX mode already removes quotes, which is what makes
    ``r""m`` collapse to ``rm``. Punctuation mode splits operators from words,
    so ``a&&b`` becomes ``a``, ``&&``, ``b``.

    Raises:
        ValueError: on an unbalanced quote or trailing backslash. The caller
            must treat that as an unparseable command and fail closed.
    """
    lexer = shlex.shlex(text, posix=True, punctuation_chars=PUNCTUATION)
    lexer.commenters = ""
    return list(lexer)


def _merge_url_tokens(tokens: Sequence[str]) -> list[str]:
    """Rejoin ``https`` ``:`` ``//host`` into a single word.

    ``:`` and ``/`` are punctuation, so a URL arrives in pieces. Merging here
    keeps the rest of the parser free of URL special cases.
    """
    merged: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if (
            index + 2 < len(tokens)
            and token.isalpha()
            and tokens[index + 1] == ":"
            and tokens[index + 2].startswith("//")
        ):
            merged.append(token + ":" + tokens[index + 2])
            index += 3
            continue
        merged.append(token)
        index += 1
    return merged


def _split(tokens: Sequence[str], ops: frozenset[str]) -> tuple[list[list[str]], list[str]]:
    """Split a token stream on operator boundaries, keeping the operators."""
    segments: list[list[str]] = [[]]
    found: list[str] = []
    for token in tokens:
        if token in ops:
            found.append(token)
            segments.append([])
        else:
            segments[-1].append(token)
    return segments, found


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


class _Parser:
    """Recursive-descent parser that accumulates confidence notes."""

    def __init__(self) -> None:
        self.confident = True
        self.notes: list[str] = []

    def doubt(self, note: str) -> None:
        """Record a reason the engine must not treat this call as safe."""
        self.confident = False
        self.notes.append(note)

    def observe(self, note: str) -> None:
        """Record an approximation that does not, by itself, lose confidence."""
        self.notes.append(note)

    # -- list ------------------------------------------------------------- #

    def parse_list(self, tokens: Sequence[str], env: dict[str, str], depth: int) -> Node | None:
        if not tokens:
            return None
        segments, ops = _split(tokens, LIST_OPS)
        items: list[Node] = []
        local_env = dict(env)
        for segment in segments:
            if not segment:
                # Trailing or doubled operator: bash would error or repeat.
                continue
            node, assignments = self.parse_pipeline(segment, local_env, depth)
            if assignments:
                # An assignment-only segment still affects later segments.
                local_env.update(assignments)
            if node is None:
                continue
            items.append(node)
        if not items:
            return None
        if len(items) == 1:
            return items[0]
        return List(tuple(items), tuple(ops[: len(items) - 1]))

    # -- pipeline --------------------------------------------------------- #

    def parse_pipeline(
        self, tokens: Sequence[str], env: dict[str, str], depth: int
    ) -> tuple[Node | None, dict[str, str]]:
        segments, ops = _split(tokens, PIPE_OPS)
        parts: list[Node] = []
        assignments: dict[str, str] = {}
        for index, segment in enumerate(segments):
            if not segment:
                continue
            node, segment_assignments = self.parse_command(segment, env, depth)
            if index == 0:
                # Assignments are recorded even when the segment is only an
                # assignment (``VAR=rm; $VAR -rf /``), which yields no command.
                assignments = segment_assignments
            if node is None:
                continue
            parts.append(node)
        if not parts:
            return None, assignments
        if len(parts) == 1:
            return parts[0], assignments
        return Pipeline(tuple(parts), tuple(ops[: len(parts) - 1])), assignments

    # -- command ---------------------------------------------------------- #

    def parse_command(
        self, tokens: Sequence[str], env: dict[str, str], depth: int
    ) -> tuple[Node | None, dict[str, str]]:
        argv: list[str] = []
        redirects: list[Redirect] = []
        assignments: dict[str, str] = {}
        inline: list[Node] = []

        index = 0
        while index < len(tokens):
            token = tokens[index]

            # Subshell grouping: the tokenizer emits the parens as words, and
            # treating "(" as a command name would be a lie about what runs.
            if token in {"(", ")"}:
                self.doubt("subshell grouping is not parsed")
                index += 1
                continue

            # Heredoc: the body is a separate document we never read.
            if token == HEREDOC_OP:
                self.doubt("heredoc body is not parsed")
                index += 2 if index + 1 < len(tokens) else 1
                continue

            # Process substitution: <(...) or >(...). The tokenizer groups the
            # opening pair into one token, so match on the prefix.
            if token.startswith("<(") or token.startswith(">("):
                self.doubt("process substitution is not parsed")
                index += 1
                continue

            # Process substitution split across tokens: < ( ... )
            if token in {"<", ">"} and index + 1 < len(tokens) and tokens[index + 1] == "(":
                self.doubt("process substitution is not parsed")
                index += 2
                continue

            # Command substitution: $ ( ... )
            if token == "$" and index + 1 < len(tokens) and tokens[index + 1] == "(":
                node, consumed = self._read_dollar_paren(tokens, index, env, depth)
                if not argv:
                    # The command name itself is computed at runtime, so we
                    # cannot know what will run. Ask.
                    self.doubt(f"command substitution in command position: {node.source}")
                argv.append(node.source)
                inline.append(node)
                index = consumed
                self.observe(f"command substitution: {node.source}")
                continue

            # Backticks: ` ... `
            if token == "`":
                node, consumed = self._read_backticks(tokens, index, env, depth)
                if not argv:
                    self.doubt(f"backtick substitution in command position: {node.source}")
                argv.append(node.source)
                inline.append(node)
                index = consumed
                self.observe(f"backtick substitution: {node.source}")
                continue

            # Variable reference split by the tokenizer: $ NAME or $ { NAME }
            if token == "$":
                value, consumed, resolved = self._read_variable(tokens, index, env)
                if not resolved and not argv and not assignments:
                    self.doubt(f"unresolved variable in command position: {value}")
                argv.append(value)
                index = consumed
                continue

            # Redirections, including the "2" ">&" "1" shape.
            if token in REDIRECT_OPS:
                target = tokens[index + 1] if index + 1 < len(tokens) else ""
                if target == "(":
                    self.doubt("process substitution is not parsed")
                    index += 2
                    continue
                redirects.append(Redirect(token, target))
                index += 2
                continue

            if token.isdigit() and index + 1 < len(tokens) and tokens[index + 1] in REDIRECT_OPS:
                target = tokens[index + 2] if index + 2 < len(tokens) else ""
                redirects.append(Redirect(token + tokens[index + 1], target))
                index += 3
                continue

            # Leading NAME=value assignment.
            if not argv and _is_assignment(token):
                name, _, value = token.partition("=")
                assignments[name] = value
                index += 1
                continue

            # A quoted word can still hide a substitution.
            if "$(" in token or "`" in token:
                inline.extend(self._observe_inline_substitutions(token, env, depth))
                argv.append(token)
                index += 1
                continue

            argv.append(token)
            index += 1

        if not argv:
            if redirects:
                self.doubt("redirection with no command")
            return None, assignments

        name = os.path.basename(argv[0])
        if name == "find" and "-exec" in argv:
            # ``find . -exec rm {} \;`` looks exactly like a list separator, so
            # the terminator is already gone by the time we see the tokens.
            self.doubt("find -exec terminator is not distinguishable from a list operator")
        if name in SHELLS and "-c" in argv and argv.index("-c") + 1 >= len(argv):
            self.doubt("shell invoked with -c but no script argument")
        if name in {"source", "."}:
            self.doubt("sourced script contents are not inspected")

        return (
            Command(
                tuple(argv),
                tuple(redirects),
                tuple(assignments.items()),
                " ".join(tokens),
                tuple(inline),
            ),
            assignments,
        )

    # -- helpers ---------------------------------------------------------- #

    def _read_dollar_paren(
        self, tokens: Sequence[str], start: int, env: dict[str, str], depth: int
    ) -> tuple[Substitution, int]:
        body: list[str] = []
        nesting = 0
        # Start after the opening parenthesis, which is at ``start + 1``.
        index = start + 2
        while index < len(tokens):
            token = tokens[index]
            if token == "(":
                nesting += 1
            elif token == ")":
                if nesting == 0:
                    break
                nesting -= 1
            body.append(token)
            index += 1
        consumed = index + 1
        source = " ".join(body)
        inner = self._parse_nested(source, env, depth, "$()")
        return Substitution("$()", source, inner), consumed

    def _read_backticks(
        self, tokens: Sequence[str], start: int, env: dict[str, str], depth: int
    ) -> tuple[Substitution, int]:
        body: list[str] = []
        index = start + 1
        while index < len(tokens) and tokens[index] != "`":
            body.append(tokens[index])
            index += 1
        consumed = index + 1 if index < len(tokens) else index
        source = " ".join(body)
        inner = self._parse_nested(source, env, depth, "backtick")
        return Substitution("backtick", source, inner), consumed

    def _parse_nested(
        self, source: str, env: dict[str, str], depth: int, style: str
    ) -> Node | None:
        if depth + 1 > MAX_NESTING:
            self.doubt(f"substitution nested deeper than {MAX_NESTING} levels ({style})")
            return None
        try:
            tokens = _merge_url_tokens(tokenize(source))
        except ValueError as exc:
            self.doubt(f"substitution could not be tokenized: {exc}")
            return None
        if not tokens:
            return None
        return self.parse_list(tokens, env, depth + 1)

    def _read_variable(
        self, tokens: Sequence[str], start: int, env: dict[str, str]
    ) -> tuple[str, int, bool]:
        """Read ``$ NAME`` or ``$ { NAME }`` and expand it when known."""
        index = start + 1
        braced = index < len(tokens) and tokens[index] == "{"
        if braced:
            index += 1
            name_parts: list[str] = []
            while index < len(tokens) and tokens[index] != "}":
                name_parts.append(tokens[index])
                index += 1
            index += 1
            name = "".join(name_parts)
        else:
            if index >= len(tokens):
                return "$", index, False
            name = tokens[index]
            index += 1
        if name in env:
            return env[name], index, True
        return f"${name}", index, False

    def _observe_inline_substitutions(
        self, word: str, env: dict[str, str], depth: int
    ) -> list[Node]:
        """Find substitutions inside a word the tokenizer treated as one token.

        Quoting hides ``$(...)`` from the token stream, so a quoted payload is
        scanned again here. The inner command is parsed and returned so it can
        be attached to the tree, while the word itself is kept verbatim because
        that is what would be executed.
        """
        nodes: list[Node] = []
        for script in _extract_inline_scripts(word):
            self.observe(f"quoted substitution: {script}")
            inner = self._parse_nested(script, env, depth, "$()")
            if inner is not None:
                nodes.append(Substitution("$()", script, inner))
        return nodes


def _extract_inline_scripts(word: str) -> list[str]:
    """Pull ``$(...)`` and backtick bodies out of a single word."""
    scripts: list[str] = []
    index = 0
    while index < len(word):
        if word.startswith("$(", index):
            depth = 0
            cursor = index + 1
            while cursor < len(word):
                if word[cursor] == "(":
                    depth += 1
                elif word[cursor] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                cursor += 1
            scripts.append(word[index + 2 : cursor])
            index = cursor + 1
            continue
        if word[index] == "`":
            cursor = word.find("`", index + 1)
            if cursor == -1:
                break
            scripts.append(word[index + 1 : cursor])
            index = cursor + 1
            continue
        index += 1
    return scripts


def _is_assignment(token: str) -> bool:
    name, sep, _ = token.partition("=")
    if not sep or not name:
        return False
    return name.replace("_", "").isalnum() and not name[0].isdigit()


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def parse(command: str) -> ParseResult:
    """Parse a shell command into a tree plus a confidence verdict."""
    if not command or not command.strip():
        return ParseResult(None, False, ("empty command",))
    parser = _Parser()
    try:
        tokens = _merge_url_tokens(tokenize(command))
    except ValueError as exc:
        return ParseResult(None, False, (f"tokenizer: {exc}",))
    root = parser.parse_list(tokens, {}, 0)
    if root is None:
        parser.doubt("no command found")
    return ParseResult(root, parser.confident, tuple(parser.notes))


# --------------------------------------------------------------------------- #
# Traversal helpers
# --------------------------------------------------------------------------- #


def iter_nodes(root: Node | None) -> Iterator[Node]:
    """Yield every node in the tree, depth first."""
    if root is None:
        return
    yield root
    if isinstance(root, List):
        for item in root.items:
            yield from iter_nodes(item)
    elif isinstance(root, Pipeline):
        for part in root.parts:
            yield from iter_nodes(part)
    elif isinstance(root, Substitution):
        yield from iter_nodes(root.inner)
    elif isinstance(root, Command):
        for node in root.inline:
            yield from iter_nodes(node)


def flatten(root: Node | None) -> list[Command]:
    """Return every command the tree implies, wrappers expanded.

    This is the list policy rules run against. A command hidden behind
    ``bash -c``, ``sudo``, ``env``, ``xargs``, ``timeout`` or ``eval`` appears
    as its own entry, so a rule matching ``rm`` sees it wherever it was nested.
    """
    commands: list[Command] = []
    queue: list[Node] = [node for node in iter_nodes(root)]
    seen: set[str] = set()
    expansions = 0
    # Wrapper expansion parses strings that came from the command itself, so a
    # pathological input could ask us to expand forever. Bound it, and stop
    # trusting the result if the bound is hit.
    while queue:
        if expansions > MAX_EXPANSIONS:
            break
        expansions += 1
        node = queue.pop(0)
        if isinstance(node, Command):
            commands.append(node)
            key = "\x00".join(node.argv)
            if key in seen:
                continue
            seen.add(key)
            for derived in _expand_command(node):
                queue.append(derived)
    return commands


def _expand_command(command: Command) -> list[Node]:
    """Commands implied by a wrapper or interpreter invocation."""
    argv = [token for token in command.argv if not _is_assignment(token)]
    if not argv:
        return []
    name = os.path.basename(argv[0])

    if name in SHELLS:
        if "-c" in argv:
            index = argv.index("-c")
            if index + 1 < len(argv):
                return _parse_as_nodes(argv[index + 1])
        return []

    if name == "eval":
        script = " ".join(argv[1:])
        return _parse_as_nodes(script)

    if name in WRAPPERS:
        rest = _strip_wrapper(name, argv[1:])
        if not rest:
            return []
        inner = Command(tuple(rest), (), (), " ".join(rest))
        return [inner, *_expand_command(inner)]

    return []


def _parse_as_nodes(script: str) -> list[Node]:
    """Parse a nested script, returning its nodes (empty when unparseable)."""
    result = parse(script)
    if result.root is None:
        return []
    return [node for node in iter_nodes(result.root)]


def _strip_wrapper(name: str, args: Sequence[str]) -> list[str]:
    """Remove a wrapper's own options, leaving the command it will run."""
    with_arg = _WRAPPER_OPT_WITH_ARG.get(name, set())
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            index += 1
            break
        if token.startswith("-") and token != "-":
            if "=" in token:
                index += 1
            elif token in with_arg:
                index += 2
            else:
                index += 1
            continue
        break
    if name == "timeout":
        index += 1  # the duration is not the command
    if name in {"env", "xargs"}:
        while index < len(args) and _is_assignment(args[index]):
            index += 1
    return list(args[index:])


def pipes_into_shell(root: Node | None) -> list[tuple[str, str]]:
    """Return ``(producer, shell)`` pairs for pipelines ending in a shell.

    ``curl … | sh`` and ``echo … | base64 -d | bash`` both land here. This is a
    structural fact about the parse, so it lives with the parser rather than
    with the policy that acts on it.
    """
    pairs: list[tuple[str, str]] = []
    for node in iter_nodes(root):
        if not isinstance(node, Pipeline):
            continue
        commands = [part for part in node.parts if isinstance(part, Command)]
        if len(commands) < 2:
            continue
        last = commands[-1]
        # A shell with no ``-c`` reads its script from stdin, which is exactly
        # the ``curl … | sh`` shape.
        if last.name in SHELLS and "-c" not in last.argv:
            pairs.append((commands[0].name, last.name))
    return pairs
