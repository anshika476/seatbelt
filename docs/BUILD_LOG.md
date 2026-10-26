# Build log

A running record of decisions, dead ends and the reasoning behind them. Written
as the work happens, not reconstructed afterwards.

## 2026-10-26 — Entry 0: scope, environment, skeleton

### Scope

Building Seatbelt, an action-guardrails layer between an AI agent and its tools.
Deterministic policy engine, taint and secret tracking, an optional open-model
injection signal, human approval, and a tamper-evident audit log. Judged on
build quality, complexity, functionality and process, so the log and the commit
history are deliverables, not overhead.

Deliberately **not** a sandbox. Seatbelt adjudicates tool calls; it does not
contain a process that escapes to the kernel. Saying this up front is cheaper
than being asked about it by a judge.

### Decision: two lanes, model only on the inbound lane

The outbound decision (should this call run?) is deterministic. The inbound
signal (does this output contain instructions aimed at the agent?) is a model
call. Keeping them separate means the security property does not depend on the
model being right, available, or fast.

Consequence: the model may only escalate `allow` to `ask`. It can never produce
a `deny`, and it can never produce an `allow` that overrides a deterministic
one. This is what makes the three-arm benchmark honest — the Seatbelt arm's
result does not improve or degrade when the model has a bad day.

### Decision: parse, don't regex

`rm -rf` is trivial to match as a string and trivial to evade: `rm -r -f`,
`rm --recursive --force`, `bash -c "rm -rf ~"`, `$(printf ...)`, `find -delete`.
Decisions are made on a parsed AST instead, with recursion into wrappers.

Dead end avoided: `bashlex` was the obvious library, but it is unmaintained and
pulls a dependency. Stdlib `shlex` with `punctuation_chars=True` gives tokens
plus operators, which is enough to build `Cmd` / `Pipeline` / `List` nodes.
Wrapper recursion (`bash -c`, `sh -c`, `sudo`, `env`, `xargs`) is then a small
amount of explicit code rather than a parser feature.

### Decision: HMAC chain rather than plain SHA-256

A plain hash chain detects edits by anyone who does not re-seal the chain, and
detects nothing against someone who can. Sealing with an HMAC key held by the
process raises the bar for an agent that can write to its own audit log, which
is exactly the self-tampering case in the threat model. It is not a signature
and the README will not pretend otherwise.

The key is exposed as `AuditLog.key` because verifying a log in a different
process needs it; the contract is that it never lands in the log file.

### Decision: redaction is a backstop, not a control

Secrets are replaced with `[redacted]` before a record is sealed, but the real
control is the egress check that should have denied the call. Writing that down
matters: redaction alone would still let a secret reach the model provider.

### Environment: Linux only

The host is Windows, but bash semantics are the product. `rc=126`, `bash -c`
recursion and `sudo`/`chmod` fixtures are not trustworthy under PowerShell, so
development happens in WSL2 (Ubuntu, Python 3.12, git 2.43) with the repo at
`/mnt/c/Users/Anshi/.alan/workspace/seatbelt`, which both Windows tooling and
WSL can see. Every test and benchmark runs through `wsl -e bash -lc`. CI target
is `ubuntu-latest`.

Cost of that choice: `/mnt/c` is slower than the WSL filesystem for git. For a
project this size it is not measurable, and the alternative — a repo the Windows
side cannot open — would be worse.

### T0 delivered

- `Action` model with `ToolKind` and `Trust`, frozen and comparable. It is not
  hashable while it carries `args`, because a mapping has no stable hash; the
  first attempt at a "hashable action" test caught this. Keys use `to_json()`.
- `AuditLog` with HMAC-sealed records, sequence and link checks, redaction, and
  `from_records` so a loaded or tampered chain can be verified.
- `seatbelt version`, tests, Makefile, MIT license.

Next: shell parsing (T1), then the policy engine (T2) and the first end-to-end
`seatbelt run` (T3).

## 2026-10-26 — Entry 1: moving the repo into WSL

The repo lived at `/mnt/c/Users/Anshi/.alan/workspace/seatbelt`, which meant
every git operation crossed the 9p filesystem. The test suite took **1.77s** on
`/mnt/c` and **0.04s** on the WSL filesystem for the same twelve tests. That is
a 40x difference on a suite that is about to grow by an order of magnitude, so
the repo moved.

How: `git clone /mnt/c/.../seatbelt ~/seatbelt`, which carries the full history
across, then a fresh venv at `~/seatbelt/.venv`, then the old directory deleted
so there is exactly one checkout and no chance of working in the wrong one.

Cost: the Windows side can still reach it through `\\wsl.localhost\Ubuntu\root\seatbelt`,
so editors and file tools keep working. All commands run through
`wsl -e bash -lc`. Note for future sessions: passing shell metacharacters
through PowerShell's quoting layer silently mangles them — verification scripts
are written to a file and executed, not inlined.

Toolchain needed one install: `python3-venv` and `python3-pip` were missing from
the Ubuntu image (`apt-get install -y python3-venv python3-pip`).

## 2026-10-26 — Entry 2: where the audit key actually lives

Question asked, and worth writing down because the first answer was "nothing
much":

> Where does the audit HMAC key live, and what stops the guarded agent from
> reading it?

Before the fix: `AuditLog.__init__` did `key or os.urandom(32)`. The key lived
only in the guardian's memory, which sounds fine until you notice the guardian
is usually a **child of the agent**. The agent could not read the log's key from
the file (it was never written), but it could start its own Seatbelt, and it
shared a user with the process holding the key.

What changed:

1. The key is read from `SEATBELT_AUDIT_KEY` (64 hex chars, base64, or ≥16 raw
   bytes), so a log written by one process can be verified by another. That is
   the whole point of an audit log; a per-process random key makes the chain
   unverifiable the moment the process exits.
2. `child_env()` strips every `SEATBELT_*` variable from the environment of any
   command Seatbelt executes, so `env` and `/proc/self/environ` inside a tool
   call do not show the key.
3. An unusable key **raises** instead of silently falling back to a random one.
   A silent fallback produces a log nobody can verify while looking healthy,
   which is the worst possible failure for this component.

What did not change, and is now written in `docs/THREAT_MODEL.md` under "The
audit key": none of this stops an attacker with same-user process access from
reading `/proc/<pid>/mem`. `ptrace_scope=1` helps only when the guardian is not
the agent's descendant, and it usually is. The documented remedy is a real
boundary — guardian under a different uid, a separate container, or asymmetric
signatures so only a public key is needed to verify.

I chose to document the gap rather than pretend the env-var trick closes it.
A guardrail that oversells itself is worse than one that names its seams.

## 2026-10-26 — Entry 3: T1, the parser

### Decision: confidence is a first-class output

`parse()` returns `ParseResult(root, confident, notes)`. `confident=False` is
not an error — it is the parser saying "I do not know what this does", and the
engine must turn that into `ask`. Every place the parser gives up is an explicit
`self.doubt(...)` call with a note that lands in the audit record, so a denial
can always explain itself.

This is the single most important design choice in the module. A parser that
silently returns something plausible for input it does not understand is a
vulnerability with good test coverage.

### Decision: `shlex`, not `bashlex`

`bashlex` is unmaintained and adds a dependency. Stdlib `shlex` with
`punctuation_chars="();<>|&"` in POSIX mode gives words plus operators, which is
enough for lists, pipelines, redirects and substitution. POSIX mode also removes
quotes for free, which is why `r""m -rf /` arrives as `rm -rf /` — the first
bypass falls out of correct tokenizing rather than a special case.

### Decision: wrapper expansion in `flatten`, not in the tree

`bash -c "rm -rf /"` stays a single `Command` whose argv[2] is the script
string. `flatten()` then re-parses that string and appends the commands it
finds, so `rm -rf /` appears as its own entry and a rule matching `rm` sees it
wherever it was hidden. Keeping the tree faithful to the input and doing
expansion on traversal means the audit record can show both "what was typed"
and "what it resolves to".

Expansion is bounded (`MAX_EXPANSIONS = 64`) so a crafted command cannot make
the flatten loop forever.

### Decision: a substitution in command position loses confidence

`$(echo rm) -rf /` executes `rm -rf /`. We cannot know that without running
`echo`, so the parser does the honest thing: it records the substitution, marks
the parse unconfident, and the engine asks. Same for backticks in command
position and for an unresolved `$CMD`.

In argument position the substitution is expanded into the tree but the word is
kept verbatim, so policy sees `echo "rm -rf /"` *and* the `rm -rf /` inside it.

### Bugs the tests caught (all real, all fixed)

1. `parse_pipeline` dropped assignments from a segment that produced no command,
   so `VAR=rm; $VAR -rf /` failed to resolve. Assignment propagation now happens
   before the `node is None` check.
2. Substitution nodes were built and then thrown away, so `flatten` could not
   see `rm` inside `` echo `rm -rf /` ``. They are now attached to the parent
   `Command.inline`.
3. `_read_dollar_paren` started at the opening paren and appended it to the
   body, producing a nested parse of `( echo rm ) -rf /`. Off-by-one, caught by
   the golden case for command-position substitution.
4. Process substitution arrives as a single `<( ` token because the tokenizer
   groups punctuation, so the `token == "<"` check never fired.
5. `find . -exec rm {} ;` — the terminator is indistinguishable from a list
   separator. Rather than pretend, `find` + `-exec` now loses confidence.

### Known limitations (deliberate, each pinned by a test)

| Input | Behaviour | Why |
| --- | --- | --- |
| `cat <<EOF` | `ask` | heredoc body is a separate document; not read |
| `diff <(a) <(b)` | `ask` | process substitution not read |
| `(cd /tmp && rm -rf x)` | `ask` | subshell grouping not read |
| `find . -exec rm {} ;` | `ask` | terminator collides with `;` |
| `bash -c` with no script | `ask` | nothing to read |
| `source ./setup.sh` | `ask` | sourced file not inspected |
| `$CMD -rf /` | `ask` | command name computed at runtime |
| `$(echo rm) -rf /` | `ask` | command name computed at runtime |
| `rm -rf $TARGET` | parse ok, literal `$TARGET` kept | argument value unknown but the command is known |
| `eval "$DYNAMIC"` | `ask` if unparseable, else parsed | literal eval is read; dynamic eval loses confidence |
| aliases, functions, globs, `$'…'` | not modelled | out of scope for a 45-minute parser |

An unconfident parse is a *downgrade*, not a denial: the call goes to a human.
That keeps the false-positive cost at "one approval" instead of "the agent
cannot work".

### Test corpus

40 golden cases in `tests/golden/shell_cases.json`, of which 23 are bypass
attempts (quote removal, backslash escape, split and long flags, command
substitution, backticks, variable indirection, `bash -c`, nested `sh -c`,
`sudo`/`env`/`xargs`/`timeout`/`nohup`/`command`, `eval`, quoted substitution,
`curl | sh`, base64 piped to `bash`, heredocs, unbalanced quotes, process
substitution, deep nesting, `find -exec`, subshells, `source`). 72 tests total.

`seatbelt parse` exits `3` when the parser is unconfident, distinct from a
policy denial, so a caller can tell "ask" from "deny" without parsing stdout.

## 2026-10-26 — Entry 4: T2, the policy engine

### Decision: severity first, with explicit fallbacks

The first implementation merged rules by severity only: any matching deny wins,
then ask, then allow. That is the right instinct for safety, and it produced a
real bug that the corpus caught immediately: a broad fallback rule
(`net.outbound`: "any request not on the allowlist -> ask") also matched
`pypi.org`, so it outranked the specific `net.registries` allow and every
package download became a question.

Two ways out: first-match-wins in file order, or keep severity and mark the
broad rules as fallbacks. I chose fallbacks. First-match makes safety depend on
authoring order, which is exactly the kind of thing an exhausted policy author
gets wrong at 2am. With `fallback: true`, a rule participates only when nothing
more specific matched, so "deny always wins" survives while specific allows can
still beat generic questions.

`fallback` is now on `net.outbound` and `mcp.default`. It is not on
`file.write_outside`, which instead uses `within_workspace: false` — a positive
match on the condition it actually describes, with no ordering subtlety.

### Decision: probes, not a monolithic evaluator

A shell command is not one question. `echo x | tee -a ~/.bashrc` is a read-only
command and a write to a protected file. `mv ~/.ssh/id_rsa /tmp/k` is a write to
`/tmp` and a destructive read of a key. The engine therefore emits **probes** —
one per command in the tree, one per redirect target, and one each for `tee`,
`dd of=`, `mv`/`cp`/`ln` destinations, `find -delete`, pipe-to-shell, inline
interpreter code, and execution of a session-created file — and merges their
verdicts.

Merging is by severity, and on a tie a probe that matched a real rule beats one
that fell through to `policy.default`. Without that tie-break, `python -c …`
reported `policy.default` instead of the more informative `shell.inline_code`,
because both were `ask`.

### Decision: paths are resolved once, before any matching

`resolve_path` expands `~` and `$HOME`, joins the tracked cwd, and calls
`realpath`, so `../../etc/passwd` and a symlink pointing out of the workspace
both arrive at the same absolute path. Rules and the protected list match that
resolved path. This is also why `mv ~/.ssh/id_rsa /tmp/k` is caught: the source
is emitted as a `mv-source` write probe and hits `protected.path`.

A path containing an unresolved variable (`$DIR/file`) does not resolve; it
becomes an `unparsed` probe and the answer is `ask`.

### Decision: the policy file and the audit log protect themselves

They are not in the YAML protected list. The engine appends `ctx.policy_path`
and `ctx.audit_path` to the protected set at evaluation time. A policy cannot
forget to protect itself, and an agent editing the rules that govern it hits the
same rule as any other protected write.

### Decision: `allow` cannot cover the three risky probe types

Inline interpreter code, commands the parser could not read, and execution of a
file this session created are all `ask` by default. An `allow` rule covers them
only with `allow_inline`, `allow_unparsed` or `allow_agent_created`. `deny` and
`ask` rules match normally. This keeps the escape hatch explicit: you can permit
`python -c` for one narrow flag pattern, but not by accident.

### Known gaps (each has a strict xfail fixture)

These are deliberate, visible and measured. Six in total, pinned in
`src/seatbelt/data/cases.json` and run by both `seatbelt policy test` and pytest
with `xfail(strict=True)`: closing one turns the fixture green and fails the
build until the marker is removed, so the list cannot rot.

| Gap | Fixture | Why it is not caught |
| --- | --- | --- |
| Download then run | `gap_download_then_run` | `curl -o` saves a file without a redirect, so it is not registered as agent-created; the later `/tmp/x.sh` is only an unknown binary |
| Symlink to a protected tree | `gap_symlink_to_ssh` | creating a symlink is a write to the link path, not to the tree it points at |
| Remote copy egress | `gap_rsync_remote` | `rsync`/`scp`/`ssh` targets are not parsed as network destinations |
| Git config persistence | `gap_git_hooks_path` | `git config core.hooksPath` is a repo-level persistence path, and `git` subcommands are not modelled individually |
| `chmod +s` | `gap_chmod_plus_s` | setuid written as bare `+s` does not match the `u+s`/`g+s` patterns |
| Editor writes | `gap_editor_write` | `vim ~/.bashrc` writes files through a process Seatbelt never sees |

### Limitations that are not gaps (they fail closed)

These ask rather than allowing, so they are availability costs, not holes, and
they are covered by the parser's confidence mechanism: heredoc bodies, process
substitution, subshell grouping, `find -exec`, `bash -c` with an unreadable
body, `source`, and command names computed at runtime.

### Corpus

63 cases in `src/seatbelt/data/cases.json`: 31 deny, 13 ask, 13 allow, plus the
6 known gaps above (all expected to deny). The CLI (`seatbelt policy test`) and
the test suite run the same file, so "the shipped policy behaves as documented"
is checked in two places.

Suite: 181 passed, 6 xfailed, 0.78s.

### Also added

- `seatbelt check -- <cmd>` prints a verdict with exit codes 0 allow, 1 deny,
  3 ask, 2 usage/policy error, and `--json` for the full probe list. This is the
  hook the demo and the benchmark will call.
- Rule validation is strict: unknown keys, unknown kinds, duplicate ids, bad
  regexes and unsupported versions all raise rather than being ignored. A typo
  in `comand:` would otherwise silently widen a rule.
- `default.yaml` shipped as package data. `bool` YAML gotcha: `true` and `false`
  in a flow list parse as booleans, not command names — the readonly rule failed
  to load until they were quoted.

Next: T3, `seatbelt run` — the first frontend that actually executes.