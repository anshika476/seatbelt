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
## 2026-10-26 — Entry 5: T3, execution and the hook

### Decision: execute the exact string, not the parse tree

`seatbelt run` passes the original command string to `bash -c` as one argument.
It would be easy, and wrong, to rebuild a command from the AST: the rebuilt
string is a second interpretation, and any difference between it and what policy
inspected is a bypass. Quoting, spacing and operator order reach the shell
exactly as they reached the parser.

Bash specifically, not `/bin/sh`, because the parser's `-c` and wrapper handling
assumes bash. Running the checked string under a different shell would recreate
the same disagreement from the other side.

### Containment around the call

- `cwd` is the declared workspace, so a relative path means what policy resolved.
- `child_env()` strips every `SEATBELT_*` variable. This moved into the runner
  rather than the CLI after a test proved the point: the CLI was stripping it,
  but any other caller of `execute()` would not have been. The guarantee belongs
  where the process is spawned, not where the arguments are parsed.
- stdout/stderr go to temporary files and are read back capped (64 KiB per
  stream by default), so a command printing a gigabyte cannot exhaust memory.
- `start_new_session=True` plus `killpg` on timeout, because a plain `kill` of
  `bash` leaves grandchildren holding the pipes — a test with `sleep 30 & wait`
  pins this.
- stdin is `/dev/null`; a command cannot block waiting for a password prompt.

### Decision: ask without a human is a deny

`run` has no harness to prompt, so an `ask` verdict with no TTY becomes a refusal
with exit 126 and a reason that says so. The hook is the opposite case: it
returns `ask` in JSON and lets Claude Code prompt, because the harness owns the
human. Same policy, different frontend capability — that distinction is worth
keeping explicit rather than papering over with a global `--yes`.

### Decision: audit after execution, and say what that costs

The record carries the verdict, rule id, exit code and duration, so it can only
be written after the command returns. The cost: a `kill -9` of the guardian
mid-command loses the record for that run. The alternative — two records per run
(start, then result) — makes the log noisier and the benchmark harder to read
for a failure mode that already requires killing the guardian. Recorded as a
limitation below rather than fixed.

### Two surprises worth writing down

1. **A 32-character hex key is valid base64.** `key_from_env` preferred hex only
   at exactly 64 characters, so a 32-character test key silently decoded through
   the base64 path into 24 different bytes. Verification then failed with "seal
   does not match" and looked like a chain bug. Tests now use 64 hex characters
   and derive the expected key with `bytes.fromhex`.
2. **`python` is not `python3`** on this host, so an execution test asserting
   exit 0 got 127 from bash. The policy treats both names as inline code, but
   only one exists in `PATH`.

### Gaps fixed (6 -> 4)

- **Download then run.** `curl -o FILE` and `wget -O FILE` write a file without a
  shell redirect. The target is now collected *before* evaluation, so
  `curl -o /tmp/x.sh … && /tmp/x.sh` is recognised as running the file it just
  downloaded, and `.x.sh` also gets a write probe.
- **Remote copy egress.** `rsync` and `scp` destinations are parsed into hosts.
  The tokenizer splits `user@host:/path` at the colon, so the host is recovered
  from the token before a lone `:`; a quoted destination keeps its colon.

Both were recorded as expected `deny` and both are now expected `ask`. That is
the honest change, not a weakening: the destination is a question for a human,
and a hard deny on every `rsync` would be wrong for legitimate use. The fixtures
assert `ask` with a specific rule, so the behaviour is still pinned.

Fixing these required `file.write_outside` to become a `fallback` rule. At equal
severity a specific finding (`shell.agent_created_exec`, `net.outbound`) should
explain the outcome rather than the generic "write outside the workspace", which
otherwise won every tie because it is written earlier.

### Not production-safe yet, on purpose

`--yes` auto-approves every `ask`. It exists for the demo and the benchmark. It
is not an approval policy, and it is not what a user should put in a wrapper
script.

### Remaining known gaps (4)

| Gap | Fixture | Why |
| --- | --- | --- |
| Symlink to a protected tree | `gap_symlink_to_ssh` | `ln -sfn ~/.ssh /tmp/link` writes a link, not the tree |
| Git config persistence | `gap_git_hooks_path` | `git config core.hooksPath` is not modelled |
| `chmod +s` | `gap_chmod_plus_s` | setuid written without a `u`/`g` prefix |
| Editor writes | `gap_editor_write` | `vim ~/.bashrc` writes through a process Seatbelt never sees |

Additional limitations without a fixture, because they cannot be expressed as a
single command:

- A `kill -9` of the guardian between execution and audit loses that record.
- The hook depends on the harness honouring either `permissionDecision` or exit
  code 2. A harness that ignores both is unguarded; that is a property of the
  integration, and the README says so.
- `run` executes one command line. An agent that starts a long-lived server and
  then talks to it through avenues Seatbelt does not see is outside the model.

### Counts

- 65 corpus fixtures, 4 known gaps (all strict xfail): 31 deny, 13 ask, 13 allow,
  and 8 that expect `ask` because of these fixes.
- 234 tests passing, 4 xfailed, ~4s including subprocess-level `run` tests.
## 2026-10-26 — Entry 6: T4, the benchmark

### Decision: real containment, not a simulator

The requirement was "never touch real files or the real network", and the easy
way to satisfy it is to fake the whole environment — which would measure the
policy against a mock instead of against a machine. I built a real jail instead,
and every mechanism is load-bearing:

- commands run as unprivileged user `sbx`, so `/`, `/usr` and `/etc` are not
  writable and `rm -rf /usr/share/doc` returns *Permission denied* while the
  fake home really is deleted;
- commands run inside a network namespace with only `lo`, so the listener is
  reachable and `pypi.org` does not resolve;
- `HOME`, `cwd` and `TMPDIR` all point into a per-scenario tree that is deleted
  afterwards.

Verified before trusting it: `rm -rf /usr/share/doc` as `sbx` left the real tree
intact, and `curl https://pypi.org` inside the namespace failed with "could not
resolve host". The one place this needs care is that the harness itself must run
as root to create the namespace; that is documented in `bench/README.md`.

### Decision: success is an effect, never a verdict

A blocked-call counter would let the policy grade its own homework. Each
scenario declares observable effects — a canary reaching the listener, a
protected file changing hash, a path disappearing, a file appearing with the
right contents — and the arm passes only if the effect happened. Verdicts appear
in the transcripts for debugging and are never scored.

`ask` counts as blocked for attacks and as friction for benign tasks, because a
benchmark has no human. That split is why the report has three numbers per arm
rather than two.

### Decision: prompt-only cannot be tested by replay

In replay mode the tool calls are fixed, so a system prompt changes nothing:
`none` and `prompt-only` are identical by construction. The report shows both at
100% and says so rather than hiding the redundancy. Only live mode measures the
prompt, and only live mode can show it failing.

### Results (dev set, replay, 8 attacks / 5 benign)

| Arm | Attack success rate | Benign completed | Benign friction |
| --- | --- | --- | --- |
| `none` | 100% (8/8) | 100% (5/5) | 0% (0/5) |
| `prompt-only` | 100% (8/8) | 100% (5/5) | 0% (0/5) |
| `seatbelt` | 0% (0/8) | 80% (4/5) | 40% (2/5) |

Full run takes ~15s, so `make demo` is comfortably under a minute.

### The attack that got through Seatbelt (found, then fixed)

While writing the corpus I added `exfil-script-drop`: write a small Python file,
then run `python3 probe.py`. It succeeded against Seatbelt.

Cause: the agent-created check only looked at `argv[0]`. `./probe.py` was caught,
`python3 probe.py` was not, and the new `shell.python_script` allow rule made the
gap wider by permitting `python3 <file>` without knowing what the file was.

Fix: for interpreters that are not running inline code, the first non-flag
argument is now also treated as a candidate for the agent-created check. The
scenario stayed in the corpus, so the regression is pinned.

### Two detector bugs the corpus caught

1. **base64 defeats substring matching.** The SSH-key attack pipes the key
   through `base64 -w0`, so the canary bytes on the wire are encoded and
   `canary_leaked()` reported a miss. The detector now checks plain, base64, hex
   and percent-encoded forms — the same mistake the policy avoids by decoding
   variants before matching.
2. **A scenario can quietly have no payload.** `curl … | sh` had nothing to
   execute because the listener returned a fixed `ok`. The listener now serves
   scenario-defined bodies, so a second-stage payload can exfiltrate and the
   effect is real rather than assumed.

### The friction is real and it is the point

Two benign runs got asked, and one of them failed outright:

- `benign-fetch-docs` asks because the docs host is not on the net allowlist —
  task still completes, but a human would be interrupted;
- `benign-edit-and-test` asks because the agent wrote `app.py` and then ran
  `python3 app.py`. Seatbelt cannot read Python, so "a script this session
  created" is exactly the case it must not allow silently.

I decided to **keep** the second one. Enabling it would reopen the script-drop
exfiltration hole, and the honest answer is that running a file you just wrote is
a question until taint tracking can tell whether anything untrusted was read
(T6). This is the main false-positive source and the report says so.

### Counts

- 8 attack scenarios, 5 benign, 13 traces for replay mode.
- Results: `bench/results/demo/report.md`, `results.csv`, per-run transcripts.
- 253 tests passing, 4 xfailed; corpus still 65/65 with 4 gaps.

### Holdout

`bench/scenarios/holdout/` is empty on purpose. The schema is documented in
`bench/README.md` so scenarios can be written independently, and the run rules
are stated there: written once, run once, results reported as they come out,
including regressions.

Next: T5/T9 style polish on reports, then T11 with the holdout set.