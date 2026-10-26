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
