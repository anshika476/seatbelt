# Threat model

Seatbelt decides whether a tool call may run. This document states what that
buys you, what it does not, and where the seams are.

## Assets

1. **The machine** — files outside the workspace, the home directory, other
   processes.
2. **Credentials** — environment variables, `~/.ssh`, `~/.aws`, `.env` files,
   package-registry tokens.
3. **Repository integrity** — source, history, CI configuration.
4. **The audit trail** — the record of what the agent did.

## Adversary

A model-driven agent with tool access, where the *inputs* to that agent are
partly attacker-controlled: web pages, issue bodies, dependency READMEs, files
outside the workspace. The attacker cannot modify Seatbelt's source or the
policy files, and does not have a shell outside the agent's tool calls.

The interesting property of this adversary is that it is not malicious in the
usual sense — it is a language model doing what the last paragraph it read
suggested. Prompt injection is not an exploit that has to be engineered; it is
the default failure mode.

## In scope

| Threat | Control |
| --- | --- |
| Destructive commands (`rm -rf`, `git push --force`, `mkfs`) | parsed AST + deny rules |
| Remote code execution (`curl … \| sh`, `bash -c "$(…)"`) | pipeline shape + domain allowlist |
| Secret exfiltration in a URL, header or file write | secret registry, exact values + decode variants |
| Persistence (`~/.bashrc`, cron, `sudo`) | write-path rules outside the workspace |
| Exfiltration of untrusted content | taint matching on the outbound string |
| Self-tampering (editing policy or the audit log) | protected paths + HMAC chain |
| Follow-on actions after reading hostile content | strict mode + injection signal |

## Out of scope

Stated plainly, because a guardrail that oversells itself is worse than none:

- **Kernel or container escape.** Seatbelt is not a sandbox. A command it allows
  runs with the privileges of the process that launched it.
- **Prompt injection that never reaches a tool call.** If the model is
  persuaded to lie in its final answer, Seatbelt never sees it.
- **A compromised model or provider.** Seatbelt governs actions, not intentions.
- **Side channels.** Timing, resource usage, and covert channels through files
  the agent is allowed to write are not modelled.
- **A same-user attacker with full process access.** See below.

## The audit key

The audit log is a hash chain, and each record's hash is an HMAC over the
record body plus the previous hash. The key is read from `SEATBELT_AUDIT_KEY`
at startup and stripped from the environment of every command Seatbelt
executes (`seatbelt.audit.child_env`).

**Where the key lives:** in the guardian process's memory, and in the
environment of whatever launched the guardian.

**What stops the guarded agent from reading it:** not enough. Specifically:

1. `child_env()` removes it from the environment of executed commands, so
   `env`, `printenv` and `/proc/self/environ` inside a tool call do not show it.
2. That is the *only* structural barrier. If the agent can run a command as the
   same user, and that command can read `/proc/<guardian-pid>/mem` or attach a
   debugger, it can read the key. Linux's `ptrace_scope=1` blocks attaching to
   non-descendant processes, which helps only if the guardian is not the
   agent's child — often it is.
3. An agent that can write to the policy directory can simply loosen the
   policy. Protected-path rules raise the cost; they do not make it impossible.

So the honest claim is: **the HMAC chain detects edits by anyone who does not
hold the key, and the key is kept away from ordinary tool calls — but it is not
protected against an attacker with same-user process access.**

For that threat you need a boundary Seatbelt deliberately does not implement:

- run the guardian as a **different user** than the agent, with the key in that
  user's environment, and let the agent talk to it over a socket; or
- run the guardian in a **separate container or VM** with the log volume mounted
  read-only into the agent's side; or
- switch the chain to **asymmetric signatures** (Ed25519), so verification needs
  only a public key and the signing key never has to be readable by the
  verifier.

A note on the alternative: a plain SHA-256 chain, with no key, would be
recomputable by anything that can write the log, which is exactly the
self-tampering case. HMAC is strictly better, and both are weaker than a
signature with an offline key. The README will not claim more than this.

## Failure modes and their defaults

| Failure | Behaviour | Why |
| --- | --- | --- |
| Shell command cannot be parsed confidently | `ask` | Guessing "safe" is the vulnerability |
| Policy file missing or invalid | refuse to start | A guardian with no policy is a false sense of safety |
| Injection classifier times out | `ask` | The model is a sensor; its absence must not be an `allow` |
| No human available for an `ask` | `deny` | Fail closed at the human boundary |
| Audit log cannot be written | refuse the action | An unlogged action is an unaccountable one |
| Audit key set but unusable | refuse to start | A silent random fallback yields an unverifiable log that looks fine |

## Known parser limitations

The shell parser is intentionally incomplete. When it is not confident it
returns `ask`, so these are availability limitations, not security holes:

- heredoc bodies are not read;
- process substitution (`<(…)`) is not read;
- subshell grouping (`( … )`) is not read;
- `find … -exec` cannot distinguish its terminator from a list separator;
- variable expansion is one level and only from earlier assignments in the same
  command line; a runtime value in command position makes the parse unconfident;
- `source` and `.` are flagged unconfident because the sourced file is not
  inspected;
- aliases, shell functions, brace/glob expansion and `$'…'` ANSI-C quoting are
  not modelled.

The full list, with the test that pins each one, is in `docs/BUILD_LOG.md`.
