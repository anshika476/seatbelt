# Seatbelt

Action guardrails for AI agents. Every tool call — shell command, file read or
write, HTTP request, MCP tool — is adjudicated **before** it executes and gets
`allow`, `deny`, or `ask` (human approval).

> Status: early. The skeleton is in place and the plan is public in
> [`docs/BUILD_LOG.md`](docs/BUILD_LOG.md). Interfaces will move.

## The problem

An agent with tool access is an agent with your credentials, your shell, and
your network. Prompt-level instructions ("never run `rm -rf`") are a request,
not a control: they are probabilistic, they can be overridden by content the
agent reads, and they leave no evidence afterwards.

Seatbelt moves the decision out of the model. The policy engine is plain,
deterministic code over a parsed representation of the action, so a denial is a
denial regardless of what the model was persuaded to say.

## Design in one diagram

```
agent -> [ normalize action ] -> [ policy: YAML rules ] -> [ taint + secrets ]
      -> [ merge verdict ] -> allow | deny | ask-human -> execute
                                      |
                              hash-chained audit log
```

Five rules the implementation must keep:

1. **Fail closed.** An unparseable command, an unknown tool, a classifier
   timeout, or an unavailable human resolves to `ask` — never `allow`.
2. **The model is a sensor, not a judge.** The optional open-model injection
   detector can only escalate `allow` to `ask`. Deterministic denials cannot be
   argued with.
3. **Parse, don't regex.** Shell decisions are made on an AST, including
   pipelines, command substitution and wrappers like `bash -c`, `sudo`, `env`.
4. **Every verdict is explainable.** Each record carries a rule id, a reason and
   evidence. The report shows *why*, not just *blocked*.
5. **Never log secrets.** Secret values are held as salted digests; the audit
   log and the published report contain digests only.

## What it covers

| Attack class | Defense |
| --- | --- |
| Destructive shell (`rm -rf ~`, `git push --force`) | parsed AST + deny rules |
| Remote code (`curl … \| sh`, `bash -c "$(curl …)"`) | pipeline shape + domain allowlist |
| Secret egress (`.env`, `~/.ssh`, cloud creds) | secret registry, exact values + decode variants |
| Persistence (`~/.bashrc`, cron, `sudo`) | write-path rules outside the workspace |
| Exfiltration through URLs | taint matching on the outbound string |
| Self-tampering (editing policy or the log) | protected paths + HMAC chain verify |
| Injected instructions in fetched content | strict mode + model signal |

## What it does not cover

Seatbelt adjudicates tool-mediated actions. It is **not** a sandbox: it does not
contain a process that escapes to the kernel, it cannot stop prompt injection
that never reaches a tool call, and it makes no claim about compromised model
weights or side channels. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Install

Linux, Python 3.11+:

```bash
git clone https://github.com/anshika-goel/seatbelt && cd seatbelt
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
seatbelt version
```

## Try it

```bash
seatbelt check -- 'rm -rf /'                  # DENY  shell.rm_recursive   (exit 1)
seatbelt check -- 'pytest -q'                 # ALLOW shell.test_runner    (exit 0)
seatbelt check -- 'python -c "print(1)"'      # ASK   shell.inline_code    (exit 3)
seatbelt check --json -- 'echo x | tee -a ~/.bashrc'
```

Exit codes: `0` allow, `1` deny, `3` ask, `2` usage or policy error.

`seatbelt check` resolves paths before matching, so these are the same verdict:

```bash
seatbelt check -- 'echo x > ~/.bashrc'
seatbelt check -- 'cd / && echo x > ../root/.bashrc'
```

Run the declarative corpus against the shipped policy:

```bash
seatbelt policy test
```

## Development

```bash
make test
```

Windows is not a supported development host: bash parsing, exit-code mapping and
wrapper recursion behave differently there. Use WSL2 or a Linux container.

## License

MIT.
