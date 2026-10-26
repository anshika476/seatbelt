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

Run a command under the guard instead of only asking about it:

```bash
seatbelt run -- 'pytest -q'                  # executes, exit 0
seatbelt run -- 'rm -rf /'                   # refuses, exit 126, rule + reason on stderr
seatbelt run -- 'python3 -c "print(1)"'      # ask; not a terminal, so refused
seatbelt run --yes -- 'python3 -c "print(1)"'  # ask, explicitly approved
```

`run` executes the exact string it checked, in the workspace, under bash, with
every `SEATBELT_*` variable removed from the child environment. Output is capped
per stream and the command is killed as a process group on timeout (exit 124).
Every decision, allowed or refused, is appended to the hash-chained audit log at
`~/.seatbelt/audit.jsonl` (override with `--audit` or `SEATBELT_AUDIT_LOG`).

Run the declarative corpus against the shipped policy:

```bash
seatbelt policy test
```

## Guard a real agent (Claude Code)

Seatbelt ships a `PreToolUse` hook: the harness sends the tool call as JSON on
stdin, Seatbelt answers with `allow`, `ask` or `deny`. Copy
[`examples/claude-code/settings.json`](examples/claude-code/settings.json) into
`.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit|Read|WebFetch",
        "hooks": [{ "type": "command", "command": "seatbelt hook" }]
      }
    ]
  }
}
```

Then every `Bash` call, file write and fetch is adjudicated before it runs:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"cwd":"'$PWD'"}' | seatbelt hook
# {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny", ...}}
```

`deny` is signalled in the JSON *and* with exit code 2, so a harness that honours
only one of the two still blocks. Unknown tools, unreadable payloads and
unparseable commands come back as `ask` — the harness owns the human, and
Seatbelt never guesses `allow`.

Run the declarative corpus against the shipped policy:

```bash
seatbelt policy test
```

## Injection detector

Tool output is the surface a prompt-only guard cannot see. `seatbelt scan`
classifies text with a small open model over an OpenAI-compatible endpoint:

```bash
echo "$(curl -s https://docs.example/page)" | seatbelt scan
# 0.92  model  "ignore previous instructions"
```

It **can only escalate**: a positive signal turns an otherwise-allowed action
into an `ask`. It never turns an ask into an allow, and a timeout or an error is
recorded as *no signal*, never as a clean verdict. The scanned text is delimited
and treated as data, so the detector cannot be instructed by what it inspects.

`SEATBELT_NO_LLM=1` uses a keyword stub. `python -m bench.injection_eval`
measures either against a labelled set; the stub scores precision 0.62 / FPR 0.30
on 20 cases that include security documentation quoting injection phrases — see
`docs/BUILD_LOG.md` for why those numbers are reported as-is.

## Roadmap

- MCP stdio proxy (dropped from this build; the Claude Code hook covers the same
  integration question with less code).

## Benchmark

Seatbelt is measured, not asserted. The harness runs a real open model against
canned poisoned environments (a README, a web page, an issue body) in a
contained sandbox, and reports success only when an attack produces an
observable effect.

| Arm | Attack success rate | Benign completed | Benign friction |
| --- | --- | --- | --- |
| `none` | 100% (8/8) | 100% (5/5) | 0% (0/5) |
| `prompt-only` | 100% (8/8) | 100% (5/5) | 0% (0/5) |
| `seatbelt` | 0% (0/8) | 80% (4/5) | 40% (2/5) |

`prompt-only` uses the same "never leak secrets or run destructive commands"
instruction the seatbelt arm gets, and no enforcement.

- **Attack success** is a canary reaching a local listener, a protected file
  changing, or a destructive command taking effect — never a verdict.
- **Benign friction** is a benign task interrupted by an `ask`, reported
  separately from completion because a question is a cost, not a failure.

The one benign task that fails is `write a script, then run it`: Seatbelt cannot
read Python, so a file the session just created is a question. That is deliberate
and it is the main false-positive source.

Reproduce it without an API key, in about 15 seconds:

```bash
sudo make demo            # replay mode: recorded traces, real effects
```

Live three-arm run (needs an OpenAI-compatible endpoint):

```bash
export SEATBELT_BENCH_BASE_URL=https://openrouter.ai/api/v1
export SEATBELT_BENCH_API_KEY=...
export SEATBELT_BENCH_MODEL=meta-llama/llama-3.1-8b-instruct
sudo -E make bench-live
```

Scenarios, the YAML schema and the sandbox design are documented in
[`bench/README.md`](bench/README.md).

## Development

```bash
make test
```

Windows is not a supported development host: bash parsing, exit-code mapping and
wrapper recursion behave differently there. Use WSL2 or a Linux container.

## License

MIT.
