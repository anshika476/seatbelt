"""Execute a command that policy has already approved.

The one rule this module exists to keep: **execute the exact string that was
checked**. The command is passed to ``bash -c`` as a single argument, never
rebuilt from the parse tree. A rebuilt command would let the parser and the
shell disagree — the parser could inspect `rm -rf ~` while the shell ran
something else — which is precisely the failure mode Seatbelt exists to prevent.

Three containment measures sit around the call:

- ``cwd`` is the declared workspace, so a relative path means what policy
  resolved it to.
- the environment is ``child_env()``: every ``SEATBELT_*`` variable, including
  the audit key, is removed.
- stdout and stderr go to temporary files and are read back capped, so a command
  that prints a gigabyte cannot exhaust memory. A changing working directory does
  not affect us: the child runs in its own session and is killed as a group on
  timeout.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Mapping

from .audit import child_env

#: Default wall-clock limit for a single command.
DEFAULT_TIMEOUT_S = 120.0

#: Default cap, per stream, on captured output.
DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024

#: Exit code used when the command was killed for running too long.
TIMEOUT_EXIT_CODE = 124


@dataclass(frozen=True, slots=True)
class RunResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    truncated: bool = False
    timed_out: bool = False


def bash_path() -> str:
    """The shell used to run adjudicated commands.

    Bash specifically, not ``/bin/sh``: the parser's wrapper and `-c` handling
    assumes bash syntax, and running under a different shell would reintroduce
    the disagreement this module avoids.
    """
    return shutil.which("bash") or "/bin/bash"


def _read_capped(handle, limit: int) -> tuple[str, bool]:
    handle.seek(0)
    data = handle.read(limit + 1)
    truncated = len(data) > limit
    return data[:limit].decode("utf-8", errors="replace"), truncated


def _kill_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        process.kill()


def execute(
    command: str,
    *,
    cwd: str,
    timeout: float = DEFAULT_TIMEOUT_S,
    max_output: int = DEFAULT_MAX_OUTPUT_BYTES,
    env: Mapping[str, str] | None = None,
) -> RunResult:
    """Run ``command`` under bash, bounded in time and output."""
    argv = [bash_path(), "-c", command]
    started = time.monotonic()
    timed_out = False

    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            # Strip SEATBELT_* here rather than trusting every caller: the audit
            # key must not be visible to a command we are about to run.
            env=child_env(env),
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            start_new_session=True,
        )
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(process)
            process.wait()

        duration_ms = int((time.monotonic() - started) * 1000)
        stdout, truncated_out = _read_capped(out, max_output)
        stderr, truncated_err = _read_capped(err, max_output)

    exit_code = process.returncode
    if exit_code is None:
        exit_code = 1
    if exit_code < 0:
        # Killed by a signal: report it the way a shell would.
        exit_code = 128 - exit_code
    if timed_out:
        exit_code = TIMEOUT_EXIT_CODE

    return RunResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_ms=duration_ms,
        truncated=truncated_out or truncated_err,
        timed_out=timed_out,
    )