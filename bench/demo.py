"""One recorded attack, replayed twice: unprotected, then through Seatbelt.

    make demo          # or: python -m bench.demo

Built for a screen recording, and for a cold reader: two steps, the same tool
calls both times, and only the outcome changes. Everything is real — the attack
runs in the sandbox with a canary in a fake home and a listener inside a network
namespace — so the unprotected step genuinely exfiltrates rather than pretending
to.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any, Sequence

from seatbelt.cases import default_policy_path
from seatbelt.policy import Policy

from .agent import run_trace
from .runner import _load_trace, _substitute_trace
from .sandbox import Effects, Sandbox, compute_effects
from .scenario import Scenario, load_set
from .tools import Tools

DEFAULT_SCENARIO = "exfil-env-curl"


def _find(scenario_id: str) -> Scenario:
    for scenario in load_set("dev"):
        if scenario.id == scenario_id:
            return scenario
    raise SystemExit(f"demo: no dev scenario named {scenario_id!r}")


def _run(scenario: Scenario, arm: str, *, policy: Policy) -> tuple[Effects, Any, dict]:
    with Sandbox(scenario.id) as sandbox:
        sandbox.seed(workspace=scenario.workspace, home=scenario.home)
        sandbox.set_responses(scenario.listener)
        tools = Tools(sandbox, arm=arm, policy=policy if arm == "seatbelt" else None)
        tools.pages = scenario.pages

        before = sandbox.snapshot()
        trace = _substitute_trace(_load_trace(scenario.id), sandbox)
        run = run_trace(tools, trace)
        after = sandbox.snapshot()
        effects = compute_effects(before, after, sandbox, scenario.expect)
        hits = len(sandbox.listener_hits())
        return effects, run, {"hits": hits, "calls": tools.state.calls}


def _line(label: str, value: str, *, indent: str = "    ") -> None:
    print(f"{indent}{label:<12} {value}")


def _show_calls(calls: Sequence[Any], *, armed: bool, pause: float) -> None:
    for call in calls:
        args = dict(call.args or {})
        what = args.get("command") or args.get("url") or args.get("path") or ""
        mark = "allowed" if call.allowed else f"{call.decision.upper()} {call.rule_id}"
        print(f"    {'->':<3} {call.tool:<10} {str(what)[:74]}")
        print(f"        {mark}")
        if not call.allowed:
            print(f"        {call.reason}")
        if pause:
            time.sleep(pause)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bench.demo")
    parser.add_argument("--scenario", default=DEFAULT_SCENARIO)
    parser.add_argument("--pause", type=float, default=0.4, help="seconds between lines")
    parser.add_argument("--no-pause", action="store_true")
    args = parser.parse_args(argv)
    pause = 0.0 if args.no_pause else args.pause

    scenario = _find(args.scenario)
    policy = Policy.load(default_policy_path())

    print()
    print("  Seatbelt demo — one recorded attack, replayed twice")
    print(f"  scenario: {scenario.id} — {scenario.name}")
    print()
    time.sleep(pause)

    print("  ── Step 1/2  unprotected agent " + "─" * 40)
    bare, bare_run, bare_info = _run(scenario, "none", policy=policy)
    _show_calls(bare_info["calls"], armed=False, pause=pause)
    leaked = bare.canary_received or bare.listener_received
    print()
    print(f"  RESULT: {'attacker received the data' if leaked else 'nothing left the machine'}")
    print(f"          listener hits: {bare_info['hits']}   canary seen: {bare.canary_received}")
    print()

    print("  ── Step 2/2  the same calls through Seatbelt " + "─" * 27)
    guarded, guarded_run, guarded_info = _run(scenario, "seatbelt", policy=policy)
    _show_calls(guarded_info["calls"], armed=True, pause=pause)
    blocked = guarded.canary_received or guarded.listener_received
    print()
    print(f"  RESULT: {'LEAKED' if blocked else 'blocked — nothing left the machine'}")
    print(f"          listener hits: {guarded_info['hits']}   canary seen: {guarded.canary_received}")
    print()

    if leaked and not blocked:
        verdict = "as expected"
    elif not leaked:
        verdict = "check the harness: the unprotected run did not leak either"
    else:
        verdict = "REGRESSION: Seatbelt let it through"
    print(f"  Unprotected exposed the canary: {leaked}.  Through Seatbelt: {blocked}.  ({verdict})")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())