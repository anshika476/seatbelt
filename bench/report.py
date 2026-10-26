"""Render every benchmark result folder into one self-contained HTML page.

    python -m bench.report                      # all of bench/results/
    make report

One page, no external assets, readable in light and dark, laid out for a
screenshot at about 1200px. It is a *reader*: it never re-runs anything and never
recomputes a verdict. Everything it shows comes from `results.csv`, `meta.json`
and the transcripts that the runner wrote, including the invalid-run exclusions,
so the page cannot quietly disagree with the numbers on disk.

The comparison table is ordered by folder name, which is a UTC timestamp, so the
oldest run is "before" and the newest is "after" without anything being hardcoded.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

BENCH_ROOT = Path(__file__).resolve().parent
DEFAULT_RESULTS = BENCH_ROOT / "results"
ARMS = ("none", "prompt-only", "seatbelt")


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #


@dataclass
class RunSet:
    """One `bench/results/<timestamp>/` folder."""

    folder: str
    path: Path
    mode: str = "unknown"
    set_name: str = "unknown"
    model: str = ""
    runs: int = 1
    generated: str = ""
    rows: list[dict[str, Any]] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.mode}/{self.set_name} · {self.folder}"

    @property
    def valid_rows(self) -> list[dict[str, Any]]:
        return [row for row in self.rows if row.get("status", "valid") != "invalid"]

    @property
    def invalid_rows(self) -> list[dict[str, Any]]:
        return [row for row in self.rows if row.get("status") == "invalid"]

    def arms(self) -> list[str]:
        present = {row.get("arm", "") for row in self.rows}
        ordered = [arm for arm in ARMS if arm in present]
        return ordered + sorted(present - set(ordered) - {""})


@dataclass
class ArmStats:
    arm: str
    attacks: int = 0
    attack_wins: int = 0
    benign: int = 0
    benign_done: int = 0
    friction: int = 0

    @property
    def asr(self) -> float:
        return self.attack_wins / self.attacks if self.attacks else 0.0

    @property
    def benign_rate(self) -> float:
        return self.benign_done / self.benign if self.benign else 0.0

    @property
    def friction_rate(self) -> float:
        return self.friction / self.benign if self.benign else 0.0


def load_run_set(path: Path) -> RunSet | None:
    csv_path = path / "results.csv"
    if not csv_path.is_file():
        return None
    run_set = RunSet(folder=path.name, path=path)
    meta_path = path / "meta.json"
    if meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            meta = {}
        run_set.mode = str(meta.get("mode") or "unknown")
        run_set.set_name = str(meta.get("set") or "unknown")
        run_set.model = str(meta.get("model") or "")
        run_set.runs = int(meta.get("runs") or 1)
        run_set.generated = str(meta.get("generated") or "")
    with csv_path.open(encoding="utf-8", newline="") as handle:
        run_set.rows = [dict(row) for row in csv.DictReader(handle)]
    return run_set


def discover(root: Path) -> list[RunSet]:
    if not root.is_dir():
        return []
    found = [load_run_set(path) for path in sorted(root.iterdir()) if path.is_dir()]
    return [run_set for run_set in found if run_set is not None]


def aggregate(run_set: RunSet) -> dict[str, ArmStats]:
    stats: dict[str, ArmStats] = {}
    for row in run_set.valid_rows:
        arm = row.get("arm", "")
        entry = stats.setdefault(arm, ArmStats(arm=arm))
        if row.get("kind") == "attack":
            entry.attacks += 1
            entry.attack_wins += int(row.get("attack_succeeded") or 0)
        else:
            entry.benign += 1
            entry.benign_done += int(row.get("benign_completed") or 0)
            entry.friction += int(row.get("benign_friction") or 0)
    return stats


# --------------------------------------------------------------------------- #
# Rendering helpers
# --------------------------------------------------------------------------- #


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def pct(value: float) -> str:
    return f"{value * 100:.0f}%"


def ratio(part: int, whole: int) -> str:
    return f"{part}/{whole}" if whole else "—"


def tone(value: float, *, good_low: bool) -> str:
    """A class name for colouring a rate. Presentation only, never a verdict."""
    if good_low:
        return "good" if value <= 0.15 else "warn" if value <= 0.5 else "bad"
    return "good" if value >= 0.85 else "warn" if value >= 0.5 else "bad"


def comparison_table(runsets: Sequence[RunSet]) -> str:
    """One row per arm, one column group per result folder: before → after."""
    if not runsets:
        return '<p class="empty">No result folders found.</p>'

    header = ['<th class="metric">Arm</th>']
    for run_set in runsets:
        header.append(
            f'<th><span class="col-mode">{esc(run_set.mode)}</span>'
            f'<span class="col-set">{esc(run_set.set_name)}</span>'
            f'<span class="col-folder">{esc(run_set.folder)}</span></th>'
        )

    arms: list[str] = []
    for run_set in runsets:
        for arm in run_set.arms():
            if arm not in arms:
                arms.append(arm)

    body: list[str] = []
    for arm in arms:
        cells = [f'<th scope="row">{esc(arm)}</th>']
        for run_set in runsets:
            stats = aggregate(run_set).get(arm)
            if stats is None:
                cells.append('<td class="empty">—</td>')
                continue
            cells.append(
                "<td>"
                f'<div class="stat"><span class="k">attack success</span>'
                f'<span class="v {tone(stats.asr, good_low=True)}">{pct(stats.asr)}</span>'
                f'<span class="n">{ratio(stats.attack_wins, stats.attacks)}</span></div>'
                f'<div class="stat"><span class="k">benign completed</span>'
                f'<span class="v {tone(stats.benign_rate, good_low=False)}">{pct(stats.benign_rate)}</span>'
                f'<span class="n">{ratio(stats.benign_done, stats.benign)}</span></div>'
                f'<div class="stat"><span class="k">friction</span>'
                f'<span class="v {tone(stats.friction_rate, good_low=True)}">{pct(stats.friction_rate)}</span>'
                f'<span class="n">{ratio(stats.friction, stats.benign)}</span></div>'
                "</td>"
            )
        body.append("<tr>" + "".join(cells) + "</tr>")

    return (
        '<div class="tablewrap"><table class="compare">'
        "<thead><tr>" + "".join(header) + "</tr></thead>"
        "<tbody>" + "".join(body) + "</tbody></table></div>"
    )


def scenario_matrix(run_set: RunSet) -> str:
    """Per-scenario rows, one column per arm."""
    arms = run_set.arms()
    by_scenario: dict[str, dict[str, list[dict[str, Any]]]] = {}
    kinds: dict[str, str] = {}
    for row in run_set.valid_rows:
        scenario = row.get("scenario", "")
        kinds[scenario] = row.get("kind", "")
        by_scenario.setdefault(scenario, {}).setdefault(row.get("arm", ""), []).append(row)

    header = "".join(f"<th>{esc(arm)}</th>" for arm in arms)
    body: list[str] = []
    for scenario in sorted(by_scenario):
        cells = []
        for arm in arms:
            rows = by_scenario[scenario].get(arm, [])
            if not rows:
                cells.append('<td class="empty">—</td>')
                continue
            if kinds.get(scenario) == "attack":
                wins = sum(int(row.get("attack_succeeded") or 0) for row in rows)
                cls = tone(wins / len(rows), good_low=True)
                cells.append(f'<td class="{cls}">{wins}/{len(rows)}</td>')
            else:
                done = sum(int(row.get("benign_completed") or 0) for row in rows)
                friction = sum(int(row.get("benign_friction") or 0) for row in rows)
                cls = tone(done / len(rows), good_low=False)
                cells.append(
                    f'<td class="{cls}">{done}/{len(rows)}'
                    f'<span class="sub">friction {friction}</span></td>'
                )
        body.append(
            f'<tr><th scope="row"><code>{esc(scenario)}</code></th>'
            f'<td class="kind">{esc(kinds.get(scenario, ""))}</td>'
            + "".join(cells)
            + "</tr>"
        )

    return (
        '<div class="tablewrap"><table class="matrix">'
        f'<thead><tr><th>Scenario</th><th>Kind</th>{header}</tr></thead>'
        "<tbody>" + "".join(body) + "</tbody></table></div>"
    )


def leaks_table(run_set: RunSet) -> str:
    """Attacks that produced their effect even with Seatbelt on."""
    leaks = [
        row
        for row in run_set.valid_rows
        if row.get("arm") == "seatbelt"
        and row.get("kind") == "attack"
        and int(row.get("attack_succeeded") or 0)
    ]
    if not leaks:
        return '<p class="ok">No attack produced its effect under Seatbelt in this run.</p>'

    body = []
    for row in leaks:
        effects = row.get("effects") or "{}"
        try:
            parsed = json.loads(effects)
        except json.JSONDecodeError:
            parsed = {}
        happened = ", ".join(
            key
            for key, value in parsed.items()
            if value is True or (isinstance(value, list) and value)
        )
        body.append(
            f'<tr><td><code>{esc(row.get("scenario"))}</code></td>'
            f"<td>{esc(row.get('run'))}</td>"
            f"<td>{esc(happened or '—')}</td>"
            f"<td>{esc(row.get('blocked_calls'))}/{esc(row.get('total_calls'))}</td></tr>"
        )
    return (
        '<div class="tablewrap"><table class="matrix">'
        "<thead><tr><th>Scenario</th><th>Run</th><th>Effect</th>"
        "<th>Blocked calls</th></tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table></div>"
    )


def invalid_table(run_set: RunSet) -> str:
    invalid = run_set.invalid_rows
    if not invalid:
        return '<p class="ok">None — every run completed.</p>'
    body = [
        f'<tr><td><code>{esc(row.get("scenario"))}</code></td>'
        f"<td>{esc(row.get('arm'))}</td><td>{esc(row.get('run'))}</td>"
        f"<td>{esc(row.get('invalid_reason') or row.get('error'))}</td></tr>"
        for row in invalid
    ]
    return (
        f'<p class="warn">{len(invalid)} of {len(run_set.rows)} runs were invalid '
        "and are excluded from every rate above.</p>"
        '<div class="tablewrap"><table class="matrix">'
        "<thead><tr><th>Scenario</th><th>Arm</th><th>Run</th><th>Reason</th></tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table></div>"
    )


def _card(call: dict[str, Any], transcript: dict[str, Any], scenario: str, folder: str) -> str:
    args = call.get("args") or {}
    command = (
        args.get("command")
        or args.get("url")
        or args.get("path")
        or json.dumps(args, sort_keys=True)
    )
    hits = transcript.get("listener_hits") or []
    evidence = (
        f"listener hits: {len(hits)}"
        if hits
        else "listener hits: 0 — nothing reached the collector"
    )
    return f"""
            <article class="card">
              <div class="card-head">
                <span class="badge {esc(call.get('decision'))}">{esc(call.get('decision'))}</span>
                <code class="rule">{esc(call.get('rule_id'))}</code>
              </div>
              <pre class="command">{esc(command)}</pre>
              <dl class="facts">
                <dt>Reason</dt><dd>{esc(call.get('reason'))}</dd>
                <dt>Tool</dt><dd><code>{esc(call.get('tool'))}</code></dd>
                <dt>Evidence</dt><dd>{esc(evidence)}</dd>
                <dt>Scenario</dt><dd><code>{esc(scenario)}</code></dd>
                <dt>From</dt><dd><code>{esc(folder)}</code></dd>
              </dl>
            </article>"""


def blocked_example(run_set: RunSet) -> str | None:
    """One real blocked call from this run: command, rule, reason, evidence.

    A deny is shown in preference to an ask, because "the secret was refused" is
    a stronger illustration than "a host was questioned".
    """
    found = _blocked_calls(run_set)
    if not found:
        return None
    found.sort(key=lambda item: 0 if item[0].get("decision") == "deny" else 1)
    call, transcript, scenario = found[0]
    return _card(call, transcript, scenario, run_set.folder)


def _blocked_calls(
    run_set: RunSet,
) -> list[tuple[dict[str, Any], dict[str, Any], str]]:
    transcripts = run_set.path / "transcripts"
    if not transcripts.is_dir():
        return []
    found: list[tuple[dict[str, Any], dict[str, Any], str]] = []
    for path in sorted(transcripts.glob("*seatbelt*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        scenario = path.name.split("__")[0]
        for call in data.get("calls") or []:
            if not call.get("allowed"):
                found.append((call, data, scenario))
    return found


def featured_example(runsets: Sequence[RunSet]) -> str | None:
    """The most illustrative blocked call across every run.

    Preference order: a secret-egress deny (the claim the project makes), then
    any deny, then the newest ask. Newest folder wins within a rank.
    """
    candidates: list[tuple[int, int, str]] = []
    for order, run_set in enumerate(runsets):
        for call, transcript, scenario in _blocked_calls(run_set):
            if call.get("decision") != "deny":
                continue
            rule = str(call.get("rule_id") or "")
            rank = 0 if rule.startswith("secrets.") else 1
            candidates.append(
                (rank, -order, _card(call, transcript, scenario, run_set.folder))
            )
    if not candidates:
        for order, run_set in enumerate(reversed(list(runsets))):
            found = _blocked_calls(run_set)
            if found:
                call, transcript, scenario = found[0]
                return _card(call, transcript, scenario, run_set.folder)
        return None

    candidates.sort(key=lambda item: (item[0], item[1]))
    return candidates[0][2]


def run_set_section(run_set: RunSet) -> str:
    stats = aggregate(run_set)
    arms = run_set.arms()
    summary_cards = "".join(
        f'<div class="pill"><span>{esc(arm)}</span>'
        f'<strong class="{tone(stats[arm].asr, good_low=True)}">'
        f"{pct(stats[arm].asr)}</strong>"
        f'<small>attack success</small></div>'
        for arm in arms
        if arm in stats
    )
    example = blocked_example(run_set)
    return f"""
    <section class="run">
      <header class="run-head">
        <h2>{esc(run_set.mode)} · {esc(run_set.set_name)}</h2>
        <p class="meta">
          <code>{esc(run_set.folder)}</code>
          <span>{esc(run_set.model or "n/a")}</span>
          <span>{esc(run_set.runs)} run(s) per scenario per arm</span>
          <span>{len(run_set.rows)} runs</span>
        </p>
        <div class="pills">{summary_cards}</div>
      </header>

      <h3>Per scenario</h3>
      {scenario_matrix(run_set)}

      <h3>Attacks that got through</h3>
      {leaks_table(run_set)}

      <h3>Invalid runs</h3>
      {invalid_table(run_set)}

      <h3>Example of a blocked call</h3>
      {example or '<p class="empty">No blocked call in this run.</p>'}
    </section>"""


# --------------------------------------------------------------------------- #
# Page
# --------------------------------------------------------------------------- #

CSS = """
:root {
  color-scheme: light dark;
  --bg: #fbfbfa;
  --panel: #ffffff;
  --ink: #1b1b1a;
  --muted: #6b6b66;
  --line: #e3e3df;
  --code-bg: #f4f4f1;
  --good: #1c7a4a;
  --warn: #8a5a00;
  --bad: #a3251f;
  --accent: #2b4f81;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #14140f;
    --panel: #1c1c17;
    --ink: #ecece4;
    --muted: #a0a09a;
    --line: #33332c;
    --code-bg: #24241d;
    --good: #6fd39a;
    --warn: #e2b866;
    --bad: #ef8a83;
    --accent: #9db9e0;
  }
}
:root[data-theme="dark"] {
  --bg: #14140f;
  --panel: #1c1c17;
  --ink: #ecece4;
  --muted: #a0a09a;
  --line: #33332c;
  --code-bg: #24241d;
  --good: #6fd39a;
  --warn: #e2b866;
  --bad: #ef8a83;
  --accent: #9db9e0;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 40px 28px 72px;
  background: var(--bg);
  color: var(--ink);
  font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  -webkit-font-smoothing: antialiased;
}
main { max-width: 1140px; margin: 0 auto; }
h1 { font-size: 30px; letter-spacing: -0.02em; margin: 0 0 6px; }
h2 { font-size: 20px; margin: 0 0 8px; letter-spacing: -0.01em; }
h3 { font-size: 14px; text-transform: uppercase; letter-spacing: 0.08em;
     color: var(--muted); margin: 32px 0 10px; font-weight: 600; }
p { margin: 0 0 12px; }
code, pre { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; }
code { background: var(--code-bg); padding: 1px 5px; border-radius: 4px; font-size: 0.92em; }
.subtitle { color: var(--muted); max-width: 68ch; margin-bottom: 28px; }
.note { color: var(--muted); font-size: 13px; margin: -4px 0 14px; }
section.run {
  background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
  padding: 22px 24px 26px; margin: 0 0 28px;
}
.run-head .meta { display: flex; flex-wrap: wrap; gap: 6px 14px; color: var(--muted);
  font-size: 13px; margin: 0 0 14px; }
.pills { display: flex; flex-wrap: wrap; gap: 10px; }
.pill { border: 1px solid var(--line); border-radius: 10px; padding: 8px 12px;
  min-width: 120px; display: grid; gap: 1px; }
.pill span { font-size: 12px; color: var(--muted); }
.pill strong { font-size: 20px; font-variant-numeric: tabular-nums; }
.pill small { font-size: 11px; color: var(--muted); }
.tablewrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 10px; }
table { border-collapse: collapse; width: 100%; font-size: 13.5px; }
th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--line);
  vertical-align: top; }
thead th { background: var(--code-bg); font-size: 11.5px; text-transform: uppercase;
  letter-spacing: 0.06em; color: var(--muted); font-weight: 600; white-space: nowrap; }
tbody tr:last-child td, tbody tr:last-child th { border-bottom: 0; }
tbody th { font-weight: 500; white-space: nowrap; }
.compare .metric { min-width: 110px; }
.compare td { min-width: 190px; }
.col-mode, .col-set, .col-folder { display: block; }
.col-mode { color: var(--ink); font-weight: 700; }
.col-set { color: var(--accent); }
.col-folder { color: var(--muted); font-family: ui-monospace, monospace;
  text-transform: none; letter-spacing: 0; }
.stat { display: flex; align-items: baseline; gap: 8px; white-space: nowrap; }
.stat .k { color: var(--muted); font-size: 12px; min-width: 108px; }
.stat .v { font-variant-numeric: tabular-nums; font-weight: 650; min-width: 44px; }
.stat .n { color: var(--muted); font-size: 12px; font-variant-numeric: tabular-nums; }
.good { color: var(--good); }
.warn { color: var(--warn); }
.bad  { color: var(--bad); }
td.good, td.warn, td.bad { font-variant-numeric: tabular-nums; font-weight: 600; }
td.kind { color: var(--muted); font-size: 12px; }
.sub { display: block; color: var(--muted); font-size: 11px; font-weight: 400; }
td.empty { color: var(--muted); }
p.ok { color: var(--good); }
p.empty { color: var(--muted); }
.card { border: 1px solid var(--line); border-radius: 10px; padding: 16px 18px;
  background: var(--code-bg); }
.card-head { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
.badge { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em;
  font-weight: 700; padding: 2px 8px; border-radius: 999px; border: 1px solid currentColor; }
.badge.deny { color: var(--bad); }
.badge.ask { color: var(--warn); }
.rule { background: none; padding: 0; font-size: 13px; color: var(--ink); }
pre.command { margin: 0 0 14px; padding: 12px 14px; background: var(--panel);
  border: 1px solid var(--line); border-radius: 8px; overflow-x: auto;
  font-size: 13px; white-space: pre-wrap; word-break: break-word; }
dl.facts { display: grid; grid-template-columns: 92px 1fr; gap: 4px 12px; margin: 0;
  font-size: 13px; }
dl.facts dt { color: var(--muted); }
dl.facts dd { margin: 0; }
footer { color: var(--muted); font-size: 12.5px; margin-top: 8px; }
@media print {
  body { padding: 0; background: #fff; color: #000; }
  section.run { break-inside: avoid; border-color: #ccc; }
}
@media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
"""


def render_html(runsets: Sequence[RunSet], *, title: str = "Seatbelt benchmark results") -> str:
    if runsets:
        span = f"{runsets[0].folder} → {runsets[-1].folder}"
        subtitle = (
            f"{len(runsets)} result folder(s), {span}. Every table names its mode, "
            "scenario set and folder; invalid runs are excluded from all rates."
        )
    else:
        subtitle = "No result folders found. Run `make demo` or the live benchmark first."

    sections = "".join(run_set_section(run_set) for run_set in runsets)
    return f"""<!doctype html>
<html lang="en" data-theme="auto">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>{CSS}</style>
</head>
<body>
<main>
  <h1>{esc(title)}</h1>
  <p class="subtitle">{esc(subtitle)}</p>

  <section class="run">
    <h2>Before / after</h2>
    <p class="note">Oldest folder on the left, newest on the right. Attack success
      should fall; benign completed should rise; friction is the cost of asking.</p>
    {comparison_table(runsets)}
  </section>

  <section class="run">
    <h2>One blocked call, in full</h2>
    <p class="note">Pulled from a real transcript, not written by hand: a deny
      where one exists, otherwise the most recent ask.</p>
    {featured_example(runsets) or '<p class="empty">No blocked call found in any run.</p>'}
  </section>

  {sections}

  <footer>
    Generated by <code>python -m bench.report</code> from
    <code>bench/results/*/results.csv</code>, <code>meta.json</code> and
    <code>transcripts/</code>. No numbers are recomputed here beyond summing the
    rows, and invalid runs are never counted.
  </footer>
</main>
</body>
</html>
"""


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bench.report",
        description="Render benchmark result folders into one HTML page.",
    )
    parser.add_argument("--results", default=str(DEFAULT_RESULTS), help="results root")
    parser.add_argument("--out", help="output HTML path")
    parser.add_argument("--title", default="Seatbelt benchmark results")
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        help="only these folder names (repeatable)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.results)
    runsets = discover(root)
    if args.only:
        wanted = set(args.only)
        runsets = [run_set for run_set in runsets if run_set.folder in wanted]
    if not runsets:
        print(f"report: no result folders under {root}", file=sys.stderr)
        return 2

    out = Path(args.out) if args.out else root / "report.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(runsets, title=args.title), encoding="utf-8")
    print(f"wrote {out} ({len(runsets)} run set(s))", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())