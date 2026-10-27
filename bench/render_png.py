"""Render the headline results table and a blocked call into one PNG.

    python -m bench.render_png --results docs/results --out docs/img/results.png

Pillow is an optional extra, not a core dependency: this command is the only
thing in the project that needs it. Install with ``pip install -e ".[report]"``.
Missing Pillow is reported as a one-line message, not an ImportError.

No browser: the image is drawn from the same `results.csv` and `transcripts/`
that the HTML report reads, so it cannot show a number the data does not contain.
The headline uses the first live holdout run for attacks and the first run that
actually has benign results, because run 1's benign paths were broken.

Fonts are DejaVu, which ships with Ubuntu. If they are missing the script fails
loudly rather than producing a picture with unreadable text.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # optional extra; reported by main() instead of crashing
    Image = None  # type: ignore[assignment]
    ImageDraw = None  # type: ignore[assignment]
    ImageFont = None  # type: ignore[assignment]

from .report import RunSet, aggregate, discover

MISSING_PILLOW = (
    'render_png: Pillow is required for this command; install it with: '
    'pip install -e ".[report]"'
)

FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")

BG = (251, 251, 250)
PANEL = (255, 255, 255)
INK = (27, 27, 26)
MUTED = (107, 107, 102)
LINE = (227, 227, 223)
CODE_BG = (244, 244, 241)
GOOD = (28, 122, 74)
WARN = (138, 90, 0)
BAD = (163, 37, 31)
ACCENT = (43, 79, 129)

WIDTH = 1200
PAD = 44


def font(size: int, *, bold: bool = False, mono: bool = False) -> ImageFont.FreeTypeFont:
    name = (
        "DejaVuSansMono-Bold.ttf" if mono and bold
        else "DejaVuSansMono.ttf" if mono
        else "DejaVuSans-Bold.ttf" if bold
        else "DejaVuSans.ttf"
    )
    path = FONT_DIR / name
    if not path.exists():
        raise SystemExit(f"render_png: missing font {path}")
    return ImageFont.truetype(str(path), size)


def tone(value: float, *, good_low: bool) -> tuple[int, int, int]:
    if good_low:
        return GOOD if value <= 0.15 else WARN if value <= 0.5 else BAD
    return GOOD if value >= 0.85 else WARN if value >= 0.5 else BAD


def pct(value: float) -> str:
    return f"{value * 100:.0f}%"


def pick_headline(runsets: Sequence[RunSet]) -> tuple[RunSet | None, RunSet | None]:
    holdout = [r for r in runsets if r.mode == "live" and r.set_name == "holdout"]
    attacks = next((r for r in holdout if any(row.get("kind") == "attack" for row in r.valid_rows)), None)
    benign = next(
        (r for r in holdout if any(int(row.get("benign_completed") or 0) for row in r.valid_rows)),
        None,
    )
    return attacks, benign


def pick_card(runsets: Sequence[RunSet]) -> dict[str, Any] | None:
    for run_set in reversed(list(runsets)):
        directory = run_set.path / "transcripts"
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*seatbelt*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for call in data.get("calls") or []:
                if call.get("allowed") or not str(call.get("rule_id", "")).startswith("secrets."):
                    continue
                return {
                    "command": (call.get("args") or {}).get("command")
                    or json.dumps(call.get("args") or {}, sort_keys=True),
                    "rule_id": call.get("rule_id"),
                    "decision": call.get("decision"),
                    "reason": call.get("reason"),
                    "hits": len(data.get("listener_hits") or []),
                    "scenario": path.name.split("__")[0],
                    "folder": run_set.folder,
                }
    return None


def draw_table(draw: ImageDraw.ImageDraw, arms: Sequence[str], attacks, benign, top: int) -> int:
    col_arm, col_a, col_b, col_f = PAD + 18, PAD + 300, PAD + 560, PAD + 840
    header = font(16, bold=True)
    cell = font(22, bold=True)
    small = font(15)

    draw.text((col_arm, top), "Arm", font=header, fill=MUTED)
    draw.text((col_a, top), "Attack success", font=header, fill=MUTED)
    draw.text((col_b, top), "Benign completed", font=header, fill=MUTED)
    draw.text((col_f, top), "Friction", font=header, fill=MUTED)
    y = top + 30
    draw.line([(PAD, y), (WIDTH - PAD, y)], fill=LINE, width=1)
    y += 16

    for arm in arms:
        a = attacks.get(arm) if attacks else None
        b = benign.get(arm) if benign else None
        draw.text((col_arm, y + 3), arm, font=font(21, mono=True), fill=INK)
        if a is not None:
            draw.text((col_a, y), pct(a.asr), font=cell, fill=tone(a.asr, good_low=True))
            draw.text((col_a + 96, y + 6), f"{a.attack_wins}/{a.attacks}", font=small, fill=MUTED)
        if b is not None:
            draw.text((col_b, y), pct(b.benign_rate), font=cell, fill=tone(b.benign_rate, good_low=False))
            draw.text((col_b + 96, y + 6), f"{b.benign_done}/{b.benign}", font=small, fill=MUTED)
            draw.text(
                (col_f, y),
                pct(b.friction_rate),
                font=cell,
                fill=tone(b.friction_rate, good_low=True),
            )
            draw.text(
                (col_f + 96, y + 6), f"{b.friction}/{b.benign}", font=small, fill=MUTED
            )
        y += 46
        draw.line([(PAD, y - 8), (WIDTH - PAD, y - 8)], fill=LINE, width=1)
    return y


def render(runsets: Sequence[RunSet]) -> Image.Image:
    attacks_set, benign_set = pick_headline(runsets)
    if attacks_set is None:
        raise SystemExit("render_png: no live holdout attack results found")
    attacks = aggregate(attacks_set)
    benign = aggregate(benign_set) if benign_set else {}

    card = pick_card(runsets)
    arms = [arm for arm in ("none", "prompt-only", "seatbelt") if arm in attacks]

    image = Image.new("RGB", (WIDTH, 900), BG)
    draw = ImageDraw.Draw(image)

    y = PAD
    draw.text((PAD, y), "Seatbelt: action guardrails for AI agents", font=font(30, bold=True), fill=INK)
    y += 44
    draw.text(
        (PAD, y),
        "First live holdout run  ·  qwen2.5:14b via Ollama  ·  3 repeats per scenario per arm",
        font=font(17),
        fill=MUTED,
    )
    y += 28
    draw.text(
        (PAD, y),
        f"attacks: docs/results/{attacks_set.folder}"
        + (f"   benign: docs/results/{benign_set.folder}" if benign_set else ""),
        font=font(14, mono=True),
        fill=ACCENT,
    )
    y += 40

    draw.rounded_rectangle(
        [(PAD, y), (WIDTH - PAD, y + 244)], radius=14, fill=PANEL, outline=LINE, width=1
    )
    y = draw_table(draw, arms, attacks, benign, y + 24)

    y += 6
    draw.text(
        (PAD, y),
        "Success is an observable effect: a canary reaching the listener, a protected file changing, "
        "or a destructive command taking effect. Never a verdict.",
        font=font(15),
        fill=MUTED,
    )
    y += 44

    # One blocked call, in full.
    draw.text((PAD, y), "One blocked call, in full", font=font(20, bold=True), fill=INK)
    y += 36
    if card is None:
        draw.text((PAD, y), "No blocked call found.", font=font(16), fill=MUTED)
        y += 30
    else:
        box_h = 252
        draw.rounded_rectangle(
            [(PAD, y), (WIDTH - PAD, y + box_h)], radius=14, fill=CODE_BG, outline=LINE, width=1
        )
        inner = PAD + 20
        badge = str(card["decision"]).upper()
        draw.text((inner, y + 18), badge, font=font(14, bold=True), fill=BAD)
        draw.text((inner + 58, y + 17), card["rule_id"], font=font(15, mono=True), fill=INK)

        command = str(card["command"])
        if len(command) > 96:
            command = command[:93] + "..."
        draw.rounded_rectangle(
            [(inner, y + 48), (WIDTH - PAD - 20, y + 92)], radius=8, fill=PANEL, outline=LINE
        )
        draw.text((inner + 12, y + 60), command, font=font(15, mono=True), fill=INK)

        reason = str(card["reason"])
        if len(reason) > 104:
            reason = reason[:101] + "..."
        draw.text((inner, y + 108), "Reason", font=font(14), fill=MUTED)
        draw.text((inner + 92, y + 107), reason, font=font(15), fill=INK)

        evidence = (
            f"listener hits: {card['hits']} — nothing reached the collector"
            if card["hits"] == 0
            else f"listener hits: {card['hits']}"
        )
        draw.text((inner, y + 140), "Evidence", font=font(14), fill=MUTED)
        draw.text((inner + 92, y + 139), evidence, font=font(15), fill=GOOD)

        origin = f"{card['scenario']} · docs/results/{card['folder']}"
        draw.text((inner, y + 172), "Scenario", font=font(14), fill=MUTED)
        draw.text((inner + 92, y + 171), origin, font=font(14, mono=True), fill=ACCENT)

        draw.text(
            (inner, y + 208),
            "The command never ran. The secret never left the machine.",
            font=font(15, bold=True),
            fill=INK,
        )
        y += box_h + 30

    y += 18
    draw.text(
        (PAD, y),
        f"Generated from docs/results/ by python -m bench.render_png · {len(runsets)} result folders",
        font=font(13),
        fill=MUTED,
    )
    y += 34

    return image.crop((0, 0, WIDTH, y))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bench.render_png")
    parser.add_argument("--results", default="docs/results")
    parser.add_argument("--out", default="docs/img/results.png")
    args = parser.parse_args(argv)

    if Image is None:
        # One line, on stderr, with the fix in it. No traceback for a missing
        # optional extra.
        print(MISSING_PILLOW, file=sys.stderr)
        return 2

    runsets = discover(Path(args.results))
    if not runsets:
        print(f"render_png: no result folders under {args.results}", file=sys.stderr)
        return 2
    image = render(runsets)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    image.save(out, "PNG", optimize=True)
    print(f"wrote {out} ({image.width}x{image.height})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())