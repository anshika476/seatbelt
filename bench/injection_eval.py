"""Measure the injection detector on a small labelled set.

    python -m bench.injection_eval                 # whatever from_env() gives
    SEATBELT_NO_LLM=1 python -m bench.injection_eval
    SEATBELT_LLM_BASE_URL=... SEATBELT_LLM_API_KEY=... SEATBELT_LLM_MODEL=... \\
        python -m bench.injection_eval --json

The set is deliberately small and deliberately hard: half the negatives are
security documentation that *quotes* injection phrases. That is where a keyword
detector dies, and the honest number is more useful than a curated one.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from seatbelt.injection import Signal, from_env

DATA = Path(__file__).resolve().parent / "data" / "injection_cases.jsonl"


@dataclass(frozen=True)
class Result:
    id: str
    label: int
    signal: Signal
    predicted: int

    @property
    def correct(self) -> bool:
        return self.predicted == self.label


def load_cases(path: Path = DATA) -> list[dict]:
    cases = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            cases.append(json.loads(line))
    return cases


def run(detector) -> list[Result]:
    results = []
    for case in load_cases():
        signal = detector.scan(case["text"])
        results.append(
            Result(
                id=case["id"],
                label=int(case["label"]),
                signal=signal,
                predicted=1 if signal.fired else 0,
            )
        )
    return results


def summarise(results: list[Result]) -> dict[str, float | int]:
    tp = sum(1 for r in results if r.label == 1 and r.predicted == 1)
    fp = sum(1 for r in results if r.label == 0 and r.predicted == 1)
    fn = sum(1 for r in results if r.label == 1 and r.predicted == 0)
    tn = sum(1 for r in results if r.label == 0 and r.predicted == 0)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "false_positive_rate": fpr,
        "accuracy": (tp + tn) / len(results) if results else 0.0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure the injection detector")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    detector = from_env()
    if detector is None:
        print(
            "no detector configured: set SEATBELT_LLM_* or SEATBELT_NO_LLM=1",
            file=sys.stderr,
        )
        return 2

    results = run(detector)
    stats = summarise(results)
    source = next((r.signal.source for r in results if r.signal.source != "none"), "none")

    if args.json:
        print(
            json.dumps(
                {
                    "detector": type(detector).__name__,
                    "source": source,
                    "stats": stats,
                    "errors": [r.id for r in results if r.signal.error],
                    "false_positives": [r.id for r in results if r.label == 0 and r.predicted == 1],
                    "false_negatives": [r.id for r in results if r.label == 1 and r.predicted == 0],
                },
                indent=2,
            )
        )
        return 0

    print(f"detector: {type(detector).__name__}  (source: {source})")
    print(f"cases:    {len(results)}  ({sum(r.label for r in results)} injected, "
          f"{len(results) - sum(r.label for r in results)} normal)")
    print(
        f"precision {stats['precision']:.2f}  recall {stats['recall']:.2f}  "
        f"FPR {stats['false_positive_rate']:.2f}  accuracy {stats['accuracy']:.2f}"
    )
    print(f"tp={stats['tp']} fp={stats['fp']} fn={stats['fn']} tn={stats['tn']}")

    errors = [r for r in results if r.signal.error]
    if errors:
        print(f"\nerrors ({len(errors)}):")
        for result in errors:
            print(f"  {result.id}: {result.signal.error}")

    for title, wanted in (("false positives", 0), ("false negatives", 1)):
        rows = [
            r for r in results if (r.label == 0 and wanted == 0 and r.predicted == 1)
            or (r.label == 1 and wanted == 1 and r.predicted == 0)
        ]
        if rows:
            print(f"\n{title}:")
            for result in rows:
                print(
                    f"  {result.id} score={result.signal.score:.2f} "
                    f"span={result.signal.span[:60]!r}"
                )
    return 0


if __name__ == "__main__":
    sys.exit(main())