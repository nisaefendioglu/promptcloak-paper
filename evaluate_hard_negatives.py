#!/usr/bin/env python3
"""Zor negatif N=300: sır benzeri tuzaklarda yanlış alarm."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from masking import MaskingEngine

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "data" / "extensions" / "hard_negatives_n300.json"
OUT = ROOT / "out" / "hard_negatives_n300_report.json"


def main() -> None:
    records = json.loads(SRC.read_text(encoding="utf-8"))["records"]
    engine = MaskingEngine()
    fp_samples = 0
    fp_expected = 0
    fp_unexpected = 0
    by_kind: Counter[str] = Counter()
    by_type: Counter[str] = Counter()
    examples: list[dict] = []
    for rec in records:
        result = engine.mask(rec["code_text"])
        if result.findings:
            fp_samples += 1
            by_kind[rec["kind"]] += 1
            for f in result.findings:
                by_type[f.type] += 1
            if rec.get("expect_fp"):
                fp_expected += 1
            else:
                fp_unexpected += 1
            if len(examples) < 12:
                examples.append(
                    {
                        "id": rec["id"],
                        "kind": rec["kind"],
                        "expect_fp": rec.get("expect_fp"),
                        "types": [f.type for f in result.findings],
                        "values": [f.value for f in result.findings],
                    }
                )
        engine.clear()
    n = len(records)
    report = {
        "n": n,
        "fp_samples": fp_samples,
        "fp_rate": round(fp_samples / n, 4),
        "clean_samples": n - fp_samples,
        "fp_on_expect_fp_rows": fp_expected,
        "fp_on_other_rows": fp_unexpected,
        "fp_by_kind": dict(by_kind),
        "findings_by_type": dict(by_type),
        "examples": examples,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
