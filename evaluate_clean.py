#!/usr/bin/env python3
"""Temiz N=300: sır yokken yanlış alarm."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from masking import MaskingEngine

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "data" / "extensions" / "clean_code_snippets_n300.json"
OUT = ROOT / "out" / "clean_n300_report.json"


def main() -> None:
    records = json.loads(SRC.read_text(encoding="utf-8"))["records"]
    engine = MaskingEngine()
    fp = 0
    by_type: Counter[str] = Counter()
    for rec in records:
        result = engine.mask(rec["code_text"])
        if result.findings:
            fp += 1
            for f in result.findings:
                by_type[f.type] += 1
        engine.clear()
    n = len(records)
    report = {
        "n": n,
        "fp_samples": fp,
        "fp_rate": round(fp / n, 4),
        "findings_by_type": dict(by_type),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
