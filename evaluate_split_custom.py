#!/usr/bin/env python3
"""Bölünmüş sır N=300: yerleşik katalog vs veri setindeki önerilen özel regex."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from masking import MaskingEngine

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data" / "extensions" / "split_pattern_custom_n300.json"
OUT = ROOT / "out" / "split_pattern_custom_eval_report.json"


def load_records() -> list[dict]:
    return json.loads(DATA.read_text(encoding="utf-8"))["records"]


def rules_from_rec(rec: dict) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for item in rec.get("custom_rules_recommended") or []:
        if isinstance(item, dict) and item.get("name") and item.get("pattern"):
            out.append((str(item["name"]), str(item["pattern"])))
    return out


def contiguous_gt(rec: dict) -> list[str]:
    if rec.get("contiguous_ground_truth"):
        return list(rec["contiguous_ground_truth"])
    code = rec["code_text"]
    return [f["value"] for f in rec.get("sensitive_findings") or [] if f.get("value") and f["value"] in code]


def eval_arm(records: list[dict], use_custom: bool) -> dict:
    engine = MaskingEngine()
    leak_samples = 0
    rt_ok = 0
    subset = 0
    leak_by_cat: Counter[str] = Counter()
    for rec in records:
        gt = contiguous_gt(rec)
        if not gt:
            engine.clear()
            continue
        subset += 1
        custom = rules_from_rec(rec) if use_custom else None
        res = engine.mask(rec["code_text"], custom_rules=custom)
        if any(v in res.masked for v in gt):
            leak_samples += 1
            leak_by_cat[rec["category"]] += 1
        if engine.unmask(res.masked, res.mapping) == rec["code_text"]:
            rt_ok += 1
        engine.clear()
    n = subset or 1
    return {
        "n_contiguous_gt": subset,
        "leak_samples": leak_samples,
        "leak_rate": round(leak_samples / n, 4),
        "roundtrip_ok": rt_ok,
        "roundtrip_rate": round(rt_ok / n, 4),
        "leak_by_category": dict(leak_by_cat),
    }


def main() -> None:
    records = load_records()
    report = {
        "dataset": "split_pattern_custom_n300",
        "n_records": len(records),
        "builtin_only": eval_arm(records, use_custom=False),
        "with_recommended_custom_rules": eval_arm(records, use_custom=True),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
