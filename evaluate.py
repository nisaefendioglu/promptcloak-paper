#!/usr/bin/env python3
"""Kural hizalı N=300: P/R/F1, sızıntı, round-trip, gecikme."""

from __future__ import annotations

import json
import time
from collections import defaultdict
from pathlib import Path

from masking import MaskingEngine

ROOT = Path(__file__).resolve().parent
DATASET = ROOT / "data" / "synthetic_sensitive_data_in_source_code_n300.json"
OUT = ROOT / "out" / "eval_report.json"


def load_records() -> list[dict]:
    return json.loads(DATASET.read_text(encoding="utf-8"))["records"]


def evaluate() -> dict:
    records = load_records()
    engine = MaskingEngine()
    tp = fp = fn = 0
    latencies_ms: list[float] = []
    unmask_ok = 0
    leak = 0
    cat_tp_fp_fn: dict[str, dict[str, int]] = defaultdict(lambda: {"n": 0, "findings_gt": 0, "tp": 0, "fp": 0, "fn": 0})

    for rec in records:
        code = rec["code_text"]
        gt = {f["value"] for f in rec["sensitive_findings"]}
        t0 = time.perf_counter()
        result = engine.mask(code)
        latencies_ms.append((time.perf_counter() - t0) * 1000)
        pred = {f.value for f in result.findings}
        tp += len(gt & pred)
        fp += len(pred - gt)
        fn += len(gt - pred)
        b = cat_tp_fp_fn[rec["category"]]
        b["n"] += 1
        b["findings_gt"] += len(gt)
        b["tp"] += len(gt & pred)
        b["fp"] += len(pred - gt)
        b["fn"] += len(gt - pred)
        if any(v in result.masked for v in gt):
            leak += 1
        if engine.unmask(result.masked, result.mapping) == code:
            unmask_ok += 1
        engine.clear()

    def prf(t, f_p, f_n):
        p = t / (t + f_p) if (t + f_p) else 0.0
        r = t / (t + f_n) if (t + f_n) else 0.0
        f1 = (2 * p * r / (p + r)) if (p + r) else 0.0
        return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4)}

    cats = {}
    for cat, b in cat_tp_fp_fn.items():
        cats[cat] = {**b, **prf(b["tp"], b["fp"], b["fn"])}

    n = len(records)
    lat = sorted(latencies_ms)
    return {
        "n_samples": n,
        "protocol": "değer kümesi kesişimi (mikro); konum F1 iddia edilmez",
        "finding_level": {"tp": tp, "fp": fp, "fn": fn, **prf(tp, fp, fn)},
        "by_category": cats,
        "leakage": {"samples_with_gt_still_in_masked": leak, "leak_rate": round(leak / n, 4)},
        "unmask_roundtrip_exact": {"ok": unmask_ok, "rate": round(unmask_ok / n, 4)},
        "latency_ms": {
            "avg": round(sum(lat) / len(lat), 3),
            "p50": round(lat[len(lat) // 2], 3),
            "p95": round(lat[int(len(lat) * 0.95)], 3),
        },
    }


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    report = evaluate()
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("Wrote", OUT)


if __name__ == "__main__":
    main()
