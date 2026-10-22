#!/usr/bin/env python3
"""Hizalı N=300: konum (start/end) F1 ve kısmi sızıntı."""

from __future__ import annotations

import json
from pathlib import Path

from masking import MaskingEngine

ROOT = Path(__file__).resolve().parent
DATASET = ROOT / "data" / "synthetic_sensitive_data_in_source_code_n300.json"
OUT = ROOT / "out" / "position_partial_n300_report.json"


def _prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * p * r / (p + r)) if (p + r) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1": round(f1, 4),
    }


def gt_spans(text: str, values: list[str]) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for v in values:
        if not v:
            continue
        start = 0
        while True:
            i = text.find(v, start)
            if i < 0:
                break
            spans.append((i, i + len(v), v))
            start = i + 1
    return spans


def iou(a: tuple[int, int], b: tuple[int, int]) -> float:
    lo = max(a[0], b[0])
    hi = min(a[1], b[1])
    inter = max(0, hi - lo)
    union = (a[1] - a[0]) + (b[1] - b[0]) - inter
    return inter / union if union else 0.0


def match_spans(
    gold: list[tuple[int, int, str]],
    pred: list[tuple[int, int, str]],
    *,
    exact: bool,
) -> tuple[int, int, int]:
    used_p: set[int] = set()
    tp = 0
    for gs, ge, gv in gold:
        hit = None
        for j, (ps, pe, pv) in enumerate(pred):
            if j in used_p:
                continue
            if exact:
                ok = (gs, ge) == (ps, pe) and gv == pv
            else:
                ok = iou((gs, ge), (ps, pe)) >= 0.5 and (gv == pv or gv in pv or pv in gv)
            if ok:
                hit = j
                break
        if hit is not None:
            used_p.add(hit)
            tp += 1
    return tp, len(pred) - tp, len(gold) - tp


def longest_kept_fragment(value: str, masked: str) -> int:
    if not value:
        return 0
    if value in masked:
        return len(value)
    n = len(value)
    for L in range(n - 1, 0, -1):
        for i in range(n - L + 1):
            if value[i : i + L] in masked:
                return L
    return 0


def evaluate() -> dict:
    records = json.loads(DATASET.read_text(encoding="utf-8"))["records"]
    engine = MaskingEngine()
    exact_tp = exact_fp = exact_fn = 0
    ov_tp = ov_fp = ov_fn = 0
    full_leak = 0
    partial_leak = 0
    n = len(records)
    gold_span_n = 0
    pred_span_n = 0

    for rec in records:
        text = rec["code_text"]
        values = [f["value"] for f in rec["sensitive_findings"] if f.get("value")]
        gold = gt_spans(text, values)
        gold_span_n += len(gold)
        result = engine.mask(text)
        pred = [(f.start, f.end, f.value) for f in result.findings]
        pred_span_n += len(pred)
        etp, efp, efn = match_spans(gold, pred, exact=True)
        otp, ofp, ofn = match_spans(gold, pred, exact=False)
        exact_tp += etp
        exact_fp += efp
        exact_fn += efn
        ov_tp += otp
        ov_fp += ofp
        ov_fn += ofn
        for v in values:
            kept = longest_kept_fragment(v, result.masked)
            if kept == len(v):
                full_leak += 1
            elif kept >= max(4, (len(v) + 1) // 2):
                partial_leak += 1
        engine.clear()

    return {
        "n_samples": n,
        "gold_spans": gold_span_n,
        "pred_spans": pred_span_n,
        "protocol": (
            "GT span = değerin metindeki her geçişi; pred = MaskingEngine start/end. "
            "Tam: (start,end,değer) bire bir. Örtüşme: IoU≥0,5 ve aynı/alt dizgi değer. "
            "Kısmi sızıntı: maskeli metinde GT değerinin en az yarısı (min 4 char) kalır."
        ),
        "exact_span": _prf(exact_tp, exact_fp, exact_fn),
        "overlap_iou_0_5": _prf(ov_tp, ov_fp, ov_fn),
        "leakage": {
            "full_value_still_in_masked": full_leak,
            "partial_half_or_more": partial_leak,
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
