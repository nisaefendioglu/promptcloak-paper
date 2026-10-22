#!/usr/bin/env python3
"""Maskeleme gecikmesi: N=300 doğal kovalar + uzunluk/yoğunluk taraması."""

from __future__ import annotations

import json
import platform
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

from masking import MaskingEngine

ROOT = Path(__file__).resolve().parent
DATASET = ROOT / "data" / "synthetic_sensitive_data_in_source_code_n300.json"
OUT = ROOT / "out" / "latency_sweep_n300_report.json"

WARMUP = 8
REPEATS = 25
LENGTHS = (200, 2000, 8000, 32000)
DENSITIES = (1, 5, 20)
SECRET = "sk-proj-5Gz8N2TY6nLDDnziKVMF0280"


def _ms(samples: list[float]) -> dict:
    xs = sorted(samples)
    return {
        "n": len(xs),
        "avg": round(statistics.fmean(xs), 3),
        "p50": round(xs[len(xs) // 2], 3),
        "p95": round(xs[max(0, int(len(xs) * 0.95) - 1)], 3),
    }


def _time_mask(text: str, repeats: int = REPEATS) -> list[float]:
    engine = MaskingEngine()
    for _ in range(WARMUP):
        engine.mask(text)
        engine.clear()
    out: list[float] = []
    for _ in range(repeats):
        engine.clear()
        t0 = time.perf_counter()
        engine.mask(text)
        out.append((time.perf_counter() - t0) * 1000)
    return out


def _bucket_len(n: int) -> str:
    if n <= 80:
        return "kısa (≤80)"
    if n <= 150:
        return "orta (81–150)"
    return "uzun (>150)"


def _bucket_den(n: int) -> str:
    if n <= 1:
        return "1 sır"
    if n <= 3:
        return "2–3 sır"
    return "4–5 sır"


def make_text(length: int, n_secrets: int) -> str:
    lines = [f'API_KEY_{i} = "{SECRET}_{i:02d}"' for i in range(n_secrets)]
    body = "\n".join(lines)
    pad_need = length - len(body)
    if pad_need > 0:
        body += "\n# " + ("x" * max(0, pad_need - 3))
    return body


def evaluate() -> dict:
    records = json.loads(DATASET.read_text(encoding="utf-8"))["records"]
    natural: dict[str, list[float]] = defaultdict(list)
    density: dict[str, list[float]] = defaultdict(list)
    for rec in records:
        text = rec["code_text"]
        ms = _time_mask(text, repeats=5)
        natural[_bucket_len(len(text))].extend(ms)
        density[_bucket_den(int(rec.get("sensitive_count") or len(rec["sensitive_findings"])))].extend(ms)

    grid = []
    for length in LENGTHS:
        for den in DENSITIES:
            text = make_text(length, den)
            samples = _time_mask(text)
            grid.append(
                {
                    "target_length": length,
                    "n_secrets": den,
                    "actual_length": len(text),
                    **_ms(samples),
                }
            )

    return {
        "environment": {
            "os": f"{platform.system()} {platform.release()}",
            "machine": platform.machine(),
            "python": sys.version.split()[0],
            "warmup": WARMUP,
            "repeats_per_cell": REPEATS,
            "timer": "time.perf_counter; only MaskingEngine.mask",
        },
        "natural_n300_by_length": {k: _ms(v) for k, v in sorted(natural.items())},
        "natural_n300_by_density": {k: _ms(v) for k, v in sorted(density.items())},
        "constructed_length_x_density": grid,
        "note_tr": (
            "Doğal N=300 metinleri kısa (35–327 karakter). Uzunluk×yoğunluk ızgarası "
            "aynı sentetik anahtar biçimiyle doldurulmuş metindir; tespit skoru değildir."
        ),
    }


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    report = evaluate()
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("Wrote", OUT)


if __name__ == "__main__":
    main()
