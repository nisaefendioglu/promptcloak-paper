#!/usr/bin/env python3
"""Eşzamanlı iki oturum: eşleme tabloları karışmamalı (n=300 çift)."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from masking import MaskingEngine

ROOT = Path(__file__).resolve().parent
N300 = ROOT / "data" / "synthetic_sensitive_data_in_source_code_n300.json"
OUT = ROOT / "out" / "concurrent_sessions_n300_report.json"


def _secrets(rec: dict) -> list[str]:
    vals = []
    for f in rec.get("sensitive_findings") or []:
        v = f.get("value")
        if v and v not in vals:
            vals.append(v)
    return vals


def _run_one(code: str) -> dict:
    eng = MaskingEngine()
    result = eng.mask(code)
    restored = eng.unmask(result.masked, result.mapping)
    return {
        "tag": eng._tag,
        "mapping": dict(result.mapping),
        "values": [f.value for f in result.findings],
        "tokens": list(result.mapping),
        "roundtrip": restored == code,
    }


def main() -> None:
    records = json.loads(N300.read_text(encoding="utf-8"))["records"]
    if len(records) < 300:
        raise SystemExit("N=300 kayıt yok")
    mix = 0
    tag_collide = 0
    rt_fail = 0
    pairs = 0
    # 300 çift: (0,1), (2,3), ... sonra kaydırılmış (0,2) ile 300'e tamamla
    pairs_idx = [(i, (i + 1) % 300) for i in range(300)]
    for i, j in pairs_idx:
        a, b = records[i], records[j]
        with ThreadPoolExecutor(max_workers=2) as pool:
            fa = pool.submit(_run_one, a["code_text"])
            fb = pool.submit(_run_one, b["code_text"])
            ra, rb = fa.result(), fb.result()
        pairs += 1
        if ra["tag"] == rb["tag"]:
            tag_collide += 1
        a_vals = set(ra["values"])
        b_vals = set(rb["values"])
        if a_vals & set(rb["mapping"].values()) and a_vals - b_vals:
            # A'nın tekil sırrı B tablosunda
            mix += 1
        elif b_vals & set(ra["mapping"].values()) and b_vals - a_vals:
            mix += 1
        # Token kesişimi olmamalı (tag farklı)
        if set(ra["tokens"]) & set(rb["tokens"]):
            mix += 1
        if not ra["roundtrip"] or not rb["roundtrip"]:
            rt_fail += 1

    report = {
        "n_pairs": pairs,
        "workers": 2,
        "mapping_mix_count": mix,
        "tag_collision_count": tag_collide,
        "roundtrip_fail_count": rt_fail,
        "isolated": mix == 0 and tag_collide == 0,
        "note_tr": (
            "Her oturum ayrı MaskingEngine (ayrı _tag). İki iş parçacığı aynı anda "
            "maskeler. Karışma: diğer oturumun simgesi veya değeri bu tabloda görünür."
        ),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
