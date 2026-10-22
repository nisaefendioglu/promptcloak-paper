#!/usr/bin/env python3
"""Çok turlu yerel oturum: 300 sohbet × 3 tur; tablo turlar boyunca kalır, sızıntı 0.

Canlı model yok. Tur 1 kod, tur 2 takip (önceki sır geçebilir), tur 3 kod yeniden.
Aynı değer aynı simgeyi almalı.
"""

from __future__ import annotations

import json
from pathlib import Path

from masking import MaskingEngine

ROOT = Path(__file__).resolve().parent
N300 = ROOT / "data" / "synthetic_sensitive_data_in_source_code_n300.json"
OUT = ROOT / "out" / "multi_turn_n300_report.json"

N_TURNS = 3
FOLLOW = (
    "Add error handling and a timeout to the previous snippet. "
    "The credential from turn 1 is '{secret}' and must stay masked."
)


def _values(rec: dict) -> list[str]:
    vals: list[str] = []
    for f in rec.get("sensitive_findings") or []:
        v = f.get("value")
        if v and v not in vals:
            vals.append(v)
    return vals


def _leaked(masked: str, values: list[str]) -> bool:
    return any(v in masked for v in values)


def main() -> None:
    records = json.loads(N300.read_text(encoding="utf-8"))["records"]
    if len(records) < 300:
        raise SystemExit("N=300 kayıt yok")

    leak_sessions = 0
    leak_turns = 0
    token_mismatch = 0
    known_miss = 0
    rt_fail = 0
    n = 0

    for rec in records[:300]:
        code = rec["code_text"]
        values = _values(rec)
        if not values:
            raise SystemExit(f"sır yok: {rec.get('id')}")
        n += 1
        eng = MaskingEngine()
        session_leak = False

        r1 = eng.mask(code)
        tokens1 = {v: t for t, v in eng.mapping.items()}
        if _leaked(r1.masked, values):
            leak_turns += 1
            session_leak = True
        if eng.unmask(r1.masked, eng.mapping) != code:
            rt_fail += 1

        t2 = FOLLOW.format(secret=values[0])
        r2 = eng.mask(t2)
        if _leaked(r2.masked, values):
            leak_turns += 1
            session_leak = True
        expect = tokens1.get(values[0])
        if expect and expect not in r2.masked:
            known_miss += 1
        if eng.unmask(r2.masked, eng.mapping) != t2:
            rt_fail += 1

        r3 = eng.mask(code)
        if _leaked(r3.masked, values):
            leak_turns += 1
            session_leak = True
        for v in values:
            if eng._token_for_value.get(v) != tokens1.get(v):
                token_mismatch += 1
                break
        if eng.unmask(r3.masked, eng.mapping) != code:
            rt_fail += 1

        if session_leak:
            leak_sessions += 1

    report = {
        "n_sessions": n,
        "n_turns": N_TURNS,
        "total_user_turns": n * N_TURNS,
        "leak_sessions": leak_sessions,
        "leak_turns": leak_turns,
        "token_mismatch_sessions": token_mismatch,
        "known_value_miss_turn2": known_miss,
        "roundtrip_fail": rt_fail,
        "clean_sessions": n - leak_sessions,
        "note_tr": (
            "Aynı MaskingEngine, turlar arasında clear yok. Canlı model yok. "
            "Tur 1 ve 3 kod; tur 2 takip + 1. sır. Ölçülen: giden metinde düz sır, "
            "aynı değer→aynı simge, yerel unmask."
        ),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
