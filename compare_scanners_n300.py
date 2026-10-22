#!/usr/bin/env python3
"""Aynı N=300: PromptCloak / naif regex / Gitleaks / TruffleHog (değer kümesi)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

from masking import MaskingEngine

ROOT = Path(__file__).resolve().parent
N300 = ROOT / "data" / "synthetic_sensitive_data_in_source_code_n300.json"
OUT = ROOT / "out" / "scanner_compare_n300_report.json"


def _gt(rec: dict) -> set[str]:
    return {f["value"] for f in rec.get("sensitive_findings") or [] if f.get("value")}


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


# İki kural: tırnaklı ≥8 karakter; çıplak [A-Za-z0-9_+\-/=]{20,}.
# PromptCloak kataloğu kopyalanmaz.
_NAIVE_QUOTED = re.compile(r"""(?P<q>['"])(?P<v>[^'"\s]{8,})(?P=q)""")
_NAIVE_BARE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+\-/=]{20,}(?![A-Za-z0-9])")


def naive_preds(text: str) -> set[str]:
    found = {m.group("v") for m in _NAIVE_QUOTED.finditer(text)}
    found.update(m.group(0) for m in _NAIVE_BARE.finditer(text))
    return found


def naive_regex(records: list[dict]) -> dict:
    tp = fp = fn = 0
    for rec in records:
        gt = _gt(rec)
        pred = naive_preds(rec["code_text"])
        tp += len(gt & pred)
        fp += len(pred - gt)
        fn += len(gt - pred)
    return _prf(tp, fp, fn)


def promptcloak(records: list[dict]) -> dict:
    engine = MaskingEngine()
    tp = fp = fn = 0
    for rec in records:
        gt = _gt(rec)
        result = engine.mask(rec["code_text"])
        pred = {f.value for f in result.findings}
        tp += len(gt & pred)
        fp += len(pred - gt)
        fn += len(gt - pred)
        engine.clear()
    return _prf(tp, fp, fn)


def _write_files(records: list[dict], root: Path) -> None:
    for rec in records:
        (root / f"{rec['id']}.txt").write_text(rec["code_text"], encoding="utf-8")


def _collect_secrets(blob: str, rec_id: str) -> set[str]:
    """Tarayıcı JSON satırından ham sır adayları."""
    found: set[str] = set()
    try:
        obj = json.loads(blob)
    except json.JSONDecodeError:
        return found
    items = obj if isinstance(obj, list) else [obj]
    for it in items:
        if not isinstance(it, dict):
            continue
        for key in ("Secret", "Raw", "RawV2", "Match", "Fingerprint"):
            v = it.get(key)
            if isinstance(v, str) and v.strip():
                found.add(v.strip())
        # gitleaks
        for key in ("Secret", "Match"):
            v = it.get(key)
            if isinstance(v, str) and v.strip():
                found.add(v.strip())
    return found


def gitleaks(records: list[dict], tmp: Path) -> tuple[dict, str]:
    src = tmp / "gitleaks_src"
    src.mkdir()
    _write_files(records, src)
    report = tmp / "gitleaks.json"
    cmd = [
        "gitleaks",
        "dir",
        str(src),
        "--no-banner",
        "--report-format",
        "json",
        "--report-path",
        str(report),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    raw = report.read_text(encoding="utf-8") if report.exists() else "[]"
    findings = json.loads(raw) if raw.strip() else []
    if not isinstance(findings, list):
        findings = [findings]
    by_file: dict[str, set[str]] = defaultdict(set)
    for it in findings:
        fn = Path(str(it.get("File") or "")).name
        rid = fn.replace(".txt", "")
        for key in ("Secret", "Match"):
            v = it.get(key)
            if isinstance(v, str) and v.strip():
                by_file[rid].add(v.strip())
    tp = fp = fn_ = 0
    for rec in records:
        gt = _gt(rec)
        pred = by_file.get(rec["id"], set())
        # alt dizgi: gitleaks bazen bağlamlı Match döner
        hit = {g for g in gt if any(g in p or p in g for p in pred)}
        extra = {p for p in pred if not any(g in p or p in g for g in gt)}
        tp += len(hit)
        fn_ += len(gt - hit)
        fp += len(extra)
    ver = subprocess.run(["gitleaks", "version"], capture_output=True, text=True)
    return _prf(tp, fp, fn_), (ver.stdout or ver.stderr or "").strip() + f" exit={proc.returncode}"


def trufflehog(records: list[dict], tmp: Path) -> tuple[dict, str]:
    src = tmp / "th_src"
    src.mkdir()
    _write_files(records, src)
    cmd = [
        "trufflehog",
        "filesystem",
        str(src),
        "--json",
        "--no-update",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    by_file: dict[str, set[str]] = defaultdict(set)
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            it = json.loads(line)
        except json.JSONDecodeError:
            continue
        src_meta = it.get("SourceMetadata") or {}
        data = (src_meta.get("Data") or {}).get("Filesystem") or {}
        fn = Path(str(data.get("file") or "")).name
        rid = fn.replace(".txt", "")
        raw = it.get("Raw") or it.get("RawV2") or ""
        if raw:
            by_file[rid].add(str(raw).strip())
    tp = fp = fn_ = 0
    for rec in records:
        gt = _gt(rec)
        pred = by_file.get(rec["id"], set())
        hit = {g for g in gt if any(g in p or p in g for p in pred)}
        extra = {p for p in pred if not any(g in p or p in g for g in gt)}
        tp += len(hit)
        fn_ += len(gt - hit)
        fp += len(extra)
    ver = subprocess.run(["trufflehog", "--version"], capture_output=True, text=True)
    return _prf(tp, fp, fn_), (ver.stdout or ver.stderr or "").strip()


def by_category_promptcloak(records: list[dict]) -> dict:
    """Tablo 6 genişletme: kategori bazında TP/FN (küme kesişimi)."""
    engine = MaskingEngine()
    buckets: dict[str, dict[str, int]] = defaultdict(lambda: {"n": 0, "findings_gt": 0, "tp": 0, "fp": 0, "fn": 0})
    for rec in records:
        cat = rec.get("category") or "?"
        gt = _gt(rec)
        result = engine.mask(rec["code_text"])
        pred = {f.value for f in result.findings}
        b = buckets[cat]
        b["n"] += 1
        b["findings_gt"] += len(gt)
        b["tp"] += len(gt & pred)
        b["fp"] += len(pred - gt)
        b["fn"] += len(gt - pred)
        engine.clear()
    out = {}
    for cat, b in buckets.items():
        prf = _prf(b["tp"], b["fp"], b["fn"])
        out[cat] = {**b, **prf}
    return out


def main() -> None:
    records = json.loads(N300.read_text(encoding="utf-8"))["records"]
    pc = promptcloak(records)
    naive = naive_regex(records)
    cats = by_category_promptcloak(records)
    tmp = Path(tempfile.mkdtemp(prefix="pc_scan_"))
    try:
        gl, gl_ver = gitleaks(records, tmp)
        th, th_ver = trufflehog(records, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    report = {
        "n_samples": len(records),
        "protocol": "değer kümesi kesişimi; tarayıcıda alt dizgi eşleşmesi kabul; naif=tırnaklı≥8 veya çıplak≥20",
        "promptcloak": pc,
        "naive_regex": naive,
        "gitleaks": gl,
        "trufflehog": th,
        "gitleaks_version": gl_ver,
        "trufflehog_version": th_ver,
        "promptcloak_by_category": cats,
        "note_tr": (
            "Aynı 300 etiketli sentetik kayıt. Gitleaks/TruffleHog unmask yapmaz; "
            "karşılaştırma yalnızca tespit. PromptCloak P/R/F1 hizalı settedir."
        ),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("promptcloak", "naive_regex", "gitleaks", "trufflehog", "gitleaks_version", "trufflehog_version")}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
