#!/usr/bin/env python3
"""HF'den makale veri setlerini indir; tuzak setini yerelde üret.

GitHub push koruması sentetik sk_live_ / AKIA dizgilerini sır sandığı için
bu JSON'lar repoda yoktur. DOI: 10.57967/hf/9800
"""

from __future__ import annotations

import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HF = (
    "https://huggingface.co/datasets/nisaefendioglu/"
    "synthetic-sensitive-data-in-source-code-n300/resolve/main/"
)
FILES = [
    ("synthetic_sensitive_data_in_source_code_n300.json", ROOT / "data" / "synthetic_sensitive_data_in_source_code_n300.json"),
    ("extensions/split_pattern_custom_n300.json", ROOT / "data" / "extensions" / "split_pattern_custom_n300.json"),
    ("extensions/clean_code_snippets_n300.json", ROOT / "data" / "extensions" / "clean_code_snippets_n300.json"),
]


def _get(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print("indiriliyor", url)
    with urllib.request.urlopen(url, timeout=60) as resp:
        dest.write_bytes(resp.read())
    print(" ", dest, dest.stat().st_size, "byte")


def main() -> None:
    for rel, dest in FILES:
        _get(HF + rel, dest)
    from generate_hard_negatives_n300 import main as gen_hn

    gen_hn()
    print("hazır")


if __name__ == "__main__":
    main()
