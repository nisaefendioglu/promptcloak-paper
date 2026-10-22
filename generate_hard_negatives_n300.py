#!/usr/bin/env python3
"""Zor negatif N=300: sır değil, sır gibi duran tuzaklar.

Yerleşik katalogun çoğu tuzakta susması beklenir. Az sayıda dokümantasyon
ataması (YOUR_API_KEY, changeme, AWS örnek AKIA) bilinçli zor satırdır.
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "data" / "extensions" / "hard_negatives_n300.json"

# 11 haneli, ilk hane 1–9, TCKN checksum geçmez.
INVALID_TCKN = [
        "11111111111",
    "12345678901",
    "10000000000",
    "23456789012",
    "34567890123",
    "45678901234",
    "56789012345",
    "67890123456",
    "78901234567",
    "89012345678",
]


def rec(i: int, kind: str, language: str, code: str, expect_fp: bool = False) -> dict:
    return {
        "id": f"HNEG-{i:04d}",
        "category": "hard_negative",
        "kind": kind,
        "language": language,
        "code_text": code,
        "has_sensitive_data": False,
        "sensitive_findings": [],
        "expect_fp": expect_fp,
    }


def build() -> list[dict]:
    rows: list[dict] = []
    n = 1

    env_tmpls = [
        ("python", 'token = os.getenv("OPENAI_API_KEY")\n'),
        ("python", 'key = os.environ["STRIPE_SECRET_KEY"]\n'),
        ("python", 'pw = os.environ.get("DB_PASSWORD", "")\n'),
        ("javascript", "const apiKey = process.env.OPENAI_API_KEY;\n"),
        ("javascript", "const secret = process.env.CLIENT_SECRET;\n"),
        ("typescript", "const token = process.env['GITHUB_TOKEN'];\n"),
        ("yaml", "API_KEY: ${{ secrets.OPENAI_API_KEY }}\n"),
        ("yaml", "password: ${{ secrets.DB_PASSWORD }}\n"),
        ("bash", 'echo "key comes from the environment: OPENAI_API_KEY"\n'),
        ("kotlin", 'val key = System.getenv("OPENAI_API_KEY")\n'),
        ("go", 'key := os.Getenv("OPENAI_API_KEY")\n'),
        ("csharp", 'var key = Environment.GetEnvironmentVariable("OPENAI_API_KEY");\n'),
        ("java", 'String key = System.getenv("OPENAI_API_KEY");\n'),
        ("ruby", 'key = ENV.fetch("OPENAI_API_KEY")\n'),
        ("php", '$key = getenv("OPENAI_API_KEY");\n'),
    ]
    for k in range(45):
        lang, code = env_tmpls[k % len(env_tmpls)]
        rows.append(rec(n, "env_ref", lang, f"// trap {k}\n{code}"))
        n += 1

    urls = [
        'fetch("https://example.com/v1/health")\n',
        'const res = await fetch("https://api.github.com/repos/pallets/flask");\n',
        'url = "https://docs.python.org/3/library/os.html"\n',
        'href="https://www.w3.org/TR/html52/"\n',
        'GET https://httpbin.org/get\n',
        'mirror = "https://pypi.org/simple/"\n',
        'cdn = "https://cdn.jsdelivr.net/npm/react/"\n',
        'docs = "https://openapi.github.com/"\n',
        'img = "https://placehold.co/600x400"\n',
        'wiki = "https://en.wikipedia.org/wiki/API"\n',
    ]
    for k in range(45):
        rows.append(rec(n, "public_url", "javascript", f"// public {k}\n{urls[k % len(urls)]}"))
        n += 1

    ph = [
        "sk-proj-your-placeholder-key",
        "sk-your-documentation-placeholder",
        "sk-proj-json-generic-sample",
        "sk-replace-this-placeholder",
        "sk-proj-dummy-placeholder-val",
    ]
    for k in range(45):
        val = ph[k % len(ph)]
        rows.append(
            rec(
                n,
                "placeholder_nonrandom",
                "text",
                f"# documentation only\n# example prefix, not a live key: {val}\n",
            )
        )
        n += 1

    comments = [
        "# TODO: put your API key here\nprint('ok')\n",
        "// Insert Stripe secret in the dashboard, do not commit it.\n",
        "/* password goes in the secrets manager */\n",
        "# jwt: paste token after login\n",
        "<!-- add database password in CI variables -->\n",
        "# PEM: drop the private key file on the server, not here\n",
        "# connection string: see .env.example\n",
        "' Use your own OpenAI key; this file has none'\n",
    ]
    for k in range(40):
        rows.append(rec(n, "comment_docs", "text", comments[k % len(comments)]))
        n += 1

    for k in range(30):
        tid = INVALID_TCKN[k % len(INVALID_TCKN)]
        # checksum-invalid; field name avoided so national_id assignment rule does not fire
        rows.append(rec(n, "invalid_tckn", "text", f"order_ref = {tid}\n"))
        n += 1

    phones = [
        "ts = 1712345678\n",
        "isbn = 9780141036144\n",
        "build_id = 2026102213\n",
        "count = 5551234567\n",
        "unix = 1690000000\n",
        "sku = 2125551234\n",
    ]
    for k in range(30):
        rows.append(rec(n, "not_phone", "python", phones[k % len(phones)]))
        n += 1

    for k in range(20):
        rows.append(
            rec(
                n,
                "pem_stub",
                "text",
                "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
            )
        )
        n += 1

    flags = [
        "DEBUG=1\nFEATURE_X=enabled\n",
        "password = false\n",
        "password = null\n",
        "secret = true\n",
        "NODE_ENV=development\nPORT=3000\n",
    ]
    for k in range(25):
        rows.append(rec(n, "config_flag", "env", flags[k % len(flags)]))
        n += 1

    # Bilinçli zor satırlar — katalog bunları sır sanabilir
    hard = [
        'api_key = "YOUR_API_KEY"\n',
        'password = "changeme"\n',
        "AKIAIOSFODNN7EXAMPLE\n",
        'openai_key = "xxxxxxxxxxxxxxxx"\n',
        'secret = "TODOSECRET"\n',
    ]
    for k in range(20):
        rows.append(rec(n, "docs_literal", "python", hard[k % len(hard)], expect_fp=True))
        n += 1

    if len(rows) != 300:
        raise SystemExit(f"n={len(rows)} expected 300")
    return rows


def main() -> None:
    records = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "name": "hard_negatives_n300",
        "description": (
            "Sır içermeyen, sır benzeri tuzaklar. expect_fp=true satırlar "
            "dokümantasyon ataması / resmi örnek anahtardır."
        ),
        "n": 300,
        "seed_note": "şablon döngüsü; rastgele sır üretilmedi",
        "records": records,
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print("yazildi", OUT, "n", len(records))


if __name__ == "__main__":
    main()
