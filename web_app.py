#!/usr/bin/env python3
"""Yerel HTTP: statik arayüz + mask / unmask."""

from __future__ import annotations

import json
import mimetypes
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from masking import MaskingEngine
from patterns import MASKABLE_TYPES

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
ASSETS = ROOT / "assets"
HOST = "127.0.0.1"
PORT = 8766
SESSIONS: dict[str, dict] = {}

TYPE_EN = {
    "api_key": "API key",
    "password_secret": "password / secret",
    "connection_string": "connection string",
    "internal_url": "internal URL",
    "email": "email",
    "phone": "phone",
    "jwt": "JWT",
    "private_key": "private key",
    "national_id": "national ID",
}
TYPE_TR = {
    "api_key": "API anahtarı",
    "password_secret": "parola / sır",
    "connection_string": "bağlantı dizesi",
    "internal_url": "iç URL",
    "email": "e-posta",
    "phone": "telefon",
    "jwt": "JWT",
    "private_key": "özel anahtar",
    "national_id": "kimlik no",
}


def _parse_custom_rules(data: dict) -> list[tuple[str, str]]:
    raw = data.get("custom_rules")
    if not isinstance(raw, list):
        return []
    out: list[tuple[str, str]] = []
    for item in raw:
        if isinstance(item, dict):
            name = (item.get("name") or "").strip()
            pat = (item.get("pattern") or "").strip()
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            name, pat = str(item[0]).strip(), str(item[1]).strip()
        else:
            continue
        if name and pat:
            out.append((name, pat))
        if len(out) >= 32:
            break
    return out


def _findings_public(findings) -> list[dict]:
    rows = []
    for f in findings:
        preview = f.value[:8] + "…" if len(f.value) > 10 else f.value
        typ_tr = "Özel kural" if f.type.startswith("custom:") else TYPE_TR.get(f.type, f.type)
        typ_en = "Custom rule" if f.type.startswith("custom:") else TYPE_EN.get(f.type, f.type)
        rows.append(
            {
                "type": f.type,
                "type_tr": typ_tr,
                "type_en": typ_en,
                "token": f.token,
                "preview": preview,
            }
        )
    return rows


def _json(handler: BaseHTTPRequestHandler, code: int, obj: dict) -> None:
    body = json.dumps(obj, ensure_ascii=False).encode()
    handler._send(code, body, "application/json; charset=utf-8")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        print(f"[promptcloak] {args[0]}")

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = unquote(urlparse(self.path).path)
        if path in ("/", "/index.html"):
            self._send(200, (WEB / "index.html").read_bytes(), "text/html; charset=utf-8")
            return
        if path.startswith("/assets/"):
            f = ASSETS / Path(path).name
            if f.is_file() and f.resolve().parent == ASSETS.resolve():
                ctype = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
                self._send(200, f.read_bytes(), ctype)
                return
        self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        n = int(self.headers.get("Content-Length", "0"))
        try:
            data = json.loads(self.rfile.read(n).decode() or "{}")
        except json.JSONDecodeError:
            _json(self, 400, {"error": "JSON bekleniyor"})
            return
        if path == "/api/mask":
            self._mask(data)
        elif path == "/api/unmask":
            self._unmask(data)
        else:
            self._send(404, b"not found", "text/plain")

    def _mask(self, data: dict) -> None:
        message = data.get("message") or ""
        if not str(message).strip():
            _json(self, 400, {"error": "Metin boş"})
            return
        custom_rules = _parse_custom_rules(data)
        enabled = data.get("enabled_types")
        if isinstance(enabled, list):
            types = {str(x) for x in enabled if str(x) in MASKABLE_TYPES}
        else:
            types = set(MASKABLE_TYPES)
        sid = uuid.uuid4().hex
        engine = MaskingEngine()
        res = engine.mask(message, enabled_types=types or None, custom_rules=custom_rules or None)
        findings = _findings_public(res.findings)
        leftover = [f for f in res.findings if f.value and f.value in res.masked]
        SESSIONS[sid] = {"mapping": dict(res.mapping)}
        _json(
            self,
            200,
            {
                "session_id": sid,
                "masked": res.masked,
                "findings": findings,
                "outbound_safe": not leftover,
                "residual_secrets": _findings_public(leftover),
            },
        )

    def _unmask(self, data: dict) -> None:
        sid = data.get("session_id") or ""
        text = data.get("text") or ""
        session = SESSIONS.get(sid)
        if not session:
            _json(self, 400, {"error": "Önce maskele."})
            return
        if not str(text).strip():
            _json(self, 400, {"error": "Çözülecek metin boş"})
            return
        restored = MaskingEngine().unmask(str(text), session.get("mapping") or {})
        _json(self, 200, {"restored": restored})


def serve() -> ThreadingHTTPServer:
    return ThreadingHTTPServer((HOST, PORT), Handler)


def main() -> None:
    httpd = serve()
    print(f"http://{HOST}:{PORT}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
