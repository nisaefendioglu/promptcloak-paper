#!/usr/bin/env python3
"""PromptCloak masaüstü penceresi — orijinal ile aynı kabuk."""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

import webview

from web_app import HOST, PORT, serve

_HTTPD = None


def _port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        return s.connect_ex((host, port)) == 0


def _ensure_server() -> None:
    global _HTTPD
    if _port_open(HOST, PORT):
        return
    _HTTPD = serve()
    threading.Thread(target=_HTTPD.serve_forever, daemon=True).start()
    for _ in range(80):
        if _port_open(HOST, PORT):
            return
        time.sleep(0.05)


def main() -> None:
    _ensure_server()
    icon = Path(__file__).resolve().parent / "assets" / "icon.png"
    webview.create_window(
        "PromptCloak",
        f"http://{HOST}:{PORT}/",
        width=1100,
        height=760,
        min_size=(820, 600),
        background_color="#0f1110",
        text_select=True,
    )
    try:
        from AppKit import NSApplication, NSImage

        img = NSImage.alloc().initWithContentsOfFile_(str(icon))
        if img:
            NSApplication.sharedApplication().setApplicationIconImage_(img)
    except Exception:
        pass
    webview.start()


if __name__ == "__main__":
    main()
