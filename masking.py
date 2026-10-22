"""Local masking and reverse-masking engine."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field

from patterns import find_matches

TYPE_PREFIX = {
    "api_key": "KEY",
    "password_secret": "PASS",
    "connection_string": "CONN",
    "internal_url": "URL",
    "email": "EMAIL",
    "phone": "PHONE",
    "jwt": "JWT",
    "private_key": "PKEY",
    "national_id": "NID",
}

_ASSIGN_RE = re.compile(r"^(\s*)([A-Za-z_]\w*)\s*=\s*(.+)$")
_GENERIC_PLACEHOLDER_RE = re.compile(
    r"\[(?:YOUR_|LOCAL_MASKED_)[^\]]+\]",
    re.IGNORECASE,
)
_TOKEN_RE = re.compile(r"\[LOCAL_MASKED_[^\]]+\]")


@dataclass
class Finding:
    type: str
    value: str
    start: int
    end: int
    token: str


@dataclass
class MaskResult:
    original: str
    masked: str
    findings: list[Finding] = field(default_factory=list)
    mapping: dict[str, str] = field(default_factory=dict)  # token -> original


class MaskingEngine:
    """In-memory mapping table; never persists secrets to disk."""

    def __init__(self, known: dict[str, str] | None = None) -> None:
        """known: aynı oturumun önceki turlarından token -> değer; aynı değer aynı simgeyi alır."""
        self._counter = 0
        # Engine-unique tag: tokens from different sessions never collide when
        # mappings are merged (history resolve). 8 hex = 32 bits.
        self._tag = secrets.token_hex(4)
        self.mapping: dict[str, str] = dict(known or {})
        # Oturum içinde tutarlı simge: değer -> token (oturumlar arasında tag farklı).
        self._token_for_value: dict[str, str] = {v: t for t, v in self.mapping.items()}

    def _next_token(self, typ: str) -> str:
        self._counter += 1
        if typ.startswith("custom:"):
            prefix = "CUSTOM"
        else:
            prefix = TYPE_PREFIX.get(typ, "MASK")
        return f"[LOCAL_MASKED_{prefix}_{self._tag}_{self._counter}]"

    def mask(
        self,
        text: str,
        enabled_types: set[str] | None = None,
        custom_rules: list[tuple[str, str]] | None = None,
    ) -> MaskResult:
        matches = find_matches(
            text,
            enabled_types=enabled_types,
            custom_rules=custom_rules,
        )
        masked = text
        findings: list[Finding] = []
        local_map: dict[str, str] = {}
        for typ, value, start, end in reversed(matches):
            token = self._token_for_value.get(value)
            if token is None:
                token = self._next_token(typ)
                self._token_for_value[value] = token
            masked = masked[:start] + token + masked[end:]
            self.mapping[token] = value
            local_map[token] = value
            findings.append(Finding(typ, value, start, end, token))

        # Desenin yakalamadığı diğer geçişler (ör. pw="…" ya da önceki turun sırrı) da aynı simgeyi alır.
        masked = self._mask_known_values(masked, local_map)
        if not local_map:
            return MaskResult(original=text, masked=text, findings=[], mapping={})

        findings.reverse()
        return MaskResult(original=text, masked=masked, findings=findings, mapping=local_map)

    def _mask_known_values(self, masked: str, local_map: dict[str, str]) -> str:
        values = sorted((v for v in self._token_for_value if v in masked), key=len, reverse=True)
        if not values:
            return masked
        value_re = re.compile(
            r"(?<![A-Za-z0-9_])(?:" + "|".join(re.escape(v) for v in values) + r")(?![A-Za-z0-9_])"
        )
        parts = _TOKEN_RE.split(masked)
        tokens = _TOKEN_RE.findall(masked)
        out: list[str] = []
        for i, part in enumerate(parts):
            def _sub(m: re.Match[str]) -> str:
                token = self._token_for_value[m.group(0)]
                local_map[token] = m.group(0)
                return token

            out.append(value_re.sub(_sub, part))
            if i < len(tokens):
                out.append(tokens[i])
        return "".join(out)

    def unmask(self, text: str, mapping: dict[str, str] | None = None) -> str:
        table = mapping if mapping is not None else self.mapping
        out = text
        for token in sorted(table.keys(), key=len, reverse=True):
            out = out.replace(token, table[token])
        return out

    def clear(self) -> None:
        self.mapping.clear()
        self._token_for_value.clear()
        self._counter = 0
        self._tag = secrets.token_hex(4)


def _quote_secret_for_line(original_line: str, secret: str) -> str:
    if "'''" in original_line or '"""' in original_line:
        return repr(secret)
    if "'" in original_line and '"' not in original_line:
        esc = secret.replace("\\", "\\\\").replace("'", "\\'")
        return f"'{esc}'"
    esc = secret.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{esc}"'


def _patch_assignment_line(original_line: str, reply_line: str, secret: str) -> str:
    m_orig = _ASSIGN_RE.match(original_line)
    m_reply = _ASSIGN_RE.match(reply_line)
    if not m_orig or not m_reply:
        return reply_line
    if m_orig.group(2) != m_reply.group(2):
        return reply_line
    val = _quote_secret_for_line(original_line, secret)
    return f"{m_reply.group(1)}{m_reply.group(2)} = {val}"


def _line_index_with_token(text: str, token: str) -> int | None:
    for i, line in enumerate(text.splitlines()):
        if token in line:
            return i
    return None


def unmask_with_fallback(
    reply: str,
    mapping: dict[str, str],
    *,
    original: str | None = None,
    masked: str | None = None,
) -> tuple[str, list[str]]:
    """Simge yanıtta yoksa mapping'den sırrı satır/bağlam ile geri yazar (yalnızca yerel)."""
    out = MaskingEngine().unmask(reply, mapping)
    if not mapping or not original or not masked:
        return out, []

    lost = [t for t in mapping if t not in reply]
    if not lost:
        return out, []

    orig_lines = original.splitlines()
    masked_lines = masked.splitlines()
    reply_lines = out.splitlines()
    patched: list[str] = []

    for token in lost:
        secret = mapping[token]
        idx = _line_index_with_token(masked, token)
        if idx is None or idx >= len(orig_lines):
            continue
        orig_line = orig_lines[idx]
        m_assign = _ASSIGN_RE.match(orig_line)

        if m_assign:
            var = m_assign.group(2)
            for j, rline in enumerate(reply_lines):
                m_r = _ASSIGN_RE.match(rline)
                if m_r and m_r.group(2) == var:
                    reply_lines[j] = _patch_assignment_line(orig_line, rline, secret)
                    patched.append(token)
                    break
            if token in patched:
                continue

        if idx < len(reply_lines):
            rline = reply_lines[idx]
            if secret not in rline:
                if _GENERIC_PLACEHOLDER_RE.search(rline):
                    reply_lines[idx] = _GENERIC_PLACEHOLDER_RE.sub(
                        _quote_secret_for_line(orig_line, secret),
                        rline,
                        count=1,
                    )
                    patched.append(token)
                elif len(reply_lines) == len(orig_lines):
                    reply_lines[idx] = orig_line
                    patched.append(token)

    return "\n".join(reply_lines), patched
