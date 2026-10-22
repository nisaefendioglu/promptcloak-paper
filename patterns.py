"""Sensitive-data detection patterns (regex / rule set)."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass


def is_valid_tckn(value: str) -> bool:
    """T.C. kimlik numarası kontrol haneleri (10. ve 11. hane) doğru mu."""
    if len(value) != 11 or not value.isdigit() or value[0] == "0":
        return False
    d = [int(c) for c in value]
    if ((sum(d[0:9:2]) * 7) - sum(d[1:8:2])) % 10 != d[9]:
        return False
    return sum(d[:10]) % 10 == d[10]


_PEM_BODY = re.compile(r"[A-Za-z0-9+/=]{32,}")
_KEY_PREFIX = re.compile(r"(?i)^(?:sk-proj-|sk_live_|sk_test_|sk-|AKIA|AIza|ghp_|xox[baprs]-)")
_CODE_MEMBER = re.compile(r"[A-Za-z_$]+(?:\.[A-Za-z_$]+)+")


def has_pem_body(value: str) -> bool:
    """A real PEM block carries base64 lines; header-only code, regexes and stubs do not."""
    return bool(_PEM_BODY.search(value))


def looks_random(value: str) -> bool:
    """Provider keys are random; all-lowercase word labels after the prefix (sk-proj-json-generic) are not keys."""
    rest = _KEY_PREFIX.sub("", value, count=1)
    return any(c.isdigit() or c.isupper() for c in rest)


def is_literal_secret(value: str) -> bool:
    """Reject code expressions on the right of an unquoted assignment (getElementById(, this.password)."""
    if "(" in value or value.startswith("["):
        return False
    return not _CODE_MEMBER.fullmatch(value)


@dataclass(frozen=True)
class PatternRule:
    type: str
    regex: re.Pattern[str]
    description: str
    validator: Callable[[str], bool] | None = None


# Order matters: more specific / longer spans first.
RULES: list[PatternRule] = [
    PatternRule(
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?"
            r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        ),
        "PEM private key block",
        validator=has_pem_body,
    ),
    PatternRule(
        "api_key",
        re.compile(
            r"(?<![A-Za-z0-9])(?:"
            r"sk-proj-[A-Za-z0-9_-]{16,}|"
            r"sk-[A-Za-z0-9_-]{20,}|"
            r"AKIA[0-9A-Z]{16}|"
            r"AIza[0-9A-Za-z\-_]{20,}|"
            r"ghp_[A-Za-z0-9]{20,}|"
            r"xox[baprs]-[A-Za-z0-9\-]+|"
            r"sk_live_[A-Za-z0-9]{20,}|"
            r"sk_test_[A-Za-z0-9]{20,}"
            r")"
        ),
        "Provider-specific API key",
        validator=looks_random,
    ),
    PatternRule(
        "api_key",
        re.compile(
            r"(?i)(?:api[_-]?key|apikey|access[_-]?key|openai[_-]?key|openaiKey)"
            r"\s*[=:]\s*['\"]([^'\"]{8,})['\"]"
        ),
        "API key assignment (quoted)",
    ),
    PatternRule(
        "api_key",
        re.compile(
            r"(?i)(?:api[_-]?key|apikey|access[_-]?key|openai[_-]?key|openaiKey)"
            r"\s*[=:]\s*([A-Za-z0-9_-]{16,})"
        ),
        "API key assignment (unquoted / YAML)",
    ),
    PatternRule(
        "connection_string",
        re.compile(
            r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|sqlserver)"
            r"://[^\s'\"<>]+"
        ),
        "URI database connection string",
    ),
    PatternRule(
        "connection_string",
        re.compile(
            r"(?i)Server\s*=\s*[^;]+;\s*Database\s*=\s*[^;]+;\s*"
            r"User Id\s*=\s*[^;]+;\s*Password\s*=\s*[^;\s'\"]+;?"
        ),
        "ADO.NET / SQL Server connection string",
    ),
    PatternRule(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        "JWT-like token",
    ),
    PatternRule(
        "password_secret",
        re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/-]{16,}=*)"),
        "Bearer token (Authorization header)",
    ),
    PatternRule(
        "password_secret",
        re.compile(
            r"(?i)(?:password|passwd|pwd|secret|access[_-]?token|auth[_-]?token|"
            r"bearer|client[_-]?secret|keystore)\s*[=:]\s*['\"]([^'\"]{6,})['\"]"
        ),
        "Password / secret assignment (quoted)",
    ),
    PatternRule(
        "password_secret",
        re.compile(
            r"(?i)(?:password|passwd|pwd|secret|access[_-]?token|auth[_-]?token|"
            r"bearer|client[_-]?secret|keystore)\s*[=:]\s*`([^`\s]{6,})`"
        ),
        "Password / secret assignment (Markdown backticks)",
    ),
    PatternRule(
        "password_secret",
        re.compile(
            r"(?i)(?:password|passwd|pwd|secret|access[_-]?token|auth[_-]?token|"
            r"bearer|client[_-]?secret|keystore)\s*[=:]\s*"
            r"(?!password\b|passwd\b|pwd\b|secret\b|true\b|false\b|null\b)"
            r"([^\s'\",;)\]}`]{6,})"
        ),
        "Password / secret assignment (unquoted)",
        validator=is_literal_secret,
    ),
    PatternRule(
        "email",
        re.compile(r"\b(?!git@)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),  # git@host:repo is an SSH remote
        "Email (PII)",
    ),
    # Phone numbers need a country/trunk prefix, digit-group separators or a phone field name;
    # bare 10-digit runs (timestamps, ISBNs, text ids) are not phones.
    PatternRule(
        "phone",
        re.compile(r"(?<![\w+])\+\d{1,3}[ \t-]?\(?\d{3}\)?[ \t-]?\d{3}[ \t-]?\d{2}[ \t-]?\d{2}(?![\w.])"),
        "Phone number with country code (PII)",
    ),
    PatternRule(
        "phone",
        re.compile(r"(?<![\w.])0[ \t-]?\(?[2-58]\d{2}\)?[ \t-]?\d{3}[ \t-]?\d{2}[ \t-]?\d{2}(?![\w.])"),
        "Turkish phone number with trunk prefix 0 (PII)",
    ),
    PatternRule(
        "phone",
        re.compile(r"(?<![\w.])\(?[2-9]\d{2}\)?[ \t-]\d{3}[ \t-]?\d{2}[ \t-]?\d{2}(?![\w.])"),
        "Formatted phone number (PII)",
    ),
    PatternRule(
        "phone",
        re.compile(r"(?<![\w.:/-])\(?\d{3}\)?[ \t-]\d{3}[ \t-]\d{4}(?![\w-]|\.\d)"),
        "Formatted phone number, 3-3-4 groups (PII)",
    ),
    PatternRule(
        "phone",
        re.compile(
            r"(?i)(?:phone|tel|telefon|gsm|mobile|cep|fax)\w*['\"]?\s*[=:]\s*['\"]?"
            r"(\+?\d[\d \t()-]{8,16}\d)(?![\w.])"
        ),
        "Phone number in phone/tel field (PII)",
    ),
    PatternRule(
        "national_id",
        re.compile(
            r"(?i)(?:contact|tc[_-]?kimlik|national[_-]?id|kimlik(?:_?no)?)['\"]?\s*[=:]\s*"
            r"['\"]?(\d{11})['\"]?"
        ),
        "National ID-like value in contact/kimlik field",
    ),
    PatternRule(
        "national_id",
        # Bare 11-digit numbers only count when the TCKN check digits are valid.
        re.compile(r"(?<![\w.])([1-9]\d{10})(?![\w.])"),
        "11-digit number with valid TCKN check digits",
        validator=is_valid_tckn,
    ),
    PatternRule(
        "internal_url",
        re.compile(
            r"(?i)\bhttps?://"
            r"(?:"
            r"localhost|127\.0\.0\.1|"
            r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
            r"192\.168\.\d{1,3}\.\d{1,3}|"
            r"172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|"
            r"[\w.-]+\.internal\.[\w.-]+|"
            r"[\w.-]+\.(?:internal\.example|svc\.cluster\.local|corp\.local|internal|local)"
            r")"
            r"(?::\d+)?"
            r"(?:/[^\s'\"<>]*)?"
        ),
        "Internal / private-network URL",
    ),
]


# Keys only — display labels come from i18n (tr/en).
MASKABLE_TYPES: list[str] = [
    "api_key",
    "password_secret",
    "connection_string",
    "jwt",
    "private_key",
    "email",
    "phone",
    "national_id",
    "internal_url",
]


def find_matches(
    text: str,
    enabled_types: set[str] | None = None,
    custom_rules: list[tuple[str, str]] | None = None,
) -> list[tuple[str, str, int, int]]:
    """Return list of (type, value, start, end), non-overlapping, left-to-right.

    custom_rules: optional list of (name, regex_pattern). Matched as type ``custom:<name>``.
    """
    candidates: list[tuple[int, int, str, str]] = []
    for rule in RULES:
        if enabled_types is not None and rule.type not in enabled_types:
            continue
        for m in rule.regex.finditer(text):
            # Capture group 1 = value when present (assignments)
            if m.lastindex:
                val = m.group(1)
                start = m.start(1)
                end = m.end(1)
            else:
                val = m.group(0)
                start, end = m.start(), m.end()
            if not val or len(val.strip()) < 3:
                continue
            if rule.validator is not None and not rule.validator(val):
                continue
            candidates.append((start, end, rule.type, val))

    for name, pattern in custom_rules or []:
        try:
            regex = re.compile(pattern)
        except re.error:
            continue
        safe = re.sub(r"[^A-Za-z0-9_-]+", "_", name.strip())[:32] or "rule"
        typ = f"custom:{safe}"
        for m in regex.finditer(text):
            if m.lastindex:
                val = m.group(1)
                start, end = m.start(1), m.end(1)
            else:
                val = m.group(0)
                start, end = m.start(), m.end()
            if not val or len(val.strip()) < 2:
                continue
            candidates.append((start, end, typ, val))

    candidates.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    selected: list[tuple[str, str, int, int]] = []
    occupied: list[tuple[int, int]] = []
    for start, end, typ, val in candidates:
        if any(not (end <= a or start >= b) for a, b in occupied):
            continue
        selected.append((typ, val, start, end))
        occupied.append((start, end))
    selected.sort(key=lambda x: x[2])
    return selected
