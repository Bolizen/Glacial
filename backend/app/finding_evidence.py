from __future__ import annotations

import re
from typing import Any


SUSPICIOUS_TEXT_CONTEXT_LINES = 1
SUSPICIOUS_TEXT_MAX_LINE_CHARS = 160
SUSPICIOUS_TEXT_MAX_EXCERPT_CHARS = (
    (SUSPICIOUS_TEXT_CONTEXT_LINES * 2 + 1) * SUSPICIOUS_TEXT_MAX_LINE_CHARS
    + SUSPICIOUS_TEXT_CONTEXT_LINES * 2
)
SUSPICIOUS_TEXT_MAX_PATTERN_CHARS = 120

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----.*?"
    r"(?:-----END(?: [A-Z0-9]+)* PRIVATE KEY-----|$)",
    re.IGNORECASE | re.DOTALL,
)
_CREDENTIAL_URL_RE = re.compile(
    r"([A-Z][A-Z0-9+.-]*://)([^/\s:@]+):([^@\s/]+)@",
    re.IGNORECASE,
)
_AUTHORIZATION_RE = re.compile(
    r"([\"']?\bauthorization\b[\"']?\s*[:=]\s*)[^\r\n]+",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(
    r"\bbearer\s+[A-Z0-9._~+/=-]+",
    re.IGNORECASE,
)
_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"([\"']?\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"password|passwd|secret|token)\b[\"']?\s*[:=]\s*)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)",
    re.IGNORECASE,
)
_KNOWN_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_LONG_TOKEN_RE = re.compile(r"[A-Z0-9._~+/=-]{32,}", re.IGNORECASE)


def build_suspicious_text_evidence(text: str, pattern: str) -> dict[str, Any] | None:
    if not isinstance(text, str) or not isinstance(pattern, str):
        return None
    if not pattern or len(pattern) > SUSPICIOUS_TEXT_MAX_PATTERN_CHARS:
        return None

    lower_text = text.lower()
    needle = pattern.lower()
    first_match = lower_text.find(needle)
    if first_match < 0:
        return None

    match_count = lower_text.count(needle)
    line_index = text.count("\n", 0, first_match)
    line_start = text.rfind("\n", 0, first_match) + 1
    match_column = first_match - line_start
    lines = text.split("\n")
    if len(lines) > 1 and not lines[-1] and text.endswith("\n"):
        lines.pop()
    excerpt_lines = []
    first_line_index = max(0, line_index - SUSPICIOUS_TEXT_CONTEXT_LINES)
    last_line_index = min(len(lines) - 1, line_index + SUSPICIOUS_TEXT_CONTEXT_LINES)
    for current_index in range(first_line_index, last_line_index + 1):
        line = lines[current_index].removesuffix("\r")
        center = match_column + len(pattern) // 2 if current_index == line_index else None
        excerpt_lines.append(_bounded_line(line, center=center))

    evidence = {
        "line": line_index + 1,
        "matchCount": match_count,
        "pattern": pattern,
        "excerpt": _redact_excerpt("\n".join(excerpt_lines)),
        "additionalMatchesOmitted": match_count > 1,
    }
    return normalize_suspicious_text_evidence(evidence)


def normalize_suspicious_text_evidence(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None

    line = value.get("line")
    match_count = value.get("matchCount")
    pattern = value.get("pattern")
    excerpt = value.get("excerpt")
    omitted = value.get("additionalMatchesOmitted")
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        return None
    if isinstance(match_count, bool) or not isinstance(match_count, int) or match_count < 1:
        return None
    if not isinstance(pattern, str) or not pattern or len(pattern) > SUSPICIOUS_TEXT_MAX_PATTERN_CHARS:
        return None
    if any(ord(character) < 32 for character in pattern):
        return None
    if not isinstance(excerpt, str) or not excerpt or len(excerpt) > SUSPICIOUS_TEXT_MAX_EXCERPT_CHARS:
        return None
    if not isinstance(omitted, bool) or omitted != (match_count > 1):
        return None

    normalized_excerpt = excerpt.replace("\r\n", "\n").replace("\r", "\n")
    excerpt_lines = normalized_excerpt.split("\n")
    if len(excerpt_lines) > SUSPICIOUS_TEXT_CONTEXT_LINES * 2 + 1:
        return None
    if any(len(item) > SUSPICIOUS_TEXT_MAX_LINE_CHARS for item in excerpt_lines):
        return None
    if any(
        ord(character) < 32 and character not in "\n\t"
        for character in normalized_excerpt
    ):
        return None

    sanitized_excerpt = _redact_excerpt(normalized_excerpt)
    if not sanitized_excerpt or len(sanitized_excerpt) > SUSPICIOUS_TEXT_MAX_EXCERPT_CHARS:
        return None
    return {
        "line": line,
        "matchCount": match_count,
        "pattern": pattern,
        "excerpt": sanitized_excerpt,
        "additionalMatchesOmitted": omitted,
    }


def redact_sensitive_text(value: Any, limit: int) -> str:
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    bounded = "".join(
        character if character in "\n\t" or ord(character) >= 32 else "�"
        for character in text[:max(0, limit)]
    )
    return _redact_excerpt(bounded)


def _bounded_line(line: str, *, center: int | None) -> str:
    clean = "".join(
        character if character == "\t" or ord(character) >= 32 else "�"
        for character in line
    ).expandtabs(4)
    if len(clean) <= SUSPICIOUS_TEXT_MAX_LINE_CHARS:
        return clean

    content_chars = SUSPICIOUS_TEXT_MAX_LINE_CHARS - 2
    if center is None:
        start = 0
    else:
        start = max(0, min(len(clean) - content_chars, center - content_chars // 2))
    end = min(len(clean), start + content_chars)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(clean) else ""
    return f"{prefix}{clean[start:end]}{suffix}"


def _redact_excerpt(excerpt: str) -> str:
    redacted = _PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", excerpt)
    redacted = _CREDENTIAL_URL_RE.sub(r"\1[REDACTED]@", redacted)
    redacted = _AUTHORIZATION_RE.sub(r"\1[REDACTED]", redacted)
    redacted = _BEARER_RE.sub("Bearer [REDACTED]", redacted)
    redacted = _CREDENTIAL_ASSIGNMENT_RE.sub(r"\1[REDACTED]", redacted)
    redacted = _KNOWN_ACCESS_KEY_RE.sub("[REDACTED]", redacted)
    return _LONG_TOKEN_RE.sub(_redact_long_token, redacted)


def _redact_long_token(match: re.Match[str]) -> str:
    value = match.group(0)
    characters = set(value.lower())
    has_letter = any(character.isalpha() for character in value)
    has_digit = any(character.isdigit() for character in value)
    has_token_symbol = any(character in "._~+/=-" for character in value)
    if len(characters) >= 10 and has_letter and (has_digit or has_token_symbol):
        return "[REDACTED]"
    return value
