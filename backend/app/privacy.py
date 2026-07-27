from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any


REDACTED = "[REDACTED]"
REDACTED_HOST_PATH = "<HOST_PATH>"
REDACTED_PROJECT_PATH = "[REDACTED PATH]"
MAX_DISCLOSURE_TEXT_CHARS = 4_000
MAX_EXCERPT_LINES = 3
MAX_EXCERPT_LINE_CHARS = 160

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----.*?"
    r"(?:-----END(?: [A-Z0-9]+)* PRIVATE KEY-----|$)",
    re.IGNORECASE | re.DOTALL,
)
_AUTHORIZATION_RE = re.compile(
    r"([\"']?\bauthorization\b[\"']?\s*[:=]\s*)[^\r\n]+",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"\bbearer\s+[A-Z0-9._~+/=-]+", re.IGNORECASE)
_CREDENTIAL_URL_RE = re.compile(
    r"([A-Z][A-Z0-9+.-]*://)(?:[^/\s:@]+):(?:[^@\s/]+)@",
    re.IGNORECASE,
)
_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"([\"']?\b"
    r"(?:[A-Z0-9_.-]*(?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"auth[_-]?token|client[_-]?secret|password|passwd|pwd|secret|private[_-]?key)"
    r"[A-Z0-9_.-]*)\b[\"']?\s*[:=]\s*)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;}\])]+)",
    re.IGNORECASE | re.MULTILINE,
)
_CONNECTION_SECRET_RE = re.compile(
    r"(\b(?:password|passwd|pwd|user\s*id|uid)\s*=\s*)[^;\s]+",
    re.IGNORECASE,
)
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_GITHUB_TOKEN_RE = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b",
    re.IGNORECASE,
)
_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
_LONG_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9._~+/=-]{32,}(?![A-Za-z0-9])")

_EXTENDED_WINDOWS_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9])\\\\\?\\(?:UNC\\[^\\/\s\"'<>|]+\\[^\\/\s\"'<>|]+|"
    r"[A-Za-z]:\\)[^\r\n\t\"'<>|]*",
    re.IGNORECASE,
)
_UNC_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9])\\\\[^\\/\s\"'<>|]+\\[^\\/\s\"'<>|]+"
    r"(?:[\\/][^\r\n\t\"'<>|]*)?",
    re.IGNORECASE,
)
_WINDOWS_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Za-z]:[\\/])[^\r\n\t\"'<>|]*",
    re.IGNORECASE,
)
_POSIX_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9:])/(?:Users|home|tmp|var/tmp|private/tmp|opt|srv|mnt|media)/"
    r"[^\r\n\t\"'<>|]*",
    re.IGNORECASE,
)

_PATH_KEYS = {
    "affected_path",
    "file",
    "file_path",
    "location_path",
    "lockfilePath",
    "manifestPath",
    "path",
    "paths",
    "relativePath",
    "reviewedPaths",
    "ignoredPaths",
}


def normalize_control_characters(value: Any, *, preserve_lines: bool = True) -> str:
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    allowed = "\n\t" if preserve_lines else ""
    return "".join(
        character
        if ord(character) >= 32 or character in allowed
        else "\uFFFD"
        for character in text
    )


def redact_secret_values(value: Any) -> str:
    text = normalize_control_characters(value)
    text = _PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", text)
    text = _CREDENTIAL_URL_RE.sub(r"\1[REDACTED]@", text)
    text = _AUTHORIZATION_RE.sub(r"\1[REDACTED]", text)
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    text = _CREDENTIAL_ASSIGNMENT_RE.sub(r"\1[REDACTED]", text)
    text = _CONNECTION_SECRET_RE.sub(r"\1[REDACTED]", text)
    text = _AWS_ACCESS_KEY_RE.sub(REDACTED, text)
    text = _GITHUB_TOKEN_RE.sub(REDACTED, text)
    text = _JWT_RE.sub(REDACTED, text)
    return _LONG_TOKEN_RE.sub(_redact_long_token, text)


def replace_absolute_paths(
    value: Any,
    *,
    project_root: Path | str | None = None,
    data_directory: Path | str | None = None,
) -> str:
    text = normalize_control_characters(value)
    replacements = (
        (data_directory, "<GLACIAL_DATA_DIR>"),
        (project_root, "<PROJECT_ROOT>"),
    )
    for raw_path, placeholder in replacements:
        if raw_path is None:
            continue
        candidate = str(raw_path).rstrip("\\/")
        if candidate:
            text = re.sub(re.escape(candidate), placeholder, text, flags=re.IGNORECASE)
            text = re.sub(
                re.escape(candidate.replace("\\", "/")),
                placeholder,
                text,
                flags=re.IGNORECASE,
            )
    text = re.sub(
        r"(?i)(?<![A-Za-z0-9])(?:[A-Za-z]:[\\/])Users[\\/][^\\/\s\"'<>|]+",
        "<USER_PROFILE>",
        text,
    )
    text = re.sub(
        r"(?i)<USER_PROFILE>[\\/]AppData[\\/]Local[\\/]Temp(?:[\\/][^\r\n\t\"'<>|]*)?",
        "<TEMP_DIR>",
        text,
    )
    text = _EXTENDED_WINDOWS_PATH_RE.sub(REDACTED_HOST_PATH, text)
    text = _UNC_PATH_RE.sub(REDACTED_HOST_PATH, text)
    text = _WINDOWS_PATH_RE.sub(REDACTED_HOST_PATH, text)
    return _POSIX_PATH_RE.sub(REDACTED_HOST_PATH, text)


def sanitize_private_text(
    value: Any,
    *,
    limit: int = MAX_DISCLOSURE_TEXT_CHARS,
    preserve_lines: bool = False,
    project_root: Path | str | None = None,
    data_directory: Path | str | None = None,
) -> str:
    redacted = redact_secret_values(value)
    redacted = replace_absolute_paths(
        redacted,
        project_root=project_root,
        data_directory=data_directory,
    )
    if preserve_lines:
        normalized = "\n".join(
            " ".join(line.split()) for line in redacted.splitlines()
        )
    else:
        normalized = " ".join(redacted.split())
    return normalized[: max(0, limit)]


def safe_project_relative_path(
    value: Any,
    *,
    project_root: Path | str | None = None,
    limit: int = 500,
) -> str:
    raw = normalize_control_characters(value, preserve_lines=False).strip()
    if not raw or "\x00" in raw:
        return ""
    normalized = raw.replace("\\", "/")
    if project_root is not None:
        root = str(project_root).replace("\\", "/").rstrip("/")
        if normalized.casefold().startswith(f"{root.casefold()}/"):
            normalized = normalized[len(root) + 1 :]
    if (
        normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
        or normalized.startswith("//")
    ):
        return REDACTED_PROJECT_PATH
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if not parts or ".." in parts:
        return REDACTED_PROJECT_PATH
    sanitized = [
        sanitize_private_text(part, limit=200, preserve_lines=False)
        for part in parts
    ]
    return "/".join(part or REDACTED for part in sanitized)[:limit]


def bounded_text_excerpt(
    value: Any,
    *,
    center_line: int | None = None,
    context_lines: int = 1,
    max_line_chars: int = MAX_EXCERPT_LINE_CHARS,
) -> str:
    text = sanitize_private_text(
        value,
        limit=max(1, MAX_EXCERPT_LINES * max_line_chars * 4),
        preserve_lines=True,
    )
    lines = text.splitlines() or [""]
    if center_line is None:
        first = 0
    else:
        center = max(0, min(len(lines) - 1, center_line))
        first = max(0, center - max(0, context_lines))
    last = min(len(lines), first + max(1, context_lines * 2 + 1))
    return "\n".join(_bounded_line(line, max_line_chars) for line in lines[first:last])


def safe_exception_message(
    error: BaseException | Any,
    *,
    fallback: str = "The operation could not be completed.",
    project_root: Path | str | None = None,
    data_directory: Path | str | None = None,
) -> str:
    value = sanitize_private_text(
        error,
        limit=300,
        project_root=project_root,
        data_directory=data_directory,
    )
    return value or fallback


def sanitize_scan_value(
    value: Any,
    *,
    project_root: Path | str,
    key: str = "",
    depth: int = 0,
) -> Any:
    if depth > 8:
        return None
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if value == value and abs(value) != float("inf") else None
    if isinstance(value, str):
        if key in _PATH_KEYS or key.lower().endswith("path"):
            return safe_project_relative_path(value, project_root=project_root)
        return sanitize_private_text(
            value,
            limit=MAX_DISCLOSURE_TEXT_CHARS,
            preserve_lines=True,
            project_root=project_root,
        )
    if isinstance(value, list):
        return [
            sanitize_scan_value(item, project_root=project_root, key=key, depth=depth + 1)
            for item in value
        ]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            safe_key = sanitize_private_text(raw_key, limit=120)
            if not safe_key:
                continue
            result[safe_key] = sanitize_scan_value(
                raw_value,
                project_root=project_root,
                key=safe_key,
                depth=depth + 1,
            )
        return result
    return sanitize_private_text(value, limit=500, project_root=project_root)


def redacted_fingerprint(value: Any) -> str:
    normalized = normalize_control_characters(value).encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()[:16]


def _redact_long_token(match: re.Match[str]) -> str:
    value = match.group(0)
    if re.fullmatch(r"[0-9a-f]{40,128}", value, re.IGNORECASE):
        return value
    if re.match(r"^(?:sha(?:256|384|512)[:_-]|cf[a-z0-9]*_)", value, re.IGNORECASE):
        return value
    characters = set(value.casefold())
    has_letter = any(character.isalpha() for character in value)
    has_digit = any(character.isdigit() for character in value)
    if len(characters) >= 10 and has_letter and has_digit:
        return REDACTED
    return value


def _bounded_line(value: str, limit: int) -> str:
    clean = normalize_control_characters(value, preserve_lines=False).expandtabs(4)
    if len(clean) <= limit:
        return clean
    return f"{clean[: max(0, limit - 1)]}\u2026"
