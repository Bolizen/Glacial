from __future__ import annotations

import base64
import binascii
import hashlib
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit


REDACTED = "[REDACTED]"
REDACTED_HOST_PATH = "<HOST_PATH>"
REDACTED_PROJECT_PATH = "[REDACTED PATH]"
MAX_DISCLOSURE_TEXT_CHARS = 4_000
MAX_EXCERPT_LINES = 3
MAX_EXCERPT_LINE_CHARS = 160
MAX_DEPENDENCY_LOCATOR_DECODE_ROUNDS = 8

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
_HEX_SECRET_RE = re.compile(
    r"(?<![A-Za-z0-9])[0-9a-f]{40,128}(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_LONG_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9._~+/=-]{32,}(?![A-Za-z0-9])")
_STRUCTURED_FINGERPRINT_RE = re.compile(
    r"^(?:cf1_|cfdb2_|cpex1_|cpda1_|cpfr1_|cpbf1_|cpcov1_|cpr1_)[0-9a-f]{64}$"
)
_STRUCTURED_FINGERPRINT_KEYS = {
    "analysisfingerprint",
    "baselinefindingsfingerprint",
    "coveragefingerprint",
    "dependencyanalysisfingerprint",
    "dependencyapprovalfingerprint",
    "evidencefingerprint",
    "expectationsfingerprint",
    "findingreviewsfingerprint",
    "fingerprint",
}
_STRUCTURED_VCS_SELECTORS = {
    "vcsrequestedrevision": {"branch", "ref", "rev", "tag"},
    "vcslockedrevision": {"reference"},
    "vcsresolvedrevision": {"resolved"},
}
_DEPENDENCY_LOCATOR_KEYS = {
    "lockedversion",
    "requested",
    "requestedspecification",
    "resolvedversion",
}
_ENCODED_DEPENDENCY_SCHEME_RE = re.compile(
    r"^(?:(?:git|hg|svn|bzr)(?:\+|%(?:25)*2b))?"
    r"(?:https?|ssh|git|svn|hg|bzr)%(?:25)*3a"
    r"%(?:25)*2f%(?:25)*2f",
    re.IGNORECASE,
)
_SCP_DEPENDENCY_LOCATOR_RE = re.compile(
    r"^(?:(?P<user>[A-Za-z0-9][A-Za-z0-9._+-]{0,63})@)?"
    r"(?P<host>[A-Za-z0-9][A-Za-z0-9.-]{0,252})"
    r":(?P<path>[^\s\\/:]+/[^\s\\:]+)$"
)

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
    text = _HEX_SECRET_RE.sub(REDACTED, text)
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


def _normalized_dependency_locator(value: Any) -> tuple[str, bool]:
    text = normalize_control_characters(value, preserve_lines=False).strip()
    # Percent-decoding cannot expand the input. Each pass must converge within this
    # fixed work bound; otherwise callers treat the still-ambiguous value as private.
    for _ in range(MAX_DEPENDENCY_LOCATOR_DECODE_ROUNDS):
        if re.search(r"%(?![0-9A-Fa-f]{2})", text):
            return text, False
        decoded = unquote(text)
        if decoded == text:
            return text, True
        text = decoded
    if re.search(r"%(?![0-9A-Fa-f]{2})", text):
        return text, False
    return text, unquote(text) == text


def _without_dependency_selector(value: str) -> str:
    locator = re.split(r"[?#]", value, maxsplit=1)[0]
    return locator.rsplit("@", 1)[0] if "@" in locator else locator


def _scp_dependency_locator(value: str) -> tuple[str, str] | None:
    match = _SCP_DEPENDENCY_LOCATOR_RE.fullmatch(value)
    if not match:
        return None
    user = match.group("user")
    host = match.group("host")
    labels = host.split(".")
    if (
        ("." not in host and user is None)
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            for label in labels
        )
    ):
        return None
    return host, match.group("path")


def _looks_like_dependency_locator(value: Any) -> bool:
    text, normalized = _normalized_dependency_locator(value)
    if not text or any(character.isspace() for character in text):
        return False
    if not normalized:
        return bool(_ENCODED_DEPENDENCY_SCHEME_RE.match(text))
    if "://" in text:
        return True
    if re.match(r"^(?:git\+|hg\+|svn\+|bzr\+)?(?:https?|ssh|git|svn|hg|bzr)(?::|/)", text, re.IGNORECASE):
        return True
    if re.match(r"^(?:github|gitlab|bitbucket):", text, re.IGNORECASE):
        return True
    if _scp_dependency_locator(text):
        return True
    return bool(re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+[?@#].*$", text))


def sanitize_dependency_locator(value: Any, *, limit: int = 500) -> str:
    """Return only persistence-safe locator structure, never selectors or credentials."""
    text, normalized = _normalized_dependency_locator(value)
    if not text:
        return ""
    if not normalized:
        return "redacted dependency locator"
    if "://" in text:
        candidate = text
        transport = ""
        for prefix in ("git+", "hg+", "svn+", "bzr+"):
            if candidate.lower().startswith(prefix):
                transport = prefix
                candidate = candidate[len(prefix):]
                break
        try:
            parsed = urlsplit(candidate)
            if not parsed.scheme or not parsed.hostname:
                return "malformed remote source"
            port = f":{parsed.port}" if parsed.port else ""
            path = re.sub(r"/{2,}", "/", parsed.path or "")
            path = _without_dependency_selector(path)
            return urlunsplit((f"{transport}{parsed.scheme.lower()}", f"{parsed.hostname.lower()}{port}", path, "", ""))[:limit]
        except (TypeError, ValueError):
            return "malformed remote source"
    provider = re.match(r"^(github|gitlab|bitbucket):(.+)$", text, re.IGNORECASE)
    if provider:
        locator = _without_dependency_selector(provider.group(2)).lstrip("/")
        return f"{provider.group(1).lower()}:{locator}"[:limit]
    if re.match(r"^(?:git\+|hg\+|svn\+|bzr\+)?(?:https?|ssh|git|svn|hg|bzr)(?::|/)", text, re.IGNORECASE):
        return "malformed remote source"
    scp = _scp_dependency_locator(text)
    if scp:
        host, raw_path = scp
        path = _without_dependency_selector(raw_path).lstrip("/")
        return f"vcs:{host.lower()}/{path}"[:limit]
    bare = re.match(r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:[?@#].*)?$", text)
    if bare:
        return bare.group(1)[:limit]
    if any(marker in text for marker in ("?", "#")) and ("/" in text or "@" in text):
        return "redacted dependency locator"
    return sanitize_private_text(text, limit=limit)


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
        structured_value = _validated_scan_field(value, key)
        if structured_value is not None:
            return structured_value
        if key.casefold() in _DEPENDENCY_LOCATOR_KEYS:
            return sanitize_dependency_locator(value, limit=MAX_DISCLOSURE_TEXT_CHARS)
        if _looks_like_dependency_locator(value):
            return sanitize_dependency_locator(value, limit=MAX_DISCLOSURE_TEXT_CHARS)
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


def validate_structured_digest(value: Any, contract: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{contract} must be a string.")
    patterns = {
        "git-commit": r"[0-9a-fA-F]{40}",
        "sha256": r"[0-9a-fA-F]{64}",
        "fingerprint": _STRUCTURED_FINGERPRINT_RE.pattern,
    }
    pattern = patterns.get(contract)
    if pattern is None:
        raise ValueError("Unknown structured digest contract.")
    if not re.fullmatch(pattern, value):
        raise ValueError(f"{contract} is invalid.")
    return value


def validate_dependency_integrity(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("dependency integrity is invalid.")
    digest_bytes = {"sha256": 32, "sha384": 48, "sha512": 64}
    for token in value.split():
        match = re.fullmatch(
            r"(sha256|sha384|sha512)([:-])([A-Za-z0-9+/=_-]+)",
            token,
        )
        if not match:
            raise ValueError("dependency integrity is invalid.")
        algorithm, separator, payload = match.groups()
        expected_bytes = digest_bytes[algorithm]
        if separator == ":":
            if not re.fullmatch(rf"[0-9a-fA-F]{{{expected_bytes * 2}}}", payload):
                raise ValueError("dependency integrity is invalid.")
            continue
        try:
            decoded = base64.b64decode(payload, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("dependency integrity is invalid.") from error
        if len(decoded) != expected_bytes:
            raise ValueError("dependency integrity is invalid.")
    return value


def _redact_long_token(match: re.Match[str]) -> str:
    value = match.group(0)
    characters = set(value.casefold())
    has_letter = any(character.isalpha() for character in value)
    has_digit = any(character.isdigit() for character in value)
    if len(characters) >= 10 and has_letter and has_digit:
        return REDACTED
    return value


def _validated_scan_field(value: str, key: str) -> str | None:
    normalized_key = key.casefold()
    if normalized_key in _STRUCTURED_FINGERPRINT_KEYS:
        try:
            return validate_structured_digest(value, "fingerprint")
        except ValueError:
            return None
    selectors = _STRUCTURED_VCS_SELECTORS.get(normalized_key)
    if selectors is not None:
        items = value.split(",") if normalized_key == "vcsrequestedrevision" else [value]
        parsed: list[str] = []
        for item in items:
            match = re.fullmatch(r"([a-z]+):sha256:([0-9a-f]{64})", item)
            if not match or match.group(1) not in selectors:
                return None
            parsed.append(item)
        if len({item.split(":", 1)[0] for item in parsed}) != len(parsed):
            return None
        return ",".join(parsed)
    if normalized_key == "integrity":
        try:
            return validate_dependency_integrity(value)
        except ValueError:
            return None
    return None


def _bounded_line(value: str, limit: int) -> str:
    clean = normalize_control_characters(value, preserve_lines=False).expandtabs(4)
    if len(clean) <= limit:
        return clean
    return f"{clean[: max(0, limit - 1)]}\u2026"
