from __future__ import annotations

import os
from urllib.parse import urlsplit


CORS_ORIGINS_ENV = "CODEXFORGE_CORS_ORIGINS"
DEFAULT_CORS_ORIGINS = (
    "http://127.0.0.1:5173",
    "http://localhost:5173",
)


def allowed_cors_origins(value: str | None = None) -> list[str]:
    configured = os.getenv(CORS_ORIGINS_ENV) if value is None else value
    if configured is None or not configured.strip():
        return list(DEFAULT_CORS_ORIGINS)

    origins: list[str] = []
    for candidate in configured.split(","):
        origin = _normalized_origin(candidate)
        if origin not in origins:
            origins.append(origin)
    return origins


def _normalized_origin(value: str) -> str:
    candidate = value.strip()
    if not candidate or candidate == "*":
        raise ValueError(f"{CORS_ORIGINS_ENV} must contain explicit HTTP(S) origins")

    parsed = urlsplit(candidate)
    try:
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError(f"{CORS_ORIGINS_ENV} contains an invalid origin") from exc
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.netloc
        or not hostname
        or any(character.isspace() for character in candidate)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{CORS_ORIGINS_ENV} contains an invalid origin")
    return f"{parsed.scheme.lower()}://{parsed.netloc}"
