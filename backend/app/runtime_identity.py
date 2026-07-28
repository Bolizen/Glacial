from __future__ import annotations

from .version import GLACIAL_VERSION

RUNTIME_IDENTITY_SCHEMA_VERSION = 1


def backend_runtime_identity() -> dict[str, object]:
    return {
        "schema_version": RUNTIME_IDENTITY_SCHEMA_VERSION,
        "product_name": "Glacial",
        "product_version": GLACIAL_VERSION,
        "component": "owned-backend",
    }

