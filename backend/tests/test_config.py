from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from fastapi.middleware.cors import CORSMiddleware

from app.config import CORS_ORIGINS_ENV, DEFAULT_CORS_ORIGINS, allowed_cors_origins
from app.main import app


class CorsConfigurationTests(unittest.TestCase):
    def test_defaults_and_middleware_use_the_resolved_origins(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(allowed_cors_origins(), list(DEFAULT_CORS_ORIGINS))

        middleware = next(item for item in app.user_middleware if item.cls is CORSMiddleware)
        self.assertEqual(middleware.kwargs["allow_origins"], allowed_cors_origins())
        self.assertNotIn("*", middleware.kwargs["allow_origins"])

    def test_multiple_configured_origins_are_normalized_and_deduplicated(self) -> None:
        configured = " https://dashboard.example.test/, http://127.0.0.1:5174,https://dashboard.example.test "
        with patch.dict(os.environ, {CORS_ORIGINS_ENV: configured}):
            self.assertEqual(
                allowed_cors_origins(),
                ["https://dashboard.example.test", "http://127.0.0.1:5174"],
            )

    def test_wildcard_and_malformed_origins_are_rejected(self) -> None:
        for configured in ("*", "dashboard.example.test", "http://:5173", "https://example.test:not-a-port", "https://user@example.test", "https://example.test/path", "https://example.test,,http://localhost:5173"):
            with self.subTest(configured=configured):
                with self.assertRaises(ValueError):
                    allowed_cors_origins(configured)


if __name__ == "__main__":
    unittest.main()
