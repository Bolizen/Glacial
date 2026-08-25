from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.config import DESKTOP_AUTH_TOKEN_ENV, desktop_auth_token
from app.database import DB_PATH, REPOSITORY_DB_DIR, resolved_database_path
from app.desktop_entry import MAX_STARTUP_MESSAGE_BYTES, parse_startup_message, run, startup_message
from app.main import _authorized_api_request, app


TOKEN = "a" * 64


async def asgi_request(
    method: str,
    path: str,
    headers: list[tuple[bytes, bytes]] | None = None,
    body: dict[str, object] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    messages: list[dict[str, object]] = []
    request_sent = False
    request_body = json.dumps(body).encode("utf-8") if body is not None else b""
    request_headers = list(headers or [])
    if body is not None:
        request_headers.extend([
            (b"content-type", b"application/json"),
            (b"content-length", str(len(request_body)).encode("ascii")),
        ])

    async def receive() -> dict[str, object]:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": request_body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "root_path": "",
            "headers": request_headers,
            "client": ("127.0.0.1", 40000),
            "server": ("127.0.0.1", 8000),
        },
        receive,
        send,
    )
    start = next(message for message in messages if message["type"] == "http.response.start")
    response_headers = {
        key.decode("latin-1").lower(): value.decode("latin-1")
        for key, value in start["headers"]
    }
    body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    return int(start["status"]), response_headers, body


class DesktopDataDirectoryTests(unittest.TestCase):
    def test_repository_fallback_is_unchanged_when_override_is_absent(self) -> None:
        self.assertEqual(
            resolved_database_path(None, environment_present=False),
            REPOSITORY_DB_DIR / "glacial.db",
        )
        self.assertEqual(DB_PATH.name, "glacial.db")

    def test_absolute_desktop_override_uses_a_dedicated_database(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "data"
            self.assertEqual(
                resolved_database_path(str(data_dir), environment_present=True),
                data_dir.resolve() / "glacial.db",
            )

    def test_invalid_desktop_overrides_are_rejected(self) -> None:
        invalid_values = (None, "", "relative\\data", "C:\\temp\\..\\escape", "bad\0path")
        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    resolved_database_path(value, environment_present=True)


class DesktopAuthenticationTests(unittest.TestCase):
    def test_missing_and_empty_token_configuration_fail_closed(self) -> None:
        for configured in (None, "", "a" * 63, "A" * 64):
            environment = {} if configured is None else {DESKTOP_AUTH_TOKEN_ENV: configured}
            with self.subTest(configured=configured):
                with patch.dict(os.environ, environment, clear=True):
                    with self.assertRaises(ValueError):
                        desktop_auth_token()
                    status, headers, body = asyncio.run(asgi_request("GET", "/api/health"))
                self.assertEqual(status, 503)
                self.assertEqual(json.loads(body), {"detail": "Desktop API authentication is unavailable."})
                self.assertNotIn(TOKEN, json.dumps(headers))
                self.assertNotIn(TOKEN.encode("ascii"), body)

        self.assertFalse(_authorized_api_request("/api/health", "GET", None, None))
        self.assertFalse(_authorized_api_request("/api/health", "GET", None, ""))

    def test_token_configuration_is_exact(self) -> None:
        self.assertEqual(desktop_auth_token(TOKEN, environment=False), TOKEN)
        for value in ("", "a" * 63, "A" * 64, "g" * 64):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    desktop_auth_token(value, environment=False)

    def test_api_authentication_accepts_only_the_exact_bearer_value(self) -> None:
        self.assertTrue(_authorized_api_request("/api/health", "GET", f"Bearer {TOKEN}", TOKEN))
        for value in (None, "", TOKEN, f"bearer {TOKEN}", f"Bearer {TOKEN[:-1]}b"):
            with self.subTest(value=value):
                self.assertFalse(_authorized_api_request("/api/health", "GET", value, TOKEN))

    def test_runtime_identity_requires_authentication_and_exposes_only_bounded_product_fields(self) -> None:
        with patch.dict(os.environ, {"GLACIAL_DESKTOP_AUTH_TOKEN": TOKEN}, clear=False):
            status, _, body = asyncio.run(asgi_request(
                "GET",
                "/api/runtime-identity",
                [(b"authorization", f"Bearer {TOKEN}".encode("ascii"))],
            ))
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(body),
            {
                "schema_version": 1,
                "product_name": "Glacial",
                "product_version": "0.9.12",
                "component": "owned-backend",
            },
        )

    def test_missing_malformed_and_incorrect_tokens_return_401(self) -> None:
        with patch.dict(os.environ, {DESKTOP_AUTH_TOKEN_ENV: TOKEN}, clear=False):
            for authorization in (None, b"", b"Basic abc", f"Bearer {'b' * 64}".encode("ascii")):
                headers = [] if authorization is None else [(b"authorization", authorization)]
                status, _, body = asyncio.run(asgi_request("GET", "/api/health", headers))
                self.assertEqual(status, 401)
                self.assertEqual(json.loads(body), {"detail": "Desktop API authentication is required."})
                self.assertNotIn(TOKEN.encode("ascii"), body)

    def test_authenticated_read_succeeds_without_exposing_the_token(self) -> None:
        with patch.dict(os.environ, {DESKTOP_AUTH_TOKEN_ENV: TOKEN}, clear=False):
            status, headers, body = asyncio.run(
                asgi_request("GET", "/api/health", [(b"authorization", f"Bearer {TOKEN}".encode("ascii"))])
            )
            self.assertEqual((status, json.loads(body)), (200, {"status": "ok"}))
            self.assertNotIn(TOKEN, json.dumps(headers))
            self.assertNotIn(TOKEN.encode("ascii"), body)

    def test_api_schema_and_interactive_documentation_are_not_exposed(self) -> None:
        with patch.dict(os.environ, {DESKTOP_AUTH_TOKEN_ENV: TOKEN}, clear=False):
            for path in ("/openapi.json", "/docs", "/redoc"):
                with self.subTest(path=path):
                    status, _, body = asyncio.run(asgi_request("GET", path))
                    self.assertEqual(status, 404)
                    self.assertNotIn(b"/api/agents", body)

    def test_authenticated_mutation_succeeds(self) -> None:
        root = Path(tempfile.gettempdir()).resolve()
        with (
            patch.dict(os.environ, {DESKTOP_AUTH_TOKEN_ENV: TOKEN}, clear=False),
            patch("app.main.existing_workspace_root", return_value=root),
            patch("app.main.set_setting") as set_setting,
        ):
            status, _, body = asyncio.run(asgi_request(
                "PUT",
                "/api/config/project-root",
                [(b"authorization", f"Bearer {TOKEN}".encode("ascii"))],
                {"project_root": str(root)},
            ))
        self.assertEqual((status, json.loads(body)), (200, {"project_root": str(root)}))
        set_setting.assert_called_once_with("project_root", str(root))

    def test_backend_entry_refuses_to_bind_without_token_configuration(self) -> None:
        errors = io.StringIO()
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("app.desktop_entry.prepare_database_directory") as prepare_database_directory,
            patch("app.desktop_entry.socket.socket") as socket_factory,
            contextlib.redirect_stderr(errors),
        ):
            self.assertEqual(run(), 1)
        prepare_database_directory.assert_not_called()
        socket_factory.assert_not_called()
        self.assertEqual(errors.getvalue(), "Glacial backend startup failed.\n")

    def test_cors_preflight_remains_available_with_desktop_authentication(self) -> None:
        headers = [
            (b"origin", b"http://127.0.0.1:5173"),
            (b"access-control-request-method", b"GET"),
            (b"access-control-request-headers", b"authorization"),
        ]
        with patch.dict(os.environ, {DESKTOP_AUTH_TOKEN_ENV: TOKEN}, clear=False):
            status, response_headers, _ = asyncio.run(asgi_request("OPTIONS", "/api/health", headers))
        self.assertEqual(status, 200)
        self.assertEqual(response_headers["access-control-allow-origin"], "http://127.0.0.1:5173")
        self.assertIn("Authorization", response_headers["access-control-allow-headers"])


class DesktopStartupMessageTests(unittest.TestCase):
    def test_startup_message_is_exact_bounded_and_round_trips(self) -> None:
        message = startup_message(49152)
        self.assertEqual(message, 'GLACIAL_BACKEND_READY {"port":49152}')
        self.assertLessEqual(len(message.encode("ascii")), MAX_STARTUP_MESSAGE_BYTES)
        self.assertEqual(parse_startup_message(message), 49152)

    def test_malformed_duplicate_and_oversized_messages_are_rejected(self) -> None:
        invalid = (
            "",
            'GLACIAL_BACKEND_READY {"port":0}',
            'GLACIAL_BACKEND_READY {"port":8000,"port":8001}',
            'GLACIAL_BACKEND_READY {"port":8000,"token":"secret"}',
            'GLACIAL_BACKEND_READY {"port":8000}\nextra',
            "x" * (MAX_STARTUP_MESSAGE_BYTES + 1),
        )
        for message in invalid:
            with self.subTest(message=message):
                with self.assertRaises(ValueError):
                    parse_startup_message(message)


if __name__ == "__main__":
    unittest.main()
