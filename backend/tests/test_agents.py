from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from app import main
from app.schemas import AgentPreviewRequest


class AgentsWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            dir=Path(__file__).resolve().parent
        )
        self.base_path = Path(self.temporary_directory.name)
        self.workspace_root = self.base_path / "workspace"
        self.workspace_root.mkdir()
        self.project_path = self.workspace_root / "project"
        self.project_path.mkdir()
        self.addCleanup(self.temporary_directory.cleanup)

    def payload(self, *, overwrite: bool = False) -> AgentPreviewRequest:
        return AgentPreviewRequest(
            project_path=str(self.project_path),
            project_purpose="Test project",
            overwrite=overwrite,
        )

    def write_agents(self, *, overwrite: bool = False) -> dict[str, object]:
        with (
            patch.object(
                main,
                "_ensure_project",
                return_value=self.project_path,
            ),
            patch.object(
                main,
                "_project_root",
                return_value=self.workspace_root,
            ),
        ):
            return main.write_agents(self.payload(overwrite=overwrite))

    def test_creates_literal_agents_file_when_absent(self) -> None:
        result = self.write_agents()
        agents_path = self.project_path / "AGENTS.md"

        self.assertTrue(result["written"])
        self.assertFalse(result["confirmation_required"])
        self.assertEqual(result["path"], str(agents_path))
        self.assertTrue(agents_path.is_file())
        self.assertIn("Test project", agents_path.read_text(encoding="utf-8"))

    def test_existing_file_requires_overwrite_confirmation(self) -> None:
        agents_path = self.project_path / "AGENTS.md"
        agents_path.write_text("original", encoding="utf-8")

        result = self.write_agents()

        self.assertFalse(result["written"])
        self.assertTrue(result["confirmation_required"])
        self.assertEqual(agents_path.read_text(encoding="utf-8"), "original")

    def test_collision_during_atomic_create_requires_confirmation(self) -> None:
        with (
            patch.object(
                main,
                "_ensure_project",
                return_value=self.project_path,
            ),
            patch.object(
                main,
                "_project_root",
                return_value=self.workspace_root,
            ),
            patch.object(Path, "open", side_effect=FileExistsError),
        ):
            result = main.write_agents(self.payload())

        self.assertFalse(result["written"])
        self.assertTrue(result["confirmation_required"])
        self.assertFalse((self.project_path / "AGENTS.md").exists())

    def test_confirmed_overwrite_replaces_regular_file(self) -> None:
        agents_path = self.project_path / "AGENTS.md"
        agents_path.write_text("original", encoding="utf-8")

        result = self.write_agents(overwrite=True)

        self.assertTrue(result["written"])
        self.assertFalse(result["confirmation_required"])
        self.assertNotEqual(
            agents_path.read_text(encoding="utf-8"),
            "original",
        )
        self.assertIn(
            "Test project",
            agents_path.read_text(encoding="utf-8"),
        )

    def test_simulated_linked_or_reparse_target_is_rejected(self) -> None:
        agents_path = self.project_path / "AGENTS.md"
        agents_path.write_text("do not change", encoding="utf-8")

        with patch(
            "app.safety.is_reparse_point_or_symlink",
            side_effect=lambda path: path == agents_path,
        ):
            with self.assertRaises(HTTPException) as raised:
                self.write_agents(overwrite=True)

        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(
            agents_path.read_text(encoding="utf-8"),
            "do not change",
        )

    def test_hardlinked_target_is_rejected_without_changing_other_name(self) -> None:
        outside_path = self.workspace_root / "outside-agents.md"
        outside_path.write_text("do not change", encoding="utf-8")
        agents_path = self.project_path / "AGENTS.md"
        try:
            os.link(outside_path, agents_path)
        except OSError as exc:
            self.skipTest(f"Hardlinks are unavailable: {exc}")

        with self.assertRaises(HTTPException) as raised:
            self.write_agents(overwrite=True)

        self.assertEqual(raised.exception.status_code, 409)
        self.assertEqual(
            outside_path.read_text(encoding="utf-8"),
            "do not change",
        )

    def test_non_regular_target_is_rejected(self) -> None:
        (self.project_path / "AGENTS.md").mkdir()

        with self.assertRaises(HTTPException) as raised:
            self.write_agents(overwrite=True)

        self.assertEqual(raised.exception.status_code, 409)


if __name__ == "__main__":
    unittest.main()
