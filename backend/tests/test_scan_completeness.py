from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from app import database, main
from app.schemas import ProjectPathRequest


class ScanCompletenessPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.base_path = Path(self.temporary_directory.name)
        self.database_path = self.base_path / "codexforge.db"
        self.project_path = self.base_path / "workspace" / "project"
        self.project_path.mkdir(parents=True)
        self.addCleanup(self.temporary_directory.cleanup)
        self.database_patch = patch.object(database, "DB_PATH", self.database_path)
        self.database_patch.start()
        self.addCleanup(self.database_patch.stop)
        self.database_connection_patch = patch.object(database, "get_connection", side_effect=self.closing_connection)
        self.main_connection_patch = patch.object(main, "get_connection", side_effect=self.closing_connection)
        self.database_connection_patch.start()
        self.main_connection_patch.start()
        self.addCleanup(self.database_connection_patch.stop)
        self.addCleanup(self.main_connection_patch.stop)
        database.init_db()
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO projects (path, name, description, project_type, created_at) VALUES (?, ?, '', '', ?)",
                (str(self.project_path), "project", "2026-01-01T00:00:00+00:00"),
            )

    @contextmanager
    def closing_connection(self) -> object:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def test_scan_and_history_preserve_completeness_and_finding_metadata(self) -> None:
        scan_result = {
            "overall_risk": "medium",
            "findings": [{
                "path": "blocked",
                "type": "directory-traversal-error",
                "severity": "medium",
                "explanation": "Directory could not be read.",
                "action": "Inspect it manually.",
                "operation": "traverse-directory",
            }],
            "manifests": [],
            "lockfiles": [],
            "lifecycleScripts": [],
            "secretFiles": [],
            "ignoredFiles": [],
            "reviewedFiles": [],
            "reviewedFileCount": 0,
            "zone": "Unknown",
            "scanCompleteness": {
                "complete": False,
                "traversalFailureCount": 1,
                "fileInspectionFailureCount": 0,
                "oversizedFileCount": 0,
                "unsafePathCount": 0,
                "issueCount": 1,
            },
        }
        payload = ProjectPathRequest(project_path=str(self.project_path))

        with (
            patch.object(main, "_ensure_project", return_value=self.project_path),
            patch.object(main, "scan_project", return_value=scan_result),
            patch.object(main, "_project_root", return_value=self.project_path.parent),
        ):
            current = main.run_scan(payload)
            history = main.scan_history(str(self.project_path))["scans"]
            project = main.list_projects()["projects"][0]

        self.assertEqual(current["scanCompleteness"], scan_result["scanCompleteness"])
        self.assertEqual(history[0]["scanCompleteness"], scan_result["scanCompleteness"])
        self.assertEqual(history[0]["findings"][0]["action"], "Inspect it manually.")
        self.assertEqual(history[0]["findings"][0]["operation"], "traverse-directory")
        self.assertEqual(project["last_scan_completeness"], scan_result["scanCompleteness"])

    def test_older_scan_without_completeness_metadata_returns_unknown(self) -> None:
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO scans (project_path, scan_date, overall_risk, findings_json, scan_metadata_json) VALUES (?, ?, ?, ?, ?)",
                (str(self.project_path), "2026-01-01T00:00:00+00:00", "none", json.dumps([]), json.dumps({})),
            )

        with (
            patch.object(main, "_ensure_project", return_value=self.project_path),
            patch.object(main, "_project_root", return_value=self.project_path.parent),
        ):
            scan = main.scan_history(str(self.project_path))["scans"][0]
            project = main.list_projects()["projects"][0]

        self.assertIsNone(scan["scanCompleteness"])
        self.assertIsNone(project["last_scan_completeness"])


if __name__ == "__main__":
    unittest.main()
