from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from app import bridge_limits, database, main
from app.schemas import ProjectPathRequest


class BridgeResponseLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            dir=Path(__file__).resolve().parent
        )
        self.addCleanup(self.temporary_directory.cleanup)
        self.base = Path(self.temporary_directory.name)
        self.database_path = self.base / "glacial.db"
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.project = self.root / "project"
        self.project.mkdir()

        patches = [
            patch.object(database, "DB_PATH", self.database_path),
            patch.object(database, "get_connection", side_effect=self.closing_connection),
            patch.object(main, "get_connection", side_effect=self.closing_connection),
        ]
        for active_patch in patches:
            active_patch.start()
            self.addCleanup(active_patch.stop)
        database.init_db()
        database.set_setting(database.WORKSPACE_ROOT_SETTING, str(self.root))
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO projects (path, name, description, project_type, created_at) "
                "VALUES (?, 'project', '', '', '2026-01-01T00:00:00+00:00')",
                (str(self.project),),
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

    def scan_result(
        self,
        reviewed_files: list[str],
        *,
        findings: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        return {
            "overall_risk": "none",
            "findings": findings or [],
            "manifests": [],
            "lockfiles": [],
            "lifecycleScripts": [],
            "secretFiles": [],
            "ignoredFiles": [],
            "builtInExcludedDirectories": [],
            "reviewedFiles": reviewed_files,
            "reviewedFileCount": len(reviewed_files),
            "zone": "Unknown",
            "dependencyTrust": None,
            "scanCompleteness": {
                "complete": True,
                "traversalFailureCount": 0,
                "fileInspectionFailureCount": 0,
                "oversizedFileCount": 0,
                "unsafePathCount": 0,
                "dependencyAnalysisFailureCount": 0,
                "policyExcludedFileCount": 0,
                "builtInExcludedDirectoryCount": 0,
                "unsupportedEncodingFileCount": 0,
                "resourceBudgetExceededCount": 0,
                "issueCount": 0,
            },
        }

    def persisted_scan_count(self) -> int:
        with database.get_connection() as connection:
            return connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

    def test_small_and_comfortably_below_limit_results_are_unchanged(self) -> None:
        paths = ["src/app.py", "src/worker.py"]
        with patch.object(main, "scan_project", return_value=self.scan_result(paths)):
            response = main.run_scan(ProjectPathRequest(project_path=str(self.project)))

        self.assertEqual(response["reviewedFiles"], paths)
        self.assertEqual(response["reviewedFileCount"], 2)
        self.assertFalse(response["reviewedFilesTruncated"])
        self.assertTrue(response["scanMetadataReliable"])
        self.assertLess(
            bridge_limits.serialized_json_bytes(response),
            bridge_limits.MAX_NATIVE_BRIDGE_JSON_BYTES // 2,
        )

    def test_unicode_reviewed_files_are_reduced_before_persistence_and_history(self) -> None:
        paths = [
            f"{index:05d}-{'雪' * 180}.txt"
            for index in range(35_000)
        ]
        previous_bytes = bridge_limits.serialized_json_bytes(
            self.scan_result(paths)
        )
        self.assertGreater(previous_bytes, 16 * 1024 * 1024)

        with patch.object(main, "scan_project", return_value=self.scan_result(paths)):
            current = main.run_scan(ProjectPathRequest(project_path=str(self.project)))

        self.assertEqual(current["reviewedFileCount"], len(paths))
        self.assertTrue(current["reviewedFilesTruncated"])
        self.assertFalse(current["scanMetadataReliable"])
        self.assertGreater(len(current["reviewedFiles"]), 0)
        self.assertLess(len(current["reviewedFiles"]), len(paths))
        self.assertEqual(current["reviewedFiles"], paths[:len(current["reviewedFiles"])])
        self.assertLessEqual(
            bridge_limits.serialized_json_bytes(current),
            bridge_limits.MAX_NATIVE_BRIDGE_JSON_BYTES,
        )
        self.assertEqual(self.persisted_scan_count(), 1)

        with database.get_connection() as connection:
            metadata = json.loads(
                connection.execute("SELECT scan_metadata_json FROM scans").fetchone()[0]
            )
        self.assertTrue(metadata["reviewedFilesTruncated"])
        self.assertEqual(metadata["reviewedFiles"], current["reviewedFiles"])

        history = main.scan_history(str(self.project))
        self.assertLessEqual(
            bridge_limits.serialized_json_bytes(history),
            bridge_limits.MAX_NATIVE_BRIDGE_JSON_BYTES,
        )
        self.assertEqual(history["scans"][0]["reviewedFileCount"], len(paths))
        self.assertTrue(history["scans"][0]["reviewedFilesTruncated"])
        self.assertEqual(history["scans"][0]["reviewedFiles"], current["reviewedFiles"])

    def test_security_significant_oversize_rolls_back_without_persistence(self) -> None:
        findings = [
            {
                "path": f"src/file-{index}.py",
                "type": "hostile-test-finding",
                "severity": "high",
                "explanation": "x" * 1_000,
                "action": "y" * 1_000,
            }
            for index in range(100)
        ]
        with (
            patch.object(bridge_limits, "MAX_NATIVE_BRIDGE_JSON_BYTES", 10_000),
            patch.object(
                main,
                "scan_project",
                return_value=self.scan_result([], findings=findings),
            ),
            self.assertRaises(HTTPException) as raised,
        ):
            main.run_scan(ProjectPathRequest(project_path=str(self.project)))

        self.assertEqual(raised.exception.status_code, 413)
        self.assertIn("not persisted", str(raised.exception.detail))
        self.assertEqual(self.persisted_scan_count(), 0)

    def test_history_reduction_and_oldest_omission_are_explicit(self) -> None:
        scans = [
            {
                "id": scan_id,
                "reviewedFiles": [f"{scan_id}-{'雪' * 40}-{index}" for index in range(10)],
                "reviewedFileCount": 10,
                "scanMetadataReliable": True,
                "findings": [],
            }
            for scan_id in (2, 1)
        ]
        with patch.object(bridge_limits, "MAX_NATIVE_BRIDGE_JSON_BYTES", 700):
            reduced = bridge_limits.fit_history_response(scans, available_scan_count=2)
        self.assertLessEqual(bridge_limits.serialized_json_bytes(reduced), 700)
        self.assertTrue(reduced["historyMetadataReduced"])
        self.assertTrue(any(scan.get("reviewedFilesTruncated") for scan in reduced["scans"]))

        security_scans = [
            {"id": scan_id, "reviewedFiles": [], "reviewedFileCount": 0, "findings": ["x" * 180]}
            for scan_id in (2, 1)
        ]
        with patch.object(bridge_limits, "MAX_NATIVE_BRIDGE_JSON_BYTES", 500):
            omitted = bridge_limits.fit_history_response(
                security_scans,
                available_scan_count=2,
            )
        self.assertTrue(omitted["historyTruncated"])
        self.assertEqual(omitted["returnedScanCount"], 1)
        self.assertEqual(omitted["availableScanCount"], 2)
        self.assertEqual(omitted["scans"][0]["id"], 2)
        self.assertEqual(omitted["scans"][0]["findings"], ["x" * 180])


if __name__ == "__main__":
    unittest.main()
