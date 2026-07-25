from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from app import database, main
from app.schemas import ProjectPathRequest, TrustedScanBaselineSet


class TrustedScanBaselineTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.database_path = self.base / "glacial.db"
        self.root = self.base / "workspace"
        self.project = self.root / "project"
        self.other = self.root / "other"
        self.project.mkdir(parents=True)
        self.other.mkdir()
        for active_patch in (
            patch.object(database, "DB_PATH", self.database_path),
            patch.object(database, "get_connection", side_effect=self.closing_connection),
            patch.object(main, "get_connection", side_effect=self.closing_connection),
        ):
            active_patch.start()
            self.addCleanup(active_patch.stop)
        database.init_db()
        database.set_setting(database.WORKSPACE_ROOT_SETTING, str(self.root))
        with database.get_connection() as connection:
            for path in (self.project, self.other):
                connection.execute(
                    "INSERT INTO projects (path, name, created_at) VALUES (?, ?, ?)",
                    (str(path), path.name, "2026-01-01T00:00:00+00:00"),
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

    def add_scan(
        self,
        scan_id: int,
        *,
        project: Path | None = None,
        complete: bool = True,
        metadata_reliable: bool = True,
        dependency_status: str = "complete",
    ) -> None:
        issue_count = 0 if complete else 1
        metadata = {
            "manifests": ["package.json"] if metadata_reliable else "package.json",
            "lockfiles": ["package-lock.json"],
            "lifecycleScripts": [{"path": "package.json", "script": "test"}],
            "ignoredFiles": [],
            "reviewedFiles": ["src/index.js"],
            "scanCompleteness": {
                "complete": complete,
                "traversalFailureCount": 0,
                "fileInspectionFailureCount": issue_count,
                "oversizedFileCount": 0,
                "unsafePathCount": 0,
                "dependencyAnalysisFailureCount": 0,
                "policyExcludedFileCount": 0,
                "resourceBudgetExceededCount": 0,
                "issueCount": issue_count,
            },
            "dependencyTrust": {
                "schemaVersion": 1,
                "status": dependency_status,
                "entries": [{
                    "ecosystem": "node",
                    "name": "alpha",
                    "group": "runtime",
                    "direct": True,
                    "lockedVersion": "1.0.0",
                }],
                "packageManagers": ["npm"],
                "ecosystems": ["node"],
            },
        }
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO scans (id, project_path, scan_date, overall_risk, findings_json, "
                "finding_count, reviewed_file_count, ignored_file_count, finding_summary_json, scan_metadata_json) "
                "VALUES (?, ?, ?, 'low', '[]', 0, 1, 0, '{}', ?)",
                (
                    scan_id,
                    str(project or self.project),
                    f"2026-06-{scan_id:02d}T12:00:00+00:00",
                    json.dumps(metadata),
                ),
            )

    def set_baseline(self, scan_id: int, *, replace: bool = False) -> dict[str, object]:
        return main.set_trusted_scan_baseline(TrustedScanBaselineSet(
            project_path=str(self.project),
            scan_id=scan_id,
            replace=replace,
        ))

    def activity_types(self) -> list[str]:
        with database.get_connection() as connection:
            rows = connection.execute(
                "SELECT event_type FROM project_activity_events WHERE project_id = ? ORDER BY rowid",
                (str(self.project),),
            ).fetchall()
        return [row["event_type"] for row in rows]

    def test_eligible_scan_can_be_pinned_and_repeated_pin_is_a_no_op(self) -> None:
        self.add_scan(1)

        created = self.set_baseline(1)
        repeated = self.set_baseline(1)

        self.assertEqual(created["status"], "valid")
        self.assertEqual(created["baseline"]["scanId"], 1)
        self.assertTrue(created["activity_recorded"])
        self.assertFalse(repeated["activity_recorded"])
        self.assertEqual(self.activity_types(), ["trusted_scan_baseline_set"])

    def test_incomplete_unreliable_and_incompatible_scans_cannot_be_pinned(self) -> None:
        self.add_scan(1, complete=False)
        self.add_scan(2, metadata_reliable=False)
        self.add_scan(3, dependency_status="incomplete")

        for scan_id in (1, 2, 3):
            with self.subTest(scan_id=scan_id), self.assertRaises(HTTPException) as error:
                self.set_baseline(scan_id)
            self.assertEqual(error.exception.status_code, 409)
        self.assertEqual(self.activity_types(), [])

    def test_cross_project_scan_cannot_be_pinned(self) -> None:
        self.add_scan(1, project=self.other)

        with self.assertRaises(HTTPException) as error:
            self.set_baseline(1)

        self.assertEqual(error.exception.status_code, 403)

    def test_replacement_is_atomic_and_records_one_replacement_event(self) -> None:
        self.add_scan(1)
        self.add_scan(2)
        self.set_baseline(1)

        with patch.object(main, "append_activity_event", side_effect=RuntimeError("event failure")):
            with self.assertRaises(RuntimeError):
                self.set_baseline(2, replace=True)
        self.assertEqual(main.get_trusted_scan_baseline(str(self.project))["baseline"]["scanId"], 1)

        replaced = self.set_baseline(2, replace=True)

        self.assertEqual(replaced["baseline"]["scanId"], 2)
        self.assertEqual(self.activity_types(), [
            "trusted_scan_baseline_set",
            "trusted_scan_baseline_replaced",
        ])

    def test_clearing_preserves_scan_and_records_only_one_clear_event(self) -> None:
        self.add_scan(1)
        self.set_baseline(1)

        cleared = main.clear_trusted_scan_baseline(ProjectPathRequest(project_path=str(self.project)))
        repeated = main.clear_trusted_scan_baseline(ProjectPathRequest(project_path=str(self.project)))

        self.assertFalse(cleared["configured"])
        self.assertTrue(cleared["activity_recorded"])
        self.assertFalse(repeated["activity_recorded"])
        with database.get_connection() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM scans WHERE id = 1").fetchone()[0], 1)
        self.assertEqual(self.activity_types(), [
            "trusted_scan_baseline_set",
            "trusted_scan_baseline_cleared",
        ])

    def test_invalid_stored_baseline_is_preserved_without_automatic_substitution(self) -> None:
        self.add_scan(1)
        self.add_scan(2)
        self.set_baseline(1)
        with database.get_connection() as connection:
            connection.execute(
                "UPDATE scans SET scan_metadata_json = '{}' WHERE id = 1",
            )

        state = main.get_trusted_scan_baseline(str(self.project))

        self.assertTrue(state["configured"])
        self.assertEqual(state["status"], "invalid")
        self.assertEqual(state["baseline"]["scanId"], 1)
        self.assertEqual(state["latestScan"]["id"], 2)
        self.assertIn("no automatic baseline was substituted", state["message"])

    def test_read_response_contains_bounded_metadata_and_finding_identities(self) -> None:
        self.add_scan(1)
        with database.get_connection() as connection:
            row = connection.execute("SELECT scan_metadata_json FROM scans WHERE id = 1").fetchone()
            metadata = json.loads(row["scan_metadata_json"])
            metadata["manifests"] = ["x" * 800]
            connection.execute(
                "UPDATE scans SET scan_metadata_json = ?, findings_json = ?, "
                "finding_count = 1 WHERE id = 1",
                (
                    json.dumps(metadata),
                    json.dumps([{
                        "type": "test-finding",
                        "path": "src/index.js",
                        "severity": "low",
                    }]),
                ),
            )
        self.set_baseline(1)

        baseline_scan = main.get_trusted_scan_baseline(str(self.project))["baseline"]["scan"]

        self.assertEqual(len(baseline_scan["manifests"][0]), 500)
        self.assertEqual(
            set(baseline_scan["dependencyTrust"]),
            {"schemaVersion", "status", "packageManagers", "ecosystems"},
        )
        self.assertNotIn("entries", baseline_scan["dependencyTrust"])
        self.assertEqual(baseline_scan["findingCount"], 1)
        self.assertEqual(set(baseline_scan["findings"][0]), {"fingerprint"})
        self.assertRegex(baseline_scan["findings"][0]["fingerprint"], r"^cf1_")

    def test_baseline_management_mutates_only_reference_and_activity_tables(self) -> None:
        self.add_scan(1)
        self.add_scan(2)
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO finding_reviews (project_path, fingerprint, status, note, created_at, updated_at) "
                "VALUES (?, ?, 'reviewed', '', '2026-01-01', '2026-01-01')",
                (str(self.project), "cf1_" + "a" * 64),
            )
            before = {
                table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "scans",
                    "finding_reviews",
                    "project_trust_profiles",
                    "trusted_dependency_baselines",
                )
            }

        self.set_baseline(1)
        self.set_baseline(2, replace=True)
        main.clear_trusted_scan_baseline(ProjectPathRequest(project_path=str(self.project)))

        with database.get_connection() as connection:
            after = {
                table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in before
            }
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
