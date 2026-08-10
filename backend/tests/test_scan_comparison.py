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


class ScanComparisonTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.database_path = self.base / "glacial.db"
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.project = self.root / "project"
        self.other_project = self.root / "other"
        self.project.mkdir()
        self.other_project.mkdir()
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
            for path in (self.project, self.other_project):
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
        date: str,
        findings: object = None,
        complete: bool = True,
        dependency: object = None,
        metadata_overrides: dict[str, object] | None = None,
    ) -> None:
        issue_count = 0 if complete else 1
        metadata: dict[str, object] = {
            "manifests": ["package.json"],
            "lockfiles": ["package-lock.json"],
            "lifecycleScripts": [{"path": "package.json", "script": "test"}],
            "ignoredFiles": [".git"],
            "reviewedFiles": ["src/index.js"],
            "scanCompleteness": {
                "complete": complete,
                "traversalFailureCount": 0,
                "fileInspectionFailureCount": 0 if complete else 1,
                "oversizedFileCount": 0,
                "unsafePathCount": 0,
                "dependencyAnalysisFailureCount": 0,
                "policyExcludedFileCount": 1,
                "builtInExcludedDirectoryCount": 0,
                "unsupportedEncodingFileCount": 0,
                "resourceBudgetExceededCount": 0,
                "issueCount": issue_count + 1,
            },
            "dependencyTrust": dependency if dependency is not None else dependency_snapshot(),
        }
        if complete:
            metadata["scanCompleteness"]["issueCount"] = 1
            metadata["scanCompleteness"]["complete"] = False
            metadata["scanCompleteness"]["policyExcludedFileCount"] = 0
            metadata["scanCompleteness"]["issueCount"] = 0
            metadata["scanCompleteness"]["complete"] = True
        if metadata_overrides:
            metadata.update(metadata_overrides)
        findings_value = [] if findings is None else findings
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO scans (id, project_path, scan_date, overall_risk, findings_json, "
                "finding_count, reviewed_file_count, ignored_file_count, finding_summary_json, scan_metadata_json) "
                "VALUES (?, ?, ?, 'low', ?, ?, 1, 1, '{}', ?)",
                (
                    scan_id,
                    str(project or self.project),
                    date,
                    json.dumps(findings_value),
                    len(findings_value) if isinstance(findings_value, list) else 0,
                    json.dumps(metadata),
                ),
            )

    def compare(self, first: int, second: int) -> dict[str, object]:
        return main.compare_scans(str(self.project), first, second)

    def test_reverse_selection_orders_scans_and_comparison_is_read_only(self) -> None:
        self.add_scan(1, date="2026-05-01T12:00:00+00:00")
        self.add_scan(2, date="2026-05-02T12:00:00+00:00")
        with database.get_connection() as connection:
            before = {
                table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("scans", "finding_reviews", "project_activity_events")
            }

        result = self.compare(2, 1)

        self.assertEqual(result["baseScan"]["id"], 1)
        self.assertEqual(result["targetScan"]["id"], 2)
        with database.get_connection() as connection:
            after = {
                table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in before
            }
        self.assertEqual(after, before)

    def test_cross_project_comparison_is_rejected(self) -> None:
        self.add_scan(1, date="2026-05-01T12:00:00+00:00")
        self.add_scan(2, project=self.other_project, date="2026-05-02T12:00:00+00:00")

        with self.assertRaises(HTTPException) as error:
            self.compare(1, 2)

        self.assertEqual(error.exception.status_code, 403)

    def test_reliable_findings_report_added_resolved_changed_and_unchanged(self) -> None:
        self.add_scan(1, date="2026-05-01T12:00:00+00:00", findings=[
            finding("shared.js", "shared", "low"),
            finding("changed.js", "changed", "low"),
            finding("resolved.js", "resolved", "medium"),
        ])
        self.add_scan(2, date="2026-05-02T12:00:00+00:00", findings=[
            finding("shared.js", "shared", "low"),
            finding("changed.js", "changed", "high"),
            finding("added.js", "added", "medium"),
        ])

        section = self.compare(1, 2)["sections"]["findings"]

        self.assertEqual(section["status"], "comparable")
        self.assertEqual(section["counts"], {
            "added": 1,
            "resolved": 1,
            "changed": 1,
            "unchanged": 1,
        })

    def test_incomplete_target_never_reports_a_resolution(self) -> None:
        self.add_scan(1, date="2026-05-01T12:00:00+00:00", findings=[finding("gone.js", "gone")])
        self.add_scan(2, date="2026-05-02T12:00:00+00:00", findings=[], complete=False)

        section = self.compare(1, 2)["sections"]["findings"]

        self.assertEqual(section["status"], "partially-comparable")
        self.assertIsNone(section["counts"]["resolved"])
        self.assertEqual(section["examples"]["resolved"], [])

    def test_dependencies_report_added_removed_and_version_changed(self) -> None:
        self.add_scan(1, date="2026-05-01T12:00:00+00:00", dependency=dependency_snapshot(
            entry("alpha", "1.0.0"),
            entry("remove-me", "1.0.0"),
        ))
        self.add_scan(2, date="2026-05-02T12:00:00+00:00", dependency=dependency_snapshot(
            entry("alpha", "2.0.0"),
            entry("add-me", "1.0.0"),
        ))

        section = self.compare(1, 2)["sections"]["dependencies"]

        self.assertEqual(section["status"], "comparable")
        self.assertEqual(section["counts"]["added"], 1)
        self.assertEqual(section["counts"]["removed"], 1)
        self.assertEqual(section["counts"]["versionChanged"], 1)

    def test_malformed_coverage_and_unknown_history_are_conservative(self) -> None:
        self.add_scan(
            1,
            date="2026-05-01T12:00:00+00:00",
            findings={"unexpected": "object"},
        )
        malformed = {
            "manifests": "package.json",
            "scanCompleteness": {
                "complete": True,
                "traversalFailureCount": "zero",
            },
            "dependencyTrust": {"schemaVersion": 99, "status": "complete", "entries": []},
        }
        self.add_scan(
            2,
            date="2026-05-02T12:00:00+00:00",
            metadata_overrides=malformed,
        )

        result = self.compare(1, 2)

        self.assertEqual(result["sections"]["coverage"]["status"], "indeterminate")
        self.assertEqual(result["sections"]["findings"]["status"], "indeterminate")
        self.assertEqual(result["sections"]["dependencies"]["status"], "indeterminate")
        self.assertEqual(result["targetScan"]["completionState"], "unknown")
        self.assertFalse(result["targetScan"]["metadataSource"]["reliable"])
        self.assertNotEqual(result["overallStatus"], "comparable")

    def test_reduced_reviewed_paths_are_not_reliable_comparison_metadata(self) -> None:
        self.add_scan(1, date="2026-05-01T12:00:00+00:00")
        self.add_scan(
            2,
            date="2026-05-02T12:00:00+00:00",
            metadata_overrides={"reviewedFilesTruncated": True},
        )

        result = self.compare(1, 2)

        self.assertFalse(result["targetScan"]["metadataSource"]["reliable"])
        self.assertEqual(result["sections"]["projectMetadataStatus"], "indeterminate")
        self.assertNotEqual(result["overallStatus"], "comparable")


def finding(path: str, reason: str, severity: str = "low") -> dict[str, object]:
    return {
        "type": "example-rule",
        "path": path,
        "severity": severity,
        "reason": reason,
        "metadata": {"line": 4},
    }


def entry(name: str, version: str) -> dict[str, object]:
    return {
        "ecosystem": "node",
        "name": name,
        "group": "runtime",
        "direct": True,
        "lockedVersion": version,
    }


def dependency_snapshot(*entries: dict[str, object]) -> dict[str, object]:
    values = list(entries) if entries else [entry("alpha", "1.0.0")]
    return {
        "schemaVersion": 1,
        "status": "complete",
        "entries": values,
        "packageManagers": ["npm"],
        "ecosystems": ["node"],
    }


if __name__ == "__main__":
    unittest.main()
