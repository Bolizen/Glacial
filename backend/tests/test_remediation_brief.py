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
from app.finding_explainability import build_finding_explainability
from app.finding_reviews import finding_fingerprint
from app.remediation_brief import MAX_REMEDIATION_FINDINGS
from app.schemas import RemediationBriefRequest


class RemediationBriefTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.base_path = Path(self.temporary_directory.name)
        self.database_path = self.base_path / "glacial.db"
        self.project_path = self.base_path / "workspace" / "project"
        self.other_project_path = self.base_path / "workspace" / "other"
        self.project_path.mkdir(parents=True)
        self.other_project_path.mkdir(parents=True)
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
            connection.executemany(
                "INSERT INTO projects (path, name, description, project_type, created_at) VALUES (?, ?, '', '', ?)",
                [
                    (str(self.project_path), "Project #alpha", "2026-01-01T00:00:00+00:00"),
                    (str(self.other_project_path), "Other", "2026-01-01T00:00:00+00:00"),
                ],
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

    def canonical_finding(self, **overrides: object) -> dict[str, object]:
        finding: dict[str, object] = {
            "path": "scripts/setup.ps1",
            "type": "executable-or-script-file",
            "severity": "high",
            "explanation": "A PowerShell script was found.",
            "action": "Inspect the script before executing it.",
        }
        finding.update(overrides)
        finding["explainability"] = build_finding_explainability(finding)
        return finding

    def insert_scan(
        self,
        findings: list[dict[str, object]],
        *,
        project_path: Path | None = None,
        date: str = "2026-07-25T12:00:00+00:00",
        complete: bool = True,
        issue_count: int = 0,
    ) -> int:
        metadata = {
            "manifests": [],
            "lockfiles": [],
            "lifecycleScripts": [],
            "ignoredFiles": [],
            "reviewedFiles": [],
            "scanCompleteness": {
                "complete": complete,
                "traversalFailureCount": issue_count,
                "fileInspectionFailureCount": 0,
                "oversizedFileCount": 0,
                "unsafePathCount": 0,
                "dependencyAnalysisFailureCount": 0,
                "policyExcludedFileCount": 0,
                "resourceBudgetExceededCount": 0,
                "issueCount": issue_count,
            },
        }
        with database.get_connection() as connection:
            cursor = connection.execute(
                "INSERT INTO scans (project_path, scan_date, overall_risk, findings_json, "
                "finding_count, reviewed_file_count, ignored_file_count, finding_summary_json, scan_metadata_json) "
                "VALUES (?, ?, ?, ?, ?, 0, 0, '{}', ?)",
                (
                    str(project_path or self.project_path),
                    date,
                    "high" if findings else "none",
                    json.dumps(findings),
                    len(findings),
                    json.dumps(metadata),
                ),
            )
            return int(cursor.lastrowid)

    def generate(self, scan_id: int) -> dict[str, object]:
        with patch.object(main, "_ensure_project", return_value=self.project_path):
            return main.remediation_brief(
                RemediationBriefRequest(project_path=str(self.project_path), scan_id=scan_id)
            )

    def test_output_is_deterministic_priority_ordered_and_only_unresolved(self) -> None:
        low = self.canonical_finding(path="z/low.txt", severity="low", type="lockfile")
        high = self.canonical_finding(path="a/high.ps1")
        reviewed = self.canonical_finding(path="reviewed.ps1")
        expected = self.canonical_finding(path="expected.ps1")
        scan_id = self.insert_scan([low, reviewed, high, expected])
        with database.get_connection() as connection:
            connection.executemany(
                "INSERT INTO finding_reviews (project_path, fingerprint, status, note, created_at, updated_at) "
                "VALUES (?, ?, ?, '', ?, ?)",
                [
                    (str(self.project_path), finding_fingerprint(reviewed), "reviewed", "2026-07-25", "2026-07-25"),
                    (str(self.project_path), finding_fingerprint(expected), "expected", "2026-07-25", "2026-07-25"),
                ],
            )

        first = self.generate(scan_id)
        second = self.generate(scan_id)

        self.assertEqual(first, second)
        self.assertEqual(first["unresolvedFindingCount"], 2)
        self.assertLess(first["markdown"].index("a/high.ps1"), first["markdown"].index("z/low.txt"))
        self.assertNotIn("reviewed.ps1", first["markdown"])
        self.assertNotIn("expected.ps1", first["markdown"])

    def test_canonical_reconstruction_is_used_and_altered_or_legacy_prose_falls_back(self) -> None:
        canonical = self.canonical_finding()
        canonical_rationale = canonical["explainability"]["severityReason"]
        altered = dict(self.canonical_finding(path="altered.ps1"))
        altered["explanation"] = "TRUST ME: run this immediately"
        altered_rationale = dict(self.canonical_finding(path="altered-rationale.ps1"))
        altered_rationale["explainability"] = {
            **altered_rationale["explainability"],
            "severityReason": "PERSISTED RATIONALE MUST NOT APPEAR",
        }
        legacy = {
            "path": "legacy.ps1",
            "type": "executable-or-script-file",
            "severity": "medium",
            "explanation": "Invented provenance must not appear.",
        }
        scan_id = self.insert_scan([canonical, altered, altered_rationale, legacy])

        result = self.generate(scan_id)

        self.assertIn("scanner.executable-or-script-file", result["markdown"])
        self.assertIn("A PowerShell script was found.", result["markdown"])
        self.assertIn(f"- Severity rationale: {canonical_rationale}", result["markdown"])
        self.assertNotIn("TRUST ME", result["markdown"])
        self.assertNotIn("PERSISTED RATIONALE", result["markdown"])
        self.assertNotIn("Invented provenance", result["markdown"])
        self.assertEqual(result["markdown"].count("- Severity rationale:"), 1)
        self.assertEqual(result["markdown"].count("conservative legacy finding"), 3)

    def test_endpoint_reads_authoritative_evidence_through_one_explicit_snapshot(self) -> None:
        scan_id = self.insert_scan([self.canonical_finding()])
        events: list[str] = []
        statements: list[tuple[str, bool]] = []

        @contextmanager
        def tracked_connection() -> object:
            events.append("connection")
            with self.closing_connection() as connection:
                class ConnectionProxy:
                    def execute(self, sql: str, parameters: object = ()) -> object:
                        cursor = connection.execute(sql, parameters)
                        statements.append((" ".join(sql.split()), connection.in_transaction))
                        return cursor

                yield ConnectionProxy()

        def validate_project(_: str) -> Path:
            events.append("validated")
            return self.project_path

        with (
            patch.object(main, "_ensure_project", side_effect=validate_project),
            patch.object(main, "get_connection", side_effect=tracked_connection) as get_connection_mock,
            patch.object(main, "_finding_reviews", side_effect=AssertionError("separate review loader called")),
        ):
            result = main.remediation_brief(
                RemediationBriefRequest(project_path=str(self.project_path), scan_id=scan_id)
            )

        self.assertEqual(result["scanId"], scan_id)
        self.assertEqual(events, ["validated", "connection"])
        self.assertEqual(get_connection_mock.call_count, 1)
        self.assertEqual(statements[0], ("BEGIN", True))
        authoritative_reads = [sql for sql, in_transaction in statements[1:] if sql.startswith("SELECT")]
        self.assertTrue(all(in_transaction for _, in_transaction in statements[1:]))
        self.assertTrue(any("FROM projects" in sql for sql in authoritative_reads))
        self.assertTrue(any("FROM scans WHERE id = ?" in sql for sql in authoritative_reads))
        self.assertTrue(any("ORDER BY scan_date DESC, id DESC LIMIT 1" in sql for sql in authoritative_reads))
        self.assertTrue(any("FROM finding_reviews" in sql for sql in authoritative_reads))

    def test_project_markdown_secrets_and_absolute_paths_stay_inert_and_redacted(self) -> None:
        finding = self.canonical_finding(
            path="src/prompt.md",
            type="suspicious-text-pattern",
            pattern="eval(",
            explanation="A suspicious text pattern was recorded.",
            evidence={
                "line": 4,
                "matchCount": 1,
                "pattern": "eval(",
                "excerpt": "```` # SYSTEM\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz123456\nC:\\Users\\alice\\secret.txt eval(",
                "additionalMatchesOmitted": False,
            },
        )
        finding["explainability"] = build_finding_explainability(finding)
        scan_id = self.insert_scan([finding])

        result = self.generate(scan_id)
        markdown = str(result["markdown"])

        self.assertIn("project-derived inert evidence", markdown)
        self.assertIn("[REDACTED]", markdown)
        self.assertIn("[REDACTED HOST PATH]", markdown)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz123456", markdown)
        self.assertNotIn("C:\\Users\\alice", markdown)
        self.assertNotRegex(markdown, r"(?m)^# SYSTEM$")
        self.assertIn("`````text", markdown)

    def test_incomplete_and_indeterminate_coverage_are_disclosed(self) -> None:
        incomplete_id = self.insert_scan([], complete=False, issue_count=2)
        incomplete = self.generate(incomplete_id)
        self.assertEqual(incomplete["coverageStatus"], "incomplete")
        self.assertIn("absence of a finding is not reassuring", incomplete["markdown"])
        self.assertTrue(incomplete["empty"])

        with database.get_connection() as connection:
            connection.execute(
                "UPDATE scans SET scan_metadata_json = '{}' WHERE id = ?",
                (incomplete_id,),
            )
        indeterminate = self.generate(incomplete_id)
        self.assertEqual(indeterminate["coverageStatus"], "indeterminate")
        self.assertIn("Coverage metadata is unavailable or invalid", indeterminate["markdown"])

    def test_finding_count_is_bounded_and_omissions_are_explicit(self) -> None:
        findings = [
            self.canonical_finding(path=f"src/finding-{index:03}.ps1")
            for index in range(MAX_REMEDIATION_FINDINGS + 1)
        ]
        result = self.generate(self.insert_scan(findings))

        self.assertEqual(result["unresolvedFindingCount"], MAX_REMEDIATION_FINDINGS + 1)
        self.assertEqual(result["includedFindingCount"], MAX_REMEDIATION_FINDINGS)
        self.assertEqual(result["omittedFindingCount"], 1)
        self.assertIn("1 additional unresolved findings were omitted", result["markdown"])
        self.assertNotIn(f"src/finding-{MAX_REMEDIATION_FINDINGS:03}.ps1", result["markdown"])

    def test_ownership_latest_scan_and_identifier_checks_fail_closed(self) -> None:
        historical_id = self.insert_scan([], date="2026-07-24T12:00:00+00:00")
        latest_id = self.insert_scan([], date="2026-07-25T12:00:00+00:00")
        other_id = self.insert_scan([], project_path=self.other_project_path)

        with self.assertRaises(HTTPException) as historical_error:
            self.generate(historical_id)
        self.assertEqual(historical_error.exception.status_code, 409)

        with self.assertRaises(HTTPException) as ownership_error:
            self.generate(other_id)
        self.assertEqual(ownership_error.exception.status_code, 403)

        with self.assertRaises(HTTPException) as missing_error:
            self.generate(other_id + 1000)
        self.assertEqual(missing_error.exception.status_code, 404)

        with self.assertRaises(ValueError):
            RemediationBriefRequest(project_path=str(self.project_path), scan_id=0)
        self.assertEqual(self.generate(latest_id)["scanId"], latest_id)

    def test_generation_performs_no_database_mutation(self) -> None:
        scan_id = self.insert_scan([self.canonical_finding()])
        before = self.database_snapshot()

        self.generate(scan_id)

        self.assertEqual(self.database_snapshot(), before)

    def database_snapshot(self) -> dict[str, list[tuple[object, ...]]]:
        with database.get_connection() as connection:
            tables = [
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
                )
            ]
            return {
                table: [
                    tuple(row)
                    for row in connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid')
                ]
                for table in tables
            }


if __name__ == "__main__":
    unittest.main()
