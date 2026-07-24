from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from app import database, main
from app.finding_reviews import finding_fingerprint
from app.schemas import (
    FindingReviewDelete,
    FindingReviewRequest,
    ProjectPathRequest,
    TrustProfileRequest,
    TrustedDependencyBaselineApprove,
)


class ProjectActivityTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.database_path = self.base / "glacial.db"
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.project = self.root / "project"
        self.project.mkdir()
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
            connection.execute(
                "INSERT INTO projects (path, name, created_at) VALUES (?, ?, ?)",
                (str(self.project), self.project.name, "2026-01-01T00:00:00+00:00"),
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

    def events(self) -> list[dict[str, object]]:
        return main.project_activity(str(self.project), limit=50, offset=0)["events"]

    def stored_events(self, event_type: str) -> list[dict[str, object]]:
        return [event for event in self.events() if event["eventType"] == event_type]

    def test_material_expectation_update_records_once_and_no_op_or_dismissal_does_not(self) -> None:
        with patch.object(main, "_now", return_value="2026-04-01T10:00:00+00:00"):
            first = main.update_trust_profile(TrustProfileRequest(
                project_path=str(self.project),
                expectedManifestFiles=["package.json"],
            ))
            repeated = main.update_trust_profile(TrustProfileRequest(
                project_path=str(self.project),
                expectedManifestFiles=["package.json"],
            ))
            dismissed = main.update_trust_profile(TrustProfileRequest(
                project_path=str(self.project),
                expectedManifestFiles=["package.json"],
                dismissedSuggestions={"expectedLockfiles": ["pnpm-lock.yaml"]},
            ))

        self.assertTrue(first["activity_recorded"])
        self.assertFalse(repeated["activity_recorded"])
        self.assertFalse(dismissed["activity_recorded"])
        events = self.stored_events("project_expectations_updated")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["details"], {
            "changedCategories": ["expectedManifestFiles"],
            "reviewContextChanged": False,
        })

    def test_drift_adoption_records_one_distinct_bounded_event_transactionally(self) -> None:
        main.update_trust_profile(TrustProfileRequest(
            project_path=str(self.project),
            expectedManifestFiles=["package.json"],
        ))
        (self.project / "pyproject.toml").write_text(
            "[project]\nname = \"sample\"\nversion = \"1.0.0\"\n",
            encoding="utf-8",
        )
        main.run_scan(ProjectPathRequest(project_path=str(self.project)))
        request = TrustProfileRequest(
            project_path=str(self.project),
            expectedManifestFiles=["pyproject.toml"],
            expectationProvenance={
                "expectedManifestFiles": {"pyproject.toml": "accepted-suggestion"},
            },
            activity_context={
                "type": "observed_drift_adopted",
                "category": "expectedManifestFiles",
                "adopted_value": "pyproject.toml",
                "replaced_value": "package.json",
            },
        )
        adopted = main.update_trust_profile(request)
        repeated = main.update_trust_profile(request)

        self.assertTrue(adopted["activity_recorded"])
        self.assertFalse(repeated["activity_recorded"])
        events = self.stored_events("observed_drift_adopted")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["details"], {
            "category": "expectedManifestFiles",
            "adoptedValue": "pyproject.toml",
            "replacedValue": "package.json",
        })
        self.assertNotIn("expectationProvenance", events[0]["details"])

        empty_project = self.root / "rollback"
        empty_project.mkdir()
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO projects (path, name, created_at) VALUES (?, ?, ?)",
                (str(empty_project), empty_project.name, "2026-01-01T00:00:00+00:00"),
            )
        with patch.object(main, "append_activity_event", side_effect=RuntimeError("activity write failed")):
            with self.assertRaises(RuntimeError):
                main.update_trust_profile(TrustProfileRequest(
                    project_path=str(empty_project),
                    expectedManifestFiles=["package.json"],
                ))
        with database.get_connection() as connection:
            self.assertIsNone(connection.execute(
                "SELECT 1 FROM project_trust_profiles WHERE project_path = ?",
                (str(empty_project),),
            ).fetchone())

    def test_finding_review_completion_is_recorded_only_on_first_completed_transition(self) -> None:
        findings = [
            {"type": "test", "path": "one.py", "severity": "low"},
            {"type": "test", "path": "two.py", "severity": "medium"},
        ]
        with database.get_connection() as connection:
            cursor = connection.execute(
                "INSERT INTO scans (project_path, scan_date, overall_risk, findings_json) VALUES (?, ?, ?, ?)",
                (str(self.project), "2026-05-01T00:00:00+00:00", "medium", json.dumps(findings)),
            )
            scan_id = cursor.lastrowid
        fingerprints = [finding_fingerprint(finding) for finding in findings]

        first = main.update_finding_review(FindingReviewRequest(
            project_path=str(self.project),
            scan_id=scan_id,
            fingerprint=fingerprints[0],
            status="reviewed",
        ))
        second = main.update_finding_review(FindingReviewRequest(
            project_path=str(self.project),
            scan_id=scan_id,
            fingerprint=fingerprints[1],
            status="expected",
        ))
        repeated = main.update_finding_review(FindingReviewRequest(
            project_path=str(self.project),
            scan_id=scan_id,
            fingerprint=fingerprints[1],
            status="reviewed",
        ))
        main.delete_finding_review(FindingReviewDelete(
            project_path=str(self.project),
            fingerprint=fingerprints[1],
        ))
        completed_again = main.update_finding_review(FindingReviewRequest(
            project_path=str(self.project),
            scan_id=scan_id,
            fingerprint=fingerprints[1],
            status="reviewed",
        ))

        self.assertFalse(first["activity_recorded"])
        self.assertTrue(second["activity_recorded"])
        self.assertFalse(repeated["activity_recorded"])
        self.assertFalse(completed_again["activity_recorded"])
        events = self.stored_events("finding_review_completed")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["relatedScanId"], scan_id)
        self.assertEqual(events[0]["details"], {
            "reviewedCount": 2,
            "totalFindingCount": 2,
        })

    def test_dependency_approval_records_only_the_meaningful_transition(self) -> None:
        (self.project / "package.json").write_text(
            json.dumps({"dependencies": {"alpha": "1.0.0"}}),
            encoding="utf-8",
        )
        (self.project / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"alpha": "1.0.0"}},
                "node_modules/alpha": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz",
                    "integrity": "sha512-AAAA",
                },
            },
        }), encoding="utf-8")
        scan = main.run_scan(ProjectPathRequest(project_path=str(self.project)))
        fingerprint = scan["dependencyTrust"]["trustedBaseline"]["approval"]["fingerprint"]
        request = TrustedDependencyBaselineApprove(
            project_path=str(self.project),
            scan_id=scan["id"],
            fingerprint=fingerprint,
        )
        main.approve_trusted_dependency_baseline(request)
        main.approve_trusted_dependency_baseline(TrustedDependencyBaselineApprove(
            project_path=str(self.project),
            scan_id=scan["id"],
            fingerprint=fingerprint,
            replace=True,
        ))

        events = self.stored_events("dependency_review_completed")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["relatedScanId"], scan["id"])
        self.assertEqual(events[0]["details"], {"status": "approved"})

    def test_timeline_orders_paginates_and_sanitizes_malformed_history(self) -> None:
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO scans (project_path, scan_date, overall_risk, findings_json) VALUES (?, ?, 'none', '[]')",
                (str(self.project), "2026-02-01T00:00:00+00:00"),
            )
            connection.execute(
                "INSERT INTO scans (project_path, scan_date, overall_risk, findings_json) VALUES (?, ?, 'low', '[]')",
                (str(self.project), "2026-03-01T00:00:00+00:00"),
            )
            connection.execute(
                "INSERT INTO project_activity_events "
                "(event_id, project_id, event_type, occurred_at, details_json) VALUES (?, ?, ?, ?, ?)",
                (
                    "evt_unknown",
                    str(self.project),
                    "future_event",
                    "2026-04-01T00:00:00+00:00",
                    '{"unexpected":["safe"],"nested":{"ignored":"value"}}',
                ),
            )

        first = main.project_activity(str(self.project), limit=2, offset=0)
        second = main.project_activity(str(self.project), limit=2, offset=2)

        self.assertEqual([event["eventType"] for event in first["events"]], ["future_event", "scan_completed"])
        self.assertTrue(first["has_more"])
        self.assertEqual(first["next_offset"], 2)
        self.assertEqual([event["eventType"] for event in second["events"]], ["scan_completed", "project_registered"])
        self.assertFalse(second["has_more"])
        malformed = first["events"][0]
        self.assertTrue(malformed["malformed"])
        self.assertEqual(malformed["details"], {})


if __name__ == "__main__":
    unittest.main()
