from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from app import database, main, review_checkpoints
from app.schemas import (
    FindingReviewRequest,
    ProjectPathRequest,
    ReviewCheckpointCreate,
    TrustProfileRequest,
    TrustedDependencyBaselineApprove,
)


class ReviewCheckpointTests(unittest.TestCase):
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
        self._register(self.project)

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

    def test_creation_is_atomic_records_one_event_and_identical_evidence_is_a_no_op(self) -> None:
        scan = self._ready_scan()
        page = self._page()
        request = self._request(scan["id"], page)

        with patch.object(main, "_now", return_value="2026-08-01T10:00:00+00:00"):
            created = main.record_review_checkpoint(request)
            duplicate = main.record_review_checkpoint(request)

        self.assertTrue(created["created"])
        self.assertTrue(created["activityRecorded"])
        self.assertEqual(created["state"]["id"], "current")
        self.assertFalse(duplicate["created"])
        self.assertFalse(duplicate["activityRecorded"])
        events = main.project_activity(str(self.project), limit=50, offset=0)["events"]
        checkpoint_events = [
            event
            for event in events
            if event["eventType"] == "review_checkpoint_created"
        ]
        self.assertEqual(len(checkpoint_events), 1)
        self.assertFalse(checkpoint_events[0]["malformed"])
        self.assertEqual(checkpoint_events[0]["relatedScanId"], scan["id"])
        self.assertEqual(checkpoint_events[0]["details"]["provenance"], "manual")
        with database.get_connection() as connection:
            self.assertEqual(connection.execute(
                "SELECT COUNT(*) FROM project_review_checkpoints WHERE project_id = ?",
                (str(self.project),),
            ).fetchone()[0], 1)
            self.assertEqual(connection.execute(
                "SELECT COUNT(*) FROM project_activity_events "
                "WHERE project_id = ? AND event_type = 'review_checkpoint_created'",
                (str(self.project),),
            ).fetchone()[0], 1)

        newer = main.run_scan(ProjectPathRequest(project_path=str(self.project)))
        newer_page = self._page()
        self.assertTrue(newer_page["currentEvidence"]["readyForCheckpoint"])
        with patch.object(
            review_checkpoints,
            "append_activity_event",
            side_effect=RuntimeError("activity insert failed"),
        ):
            with self.assertRaises(RuntimeError):
                main.record_review_checkpoint(self._request(newer["id"], newer_page))
        with database.get_connection() as connection:
            self.assertEqual(connection.execute(
                "SELECT COUNT(*) FROM project_review_checkpoints WHERE project_id = ?",
                (str(self.project),),
            ).fetchone()[0], 1)

    def test_ineligible_stale_and_cross_project_submissions_are_rejected(self) -> None:
        scan = self._ready_scan()
        ready_page = self._page()
        ready_fingerprint = ready_page["currentEvidence"]["evidenceFingerprint"]

        main.update_trust_profile(TrustProfileRequest(
            project_path=str(self.project),
            expectedManifestFiles=["different.json"],
        ))
        ineligible = self._page()
        self.assertFalse(ineligible["currentEvidence"]["readyForCheckpoint"])
        with self.assertRaises(HTTPException) as stale_error:
            main.record_review_checkpoint(ReviewCheckpointCreate(
                project_path=str(self.project),
                scan_id=scan["id"],
                expected_evidence_fingerprint=ready_fingerprint,
                security_status="ready",
            ))
        self.assertEqual(stale_error.exception.status_code, 409)

        other = self.root / "other"
        other.mkdir()
        self._register(other)
        other_scan = self._scan(other)
        with self.assertRaises(HTTPException) as ownership_error:
            main.record_review_checkpoint(ReviewCheckpointCreate(
                project_path=str(self.project),
                scan_id=other_scan["id"],
                expected_evidence_fingerprint=ineligible["currentEvidence"]["evidenceFingerprint"],
                security_status="ready",
            ))
        self.assertEqual(ownership_error.exception.status_code, 403)

    def test_no_supported_dependency_metadata_is_explicitly_not_applicable_and_eligible(self) -> None:
        (self.project / "README.md").write_text("Project documentation.", encoding="utf-8")
        scan = main.run_scan(ProjectPathRequest(project_path=str(self.project)))
        self.assertEqual(scan["dependencyTrust"]["status"], "unsupported")
        main.update_trust_profile(TrustProfileRequest(
            project_path=str(self.project),
            reviewedPaths=scan["reviewedFiles"],
        ))

        page = self._page()
        evidence = page["currentEvidence"]
        self.assertTrue(evidence["reliable"], evidence)
        self.assertTrue(evidence["readyForCheckpoint"], evidence)
        self.assertEqual(evidence["dependencyApprovalState"], "not-applicable")
        self.assertRegex(evidence["dependencyAnalysisFingerprint"], r"^cpda1_")
        self.assertEqual(evidence["dependencyApprovalFingerprint"], "")

        created = main.record_review_checkpoint(self._request(scan["id"], page))
        self.assertTrue(created["created"])
        self.assertEqual(created["state"]["id"], "current")

    def test_new_reviewed_high_finding_and_malformed_baseline_cannot_be_bypassed_by_ready_request(self) -> None:
        baseline = self._ready_scan()
        current = self._insert_scan_after(
            baseline,
            findings=[{
                "type": "test-high",
                "path": "src/high.js",
                "severity": "high",
                "explanation": "Focused parity fixture.",
            }],
        )
        current_scan = main.scan_history(str(self.project))["scans"][0]
        main.update_finding_review(FindingReviewRequest(
            project_path=str(self.project),
            scan_id=current,
            fingerprint=current_scan["findings"][0]["fingerprint"],
            status="expected",
        ))

        blocked = self._page()
        evidence = blocked["currentEvidence"]
        self.assertTrue(evidence["reliable"], evidence)
        self.assertFalse(evidence["readyForCheckpoint"])
        self.assertEqual(evidence["newCriticalHighCount"], 1)
        with self.assertRaises(HTTPException) as bypass_error:
            main.record_review_checkpoint(self._request(current, blocked))
        self.assertEqual(bypass_error.exception.status_code, 409)
        with database.get_connection() as connection:
            self.assertEqual(connection.execute(
                "SELECT COUNT(*) FROM project_review_checkpoints WHERE project_id = ?",
                (str(self.project),),
            ).fetchone()[0], 0)
            self.assertEqual(connection.execute(
                "SELECT COUNT(*) FROM project_activity_events "
                "WHERE project_id = ? AND event_type = 'review_checkpoint_created'",
                (str(self.project),),
            ).fetchone()[0], 0)

        with database.get_connection() as connection:
            connection.execute(
                "UPDATE scans SET finding_count = finding_count + 1 WHERE id = ?",
                (baseline["id"],),
            )
        malformed = self._page()
        self.assertFalse(malformed["currentEvidence"]["reliable"])
        self.assertRegex(
            " ".join(malformed["currentEvidence"]["reasons"]),
            r"baseline evidence",
        )

    def test_newer_scan_requires_review_and_malformed_current_or_historical_evidence_is_indeterminate(self) -> None:
        scan = self._ready_scan()
        created = main.record_review_checkpoint(self._request(scan["id"], self._page()))
        checkpoint_id = created["checkpoint"]["checkpointId"]

        with database.get_connection() as connection:
            row = connection.execute(
                "SELECT scan_metadata_json FROM scans WHERE id = ?",
                (scan["id"],),
            ).fetchone()
            original_metadata = row["scan_metadata_json"]
            metadata = json.loads(original_metadata)
            metadata["scanCompleteness"]["complete"] = False
            metadata["scanCompleteness"]["fileInspectionFailureCount"] = 1
            metadata["scanCompleteness"]["issueCount"] = 1
            connection.execute(
                "UPDATE scans SET scan_metadata_json = ? WHERE id = ?",
                (json.dumps(metadata), scan["id"]),
            )
        incomplete = self._page()
        self.assertEqual(incomplete["state"]["id"], "review-required")
        self.assertRegex(" ".join(incomplete["state"]["reasons"]), r"Coverage")
        with database.get_connection() as connection:
            connection.execute(
                "UPDATE scans SET scan_metadata_json = ? WHERE id = ?",
                (original_metadata, scan["id"]),
            )

        main.run_scan(ProjectPathRequest(project_path=str(self.project)))
        stale = self._page()
        self.assertEqual(stale["state"]["id"], "review-required")
        self.assertRegex(stale["state"]["reasons"][0], r"different latest scan")

        with database.get_connection() as connection:
            original_count = connection.execute(
                "SELECT finding_count FROM scans WHERE id = ?",
                (scan["id"],),
            ).fetchone()["finding_count"]
            connection.execute(
                "UPDATE scans SET finding_count = ? WHERE id = ?",
                (original_count + 1, scan["id"]),
            )
        malformed_baseline = self._page()
        self.assertEqual(malformed_baseline["state"]["id"], "indeterminate")
        self.assertRegex(
            " ".join(malformed_baseline["state"]["reasons"]),
            r"baseline evidence",
        )
        with database.get_connection() as connection:
            connection.execute(
                "UPDATE scans SET finding_count = ? WHERE id = ?",
                (original_count, scan["id"]),
            )

        with database.get_connection() as connection:
            latest = connection.execute(
                "SELECT id FROM scans WHERE project_path = ? ORDER BY scan_date DESC, id DESC LIMIT 1",
                (str(self.project),),
            ).fetchone()
            connection.execute(
                "UPDATE scans SET scan_metadata_json = '{}' WHERE id = ?",
                (latest["id"],),
            )
        indeterminate = self._page()
        self.assertEqual(indeterminate["state"]["id"], "indeterminate")
        self.assertRegex(" ".join(indeterminate["state"]["reasons"]), r"Coverage metadata")

        with database.get_connection() as connection:
            connection.execute(
                "DELETE FROM scans WHERE id = ?",
                (latest["id"],),
            )
            connection.execute(
                "UPDATE project_review_checkpoints SET evaluator_version = 999 "
                "WHERE checkpoint_id = ?",
                (checkpoint_id,),
            )
        malformed_history = self._page()
        self.assertEqual(malformed_history["state"]["id"], "indeterminate")
        self.assertRegex(malformed_history["state"]["reasons"][0], r"unsupported")

    def test_reduced_reviewed_paths_cannot_supply_checkpoint_baseline_evidence(self) -> None:
        baseline = self._ready_scan()
        with database.get_connection() as connection:
            row = connection.execute(
                "SELECT scan_metadata_json FROM scans WHERE id = ?",
                (baseline["id"],),
            ).fetchone()
            metadata = json.loads(row["scan_metadata_json"])
            metadata["reviewedFilesTruncated"] = True
            connection.execute(
                "UPDATE scans SET scan_metadata_json = ? WHERE id = ?",
                (json.dumps(metadata), baseline["id"]),
            )

        current = main.run_scan(ProjectPathRequest(project_path=str(self.project)))
        page = self._page()
        evidence = page["currentEvidence"]
        self.assertTrue(evidence["reliable"], evidence)
        self.assertTrue(evidence["readyForCheckpoint"], evidence)
        self.assertIsNone(evidence["baselineScanId"])
        self.assertEqual(evidence["baselineProvenance"], "none")

        with database.get_connection() as connection:
            row = connection.execute(
                "SELECT scan_metadata_json FROM scans WHERE id = ?",
                (current["id"],),
            ).fetchone()
            metadata = json.loads(row["scan_metadata_json"])
            metadata["reviewedFilesTruncated"] = True
            connection.execute(
                "UPDATE scans SET scan_metadata_json = ? WHERE id = ?",
                (json.dumps(metadata), current["id"]),
            )

        reduced_current = self._page()["currentEvidence"]
        self.assertFalse(reduced_current["reliable"])
        self.assertRegex(" ".join(reduced_current["reasons"]), r"metadata is unreliable")

    def _register(self, project: Path) -> None:
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO projects (path, name, created_at) VALUES (?, ?, ?)",
                (str(project), project.name, "2026-01-01T00:00:00+00:00"),
            )

    def _ready_scan(self) -> dict[str, object]:
        scan = self._scan(self.project)
        for finding in scan["findings"]:
            main.update_finding_review(FindingReviewRequest(
                project_path=str(self.project),
                scan_id=scan["id"],
                fingerprint=finding["fingerprint"],
                status="expected",
            ))
        scan = main.scan_history(str(self.project))["scans"][0]
        approval = scan["dependencyTrust"]["trustedBaseline"]["approval"]
        main.approve_trusted_dependency_baseline(TrustedDependencyBaselineApprove(
            project_path=str(self.project),
            scan_id=scan["id"],
            fingerprint=approval["fingerprint"],
        ))
        main.update_trust_profile(TrustProfileRequest(
            project_path=str(self.project),
            trustedPackageManagers=scan["dependencyTrust"]["packageManagers"],
            expectedManifestFiles=scan["manifests"],
            expectedLockfiles=scan["lockfiles"],
            allowedLifecycleScripts=[
                item["script"]
                for item in scan["lifecycleScripts"]
            ],
            expectedEcosystems=scan["dependencyTrust"]["ecosystems"],
            reviewedPaths=scan["reviewedFiles"],
            ignoredPaths=scan["ignoredFiles"],
        ))
        page = self._page()
        self.assertTrue(page["currentEvidence"]["readyForCheckpoint"], page["currentEvidence"])
        return scan

    def _scan(self, project: Path) -> dict[str, object]:
        (project / "package.json").write_text(
            json.dumps({"dependencies": {"alpha": "1.0.0"}}),
            encoding="utf-8",
        )
        (project / "package-lock.json").write_text(json.dumps({
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
        return main.run_scan(ProjectPathRequest(project_path=str(project)))

    def _page(self) -> dict[str, object]:
        return main.review_checkpoints(str(self.project), limit=5, offset=0)

    def _insert_scan_after(
        self,
        source: dict[str, object],
        *,
        findings: list[dict[str, object]],
    ) -> int:
        source_date = datetime.fromisoformat(str(source["scan_date"]).replace("Z", "+00:00"))
        later_date = (source_date + timedelta(seconds=1)).isoformat()
        with database.get_connection() as connection:
            row = connection.execute(
                "SELECT * FROM scans WHERE id = ?",
                (source["id"],),
            ).fetchone()
            cursor = connection.execute(
                "INSERT INTO scans ("
                "project_path, scan_date, overall_risk, findings_json, finding_count, "
                "reviewed_file_count, ignored_file_count, finding_summary_json, scan_metadata_json"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(self.project),
                    later_date,
                    "high" if findings else "low",
                    json.dumps(findings),
                    len(findings),
                    row["reviewed_file_count"],
                    row["ignored_file_count"],
                    json.dumps({"test-high": len(findings)} if findings else {}),
                    row["scan_metadata_json"],
                ),
            )
            return int(cursor.lastrowid)

    def _request(
        self,
        scan_id: int,
        page: dict[str, object],
    ) -> ReviewCheckpointCreate:
        return ReviewCheckpointCreate(
            project_path=str(self.project),
            scan_id=scan_id,
            expected_evidence_fingerprint=page["currentEvidence"]["evidenceFingerprint"],
            security_status="ready",
        )
