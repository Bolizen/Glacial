from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError

from app import database, main
from app.privacy import sanitize_scan_value
from app.schemas import ProjectPathRequest, TrustedDependencyBaselineApprove, TrustedDependencyBaselineNote
from app.trusted_dependency_baseline import (
    BASELINE_SCHEMA_VERSION,
    BaselineError,
    MAX_ENTRIES,
    approval_for_analysis,
    compare_with_baseline,
    public_baseline,
    snapshot_fingerprint,
    snapshot_from_analysis,
    snapshot_json,
)


INTEGRITY_A = "sha256:" + ("a" * 64)
INTEGRITY_B = "sha256:" + ("b" * 64)


def analysis(entries: list[dict[str, object]] | None = None, **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schemaVersion": 1,
        "status": "complete",
        "ecosystems": ["node"],
        "manifests": ["package.json"],
        "lockfiles": ["package-lock.json"],
        "packageManagers": ["npm"],
        "entries": entries or [],
    }
    value.update(overrides)
    return value


def entry(name: str, *, direct: bool = True, **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "ecosystem": "node",
        "name": name,
        "group": "dependencies",
        "requestedSpecification": "1.0.0" if direct else "",
        "lockedVersion": "1.0.0",
        "sourceType": "registry",
        "sourceIdentifier": "registry.npmjs.org",
        "integrity": INTEGRITY_A,
        "integrityPresent": True,
        "direct": direct,
        "optional": False,
        "dev": False,
        "peer": False,
        "installScriptIndicator": False,
        "manifestPath": "package.json" if direct else "",
        "lockfilePath": "package-lock.json",
    }
    value.update(overrides)
    return value


def baseline_row(snapshot: dict[str, object], project: str = "C:/workspace/project") -> dict[str, object]:
    return {
        "project_path": project,
        "baseline_schema_version": BASELINE_SCHEMA_VERSION,
        "dependency_schema_version": 1,
        "fingerprint": snapshot_fingerprint(snapshot),
        "snapshot_json": snapshot_json(snapshot),
        "source_scan_id": 1,
        "source_scan_date": "2026-07-13T10:00:00+00:00",
        "note": "Approved locally.",
        "created_at": "2026-07-13T10:00:00+00:00",
        "updated_at": "2026-07-13T10:00:00+00:00",
    }


def vcs_identity(selector: str, value: str) -> str:
    return f"{selector}:sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


class BaselineIdentityTests(unittest.TestCase):
    def test_fingerprint_is_order_stable_bounded_and_schema_versioned(self) -> None:
        first = snapshot_from_analysis(analysis([
            entry("beta", direct=False),
            entry("alpha", optional=False),
        ], ecosystems=["python", "node"], packageManagers=["pip", "npm"]))
        second = snapshot_from_analysis(analysis([
            entry("alpha", optional=False),
            entry("beta", direct=False),
        ], ecosystems=["node", "python"], packageManagers=["npm", "pip"]))
        self.assertEqual(snapshot_fingerprint(first), snapshot_fingerprint(second))
        self.assertRegex(snapshot_fingerprint(first), r"^cfdb2_[0-9a-f]{64}$")
        incompatible = {**first, "baselineSchemaVersion": 1}
        with self.assertRaises(BaselineError):
            snapshot_fingerprint(incompatible)

    def test_vcs_revision_identity_is_stable_distinct_and_schema_versioned(self) -> None:
        original = analysis([entry(
            "vcsdep", sourceType="vcs", sourceIdentifier="github.com",
            requestedSpecification="https://github.com/org/repo.git",
            vcsRequestedRevision=vcs_identity("rev", "revision-one"),
            vcsLockedRevision=vcs_identity("reference", "revision-one"),
            vcsResolvedRevision=vcs_identity("resolved", "a" * 40),
        )])
        identical = analysis([dict(original["entries"][0])])
        changed = analysis([entry(
            "vcsdep", sourceType="vcs", sourceIdentifier="github.com",
            requestedSpecification="https://github.com/org/repo.git",
            vcsRequestedRevision=vcs_identity("rev", "revision-two"),
            vcsLockedRevision=vcs_identity("reference", "revision-two"),
            vcsResolvedRevision=vcs_identity("resolved", "b" * 40),
        )])
        tagged = analysis([entry(
            "vcsdep", sourceType="vcs", sourceIdentifier="github.com",
            requestedSpecification="https://github.com/org/repo.git",
            vcsRequestedRevision=vcs_identity("tag", "revision-one"),
        )])

        original_snapshot = snapshot_from_analysis(original)
        original_fingerprint = snapshot_fingerprint(original_snapshot)
        self.assertEqual(original_fingerprint, snapshot_fingerprint(snapshot_from_analysis(identical)))
        self.assertNotEqual(original_fingerprint, snapshot_fingerprint(snapshot_from_analysis(changed)))
        self.assertNotEqual(original_fingerprint, snapshot_fingerprint(snapshot_from_analysis(tagged)))
        drift = compare_with_baseline(changed, baseline_row(original_snapshot))
        self.assertEqual(drift["status"], "drift")
        self.assertIn("vcs-revision-changed", {change["changeType"] for change in drift["changes"]})

    def test_privacy_canonicalization_cannot_manufacture_trusted_identity(self) -> None:
        project_root = r"C:\workspace\project"

        def sanitized(candidate: dict[str, object]) -> dict[str, object]:
            return sanitize_scan_value(
                analysis([candidate]),
                project_root=project_root,
            )

        unsafe = (
            entry(
                "vcsdep",
                sourceType="vcs",
                sourceIdentifier="vcs:github.com/owner/repository",
                requestedSpecification="github:owner/repository#private-selector",
                integrity="",
                integrityPresent=False,
            ),
            entry(
                "urldep",
                sourceType="url",
                sourceIdentifier="packages.example",
                requestedSpecification="https://packages.example/archive.whl#sha256=private",
                integrity="",
                integrityPresent=False,
            ),
            entry(
                "unknown-dep",
                sourceType="unknown",
                sourceIdentifier="",
                requestedSpecification="unknown:owner/repository#private-selector",
                integrity="",
                integrityPresent=False,
            ),
            entry(
                "malformed-dep",
                sourceType="vcs",
                sourceIdentifier="vcs:github.com/owner/repository",
                requestedSpecification="https:/user:password@github.com/owner/repository#private",
                integrity="",
                integrityPresent=False,
            ),
            entry(
                "local-dep",
                sourceType="local",
                sourceIdentifier="local:cache",
                requestedSpecification="file:C:/Users/private/cache",
                integrity="",
                integrityPresent=False,
            ),
            entry("path-dep", manifestPath=r"C:\Users\private\package.json"),
        )
        for candidate in unsafe:
            with self.subTest(candidate=candidate):
                approval = approval_for_analysis(sanitized(candidate))
                self.assertFalse(approval["eligible"])
                self.assertEqual(approval["fingerprint"], "")

        vcs_control = sanitized(entry(
            "vcs-control",
            sourceType="vcs",
            sourceIdentifier="vcs:github.com/owner/repository",
            requestedSpecification="github:owner/repository#private-selector",
            vcsRequestedRevision=vcs_identity("ref", "private-selector"),
            integrity="",
            integrityPresent=False,
        ))
        url_control = sanitized(entry(
            "url-control",
            sourceType="url",
            sourceIdentifier="packages.example",
            requestedSpecification="https://packages.example/archive.whl?credential=private",
            integrity=INTEGRITY_A,
            integrityPresent=True,
        ))
        self.assertTrue(approval_for_analysis(vcs_control)["eligible"])
        self.assertTrue(approval_for_analysis(url_control)["eligible"])
        self.assertEqual(
            snapshot_from_analysis(vcs_control)["entries"][0]["requestedSpecification"],
            "github:owner/repository",
        )
        self.assertEqual(
            snapshot_from_analysis(url_control)["entries"][0]["requestedSpecification"],
            "https://packages.example/archive.whl",
        )

    def test_legacy_baseline_without_vcs_identity_requires_reapproval(self) -> None:
        current = analysis([entry(
            "vcsdep", sourceType="vcs", sourceIdentifier="github.com",
            requestedSpecification="https://github.com/org/repo.git",
            vcsRequestedRevision=vcs_identity("rev", "revision-one"),
        )])
        current_snapshot = snapshot_from_analysis(current)
        legacy_snapshot = {
            **current_snapshot,
            "baselineSchemaVersion": 1,
            "entries": [{
                key: value
                for key, value in current_snapshot["entries"][0].items()
                if key not in {"vcsRequestedRevision", "vcsLockedRevision", "vcsResolvedRevision"}
            }],
        }
        legacy_row = {
            **baseline_row(current_snapshot),
            "baseline_schema_version": 1,
            "fingerprint": "cfdb1_" + "0" * 64,
            "snapshot_json": json.dumps(legacy_snapshot),
        }

        self.assertEqual(public_baseline(legacy_row)["status"], "invalid")
        self.assertEqual(compare_with_baseline(current, legacy_row)["status"], "invalid")
        approval = approval_for_analysis(current)
        self.assertTrue(approval["eligible"])
        self.assertRegex(approval["fingerprint"], r"^cfdb2_[0-9a-f]{64}$")

    def test_sensitive_or_unsafe_snapshot_values_are_rejected(self) -> None:
        unsafe_values = [
            entry("alpha", requestedSpecification="https://user:token@example.test/pkg.tgz?token=secret#frag"),
            entry("alpha", sourceIdentifier="user:token@example.test"),
            entry("alpha", sourceIdentifier="file:C:/host/cache"),
            entry("alpha", manifestPath="C:/host/package.json"),
            entry("alpha", lockfilePath="../outside.lock"),
            entry("alpha", lockedVersion="https://user:token@example.test/package.tgz"),
            entry("alpha", integrity="token=secret", integrityPresent=True),
            entry("alpha", integrity="", integrityPresent=True),
            entry("alpha", requestedSpecification="github:user/private#credential-fragment"),
            entry("alpha", requestedSpecification="user@private.example:repository"),
            entry("https://user:token@example.test/package?secret=yes"),
            entry("alpha", group="optional:https://user:token@example.test#secret"),
            entry("alpha", sourceIdentifier="a" * 201),
            entry("alpha", sourceType="vcs", vcsRequestedRevision="rev:RAW_SECRET"),
            entry("alpha", sourceType="registry", vcsRequestedRevision=vcs_identity("rev", "hidden")),
            entry("alpha", integrity="sha512-AAAA", integrityPresent=True),
        ]
        for unsafe in unsafe_values:
            with self.subTest(unsafe=unsafe), self.assertRaises(BaselineError):
                snapshot_from_analysis(analysis([unsafe]))

    def test_approval_eligibility_is_conservative(self) -> None:
        self.assertTrue(approval_for_analysis(analysis([entry("alpha")]))["eligible"])
        for value in (
            None,
            {"schemaVersion": 0},
            analysis(status="incomplete"),
            analysis(status="malformed"),
            analysis(status="unsupported", manifests=[], lockfiles=[]),
            analysis(manifests=[], lockfiles=[]),
        ):
            self.assertFalse(approval_for_analysis(value)["eligible"])

    def test_inventory_above_canonical_limit_is_rejected_without_truncation(self) -> None:
        oversized = analysis([entry(f"package-{index}") for index in range(MAX_ENTRIES + 1)])
        approval = approval_for_analysis(oversized)
        self.assertFalse(approval["eligible"])
        self.assertEqual(approval["fingerprint"], "")
        self.assertIn("exceeds the trusted baseline limit", approval["reason"])
        with self.assertRaises(BaselineError):
            snapshot_from_analysis(oversized)


class BaselineComparisonTests(unittest.TestCase):
    def test_identical_and_full_drift_comparisons_are_distinct(self) -> None:
        original = analysis([
            entry("alpha"),
            entry("removed"),
            entry("integrity", integrity=INTEGRITY_A),
            entry("transitive", direct=False),
        ])
        snapshot = snapshot_from_analysis(original)
        row = baseline_row(snapshot)
        identical = compare_with_baseline(original, row)
        self.assertEqual(identical["status"], "identical")
        self.assertEqual(identical["changeCount"], 0)

        current = analysis([
            entry("alpha", requestedSpecification="^2.0.0", lockedVersion="2.0.0", sourceType="url", sourceIdentifier="http:packages.example"),
            entry("added"),
            entry("integrity", integrity=INTEGRITY_B),
            entry("new-transitive", direct=False),
        ], packageManagers=["npm", "pnpm"], lockfiles=["package-lock.json", "npm-shrinkwrap.json"])
        drift = compare_with_baseline(current, row)
        self.assertEqual(drift["status"], "drift")
        change_types = {item["changeType"] for item in drift["changes"]}
        self.assertTrue({
            "direct-dependency-added", "direct-dependency-removed", "specification-changed",
            "version-changed", "source-changed", "integrity-changed", "locked-package-added",
            "locked-package-removed", "package-manager-added", "lockfile-added",
        }.issubset(change_types))
        finding_types = {item["type"] for item in drift["findings"]}
        self.assertIn("trusted-baseline-integrity-changed", finding_types)
        self.assertIn("trusted-baseline-source-changed", finding_types)
        self.assertEqual(drift["highestSeverity"], "high")

    def test_incomplete_current_analysis_never_manufactures_removals(self) -> None:
        original = analysis([entry("alpha"), entry("beta"), entry("transitive", direct=False)])
        row = baseline_row(snapshot_from_analysis(original))
        incomplete = analysis([entry("alpha")], status="incomplete")
        result = compare_with_baseline(incomplete, row)
        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(any("removed" in item["changeType"] for item in result["changes"]))
        self.assertIn("trusted-baseline-comparison-incomplete", {item["type"] for item in result["findings"]})

    def test_incompatible_and_corrupted_baselines_fail_conservatively(self) -> None:
        snapshot = snapshot_from_analysis(analysis([entry("alpha")]))
        row = baseline_row(snapshot)
        self.assertEqual(compare_with_baseline({"schemaVersion": 2}, row)["status"], "incompatible")
        self.assertEqual(compare_with_baseline(analysis([entry("alpha")]), {**row, "snapshot_json": "{"})["status"], "invalid")
        self.assertEqual(compare_with_baseline(analysis([entry("alpha")]), {**row, "fingerprint": "cfdb2_" + "0" * 64})["status"], "invalid")
        self.assertEqual(compare_with_baseline(analysis([entry("alpha")]), {**row, "baseline_schema_version": "corrupt"})["status"], "invalid")
        self.assertEqual(compare_with_baseline(analysis([entry("alpha")]), {**row, "dependency_schema_version": 2})["status"], "invalid")

    def test_metadata_and_duplicate_entry_drift_is_explicit_and_bounded(self) -> None:
        original = analysis([
            entry("alpha", direct=False, lockedVersion="1.0.0", optional=False, lockfilePath="locks/a.lock"),
            entry("alpha", direct=False, lockedVersion="2.0.0", optional=False, lockfilePath="locks/b.lock"),
        ], lockfiles=["locks/a.lock", "locks/b.lock"])
        current = analysis([
            entry("alpha", direct=False, lockedVersion="2.0.0", optional=True, lockfilePath="locks/a.lock"),
            entry("alpha", direct=False, lockedVersion="1.0.0", optional=False, lockfilePath="locks/b.lock"),
        ], lockfiles=["locks/a.lock", "locks/b.lock"])
        result = compare_with_baseline(current, baseline_row(snapshot_from_analysis(original)))
        self.assertEqual(result["status"], "drift")
        self.assertEqual(sum(change["changeType"] == "version-changed" for change in result["changes"]), 2)
        self.assertIn("dependency-metadata-changed", {change["changeType"] for change in result["changes"]})
        self.assertGreater(result["changeCount"], 0)

        many_original = analysis([entry(f"package-{index:04d}") for index in range(350)])
        many_current = analysis([])
        bounded = compare_with_baseline(many_current, baseline_row(snapshot_from_analysis(many_original)))
        self.assertEqual(bounded["changeCount"], 350)
        self.assertEqual(len(bounded["changes"]), 300)
        self.assertTrue(bounded["truncated"])


class TrustedBaselineApiTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.database_path = self.base / "glacial.db"
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.project = self.root / "project"
        self.project.mkdir()
        self.other = self.root / "other"
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
        self.register(self.project)
        self.register(self.other)

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

    def register(self, project: Path) -> None:
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO projects (path, name, created_at) VALUES (?, ?, ?)",
                (str(project), project.name, "2026-01-01T00:00:00+00:00"),
            )

    def write_node_project(self, project: Path, version: str = "1.0.0") -> None:
        (project / "package.json").write_text(json.dumps({"dependencies": {"alpha": version}}), encoding="utf-8")
        (project / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"alpha": version}},
                "node_modules/alpha": {
                    "version": version,
                    "resolved": f"https://registry.npmjs.org/alpha/-/alpha-{version}.tgz",
                    "integrity": INTEGRITY_A,
                },
            },
        }), encoding="utf-8")

    def scan(self, project: Path, version: str = "1.0.0") -> dict[str, object]:
        self.write_node_project(project, version)
        return main.run_scan(ProjectPathRequest(project_path=str(project)))

    def approve(self, scan: dict[str, object], *, replace: bool = False, note: str = "Approved.") -> dict[str, object]:
        fingerprint = scan["dependencyTrust"]["trustedBaseline"]["approval"]["fingerprint"]
        return main.approve_trusted_dependency_baseline(TrustedDependencyBaselineApprove(
            project_path=scan["project_path"], scan_id=scan["id"], fingerprint=fingerprint,
            note=note, replace=replace,
        ))

    def test_create_read_replace_note_clear_and_history_round_trip(self) -> None:
        first = self.scan(self.project)
        self.assertEqual(first["dependencyTrust"]["comparison"]["baselineStatus"], "unavailable")
        self.assertFalse(first["dependencyTrust"]["trustedBaseline"]["configured"])
        created = self.approve(first)
        self.assertTrue(created["configured"])
        self.assertEqual(main.get_trusted_dependency_baseline(str(self.project))["fingerprint"], created["fingerprint"])
        other_scan = self.scan(self.other)
        self.assertFalse(other_scan["dependencyTrust"]["trustedBaseline"]["configured"])

        history = main.scan_history(str(self.project))["scans"][0]
        self.assertEqual(history["dependencyTrust"]["trustedBaseline"]["comparison"]["status"], "identical")
        self.assertEqual(history["dependencyTrust"]["comparison"]["baselineStatus"], "unavailable")

        second = self.scan(self.project, "2.0.0")
        self.assertEqual(second["dependencyTrust"]["trustedBaseline"]["comparison"]["status"], "drift")
        self.assertEqual(second["dependencyTrust"]["comparison"]["baselineStatus"], "available")
        with self.assertRaises(HTTPException) as stale_fingerprint:
            main.approve_trusted_dependency_baseline(TrustedDependencyBaselineApprove(
                project_path=str(self.project), scan_id=second["id"],
                fingerprint="cfdb2_" + "0" * 64, replace=True,
            ))
        self.assertEqual(stale_fingerprint.exception.status_code, 409)
        with self.assertRaises(HTTPException) as historical:
            self.approve(first, replace=True)
        self.assertEqual(historical.exception.status_code, 409)
        self.assertEqual(main.get_trusted_dependency_baseline(str(self.project))["fingerprint"], created["fingerprint"])
        with self.assertRaises(HTTPException) as confirmation:
            self.approve(second)
        self.assertEqual(confirmation.exception.status_code, 409)
        replaced = self.approve(second, replace=True, note="Replacement note.")
        self.assertNotEqual(replaced["fingerprint"], created["fingerprint"])

        updated = main.update_trusted_dependency_baseline_note(TrustedDependencyBaselineNote(
            project_path=str(self.project), note=" Updated note. ",
        ))
        self.assertEqual(updated["note"], "Updated note.")
        self.assertEqual(updated["fingerprint"], replaced["fingerprint"])
        with self.assertRaises(HTTPException) as isolated_note:
            main.update_trusted_dependency_baseline_note(TrustedDependencyBaselineNote(
                project_path=str(self.other), note="Must not cross projects.",
            ))
        self.assertEqual(isolated_note.exception.status_code, 404)
        main.clear_trusted_dependency_baseline(ProjectPathRequest(project_path=str(self.other)))
        self.assertEqual(main.get_trusted_dependency_baseline(str(self.project))["fingerprint"], replaced["fingerprint"])
        self.assertTrue(main.clear_trusted_dependency_baseline(ProjectPathRequest(project_path=str(self.project)))["cleared"])
        self.assertFalse(main.get_trusted_dependency_baseline(str(self.project))["configured"])
        self.assertTrue(main.clear_trusted_dependency_baseline(ProjectPathRequest(project_path=str(self.project)))["cleared"])

    def test_stale_arbitrary_ineligible_and_cross_project_approvals_are_rejected(self) -> None:
        first = self.scan(self.project)
        fingerprint = first["dependencyTrust"]["trustedBaseline"]["approval"]["fingerprint"]
        with self.assertRaises(HTTPException) as stale:
            main.approve_trusted_dependency_baseline(TrustedDependencyBaselineApprove(
                project_path=str(self.project), scan_id=first["id"], fingerprint="cfdb2_" + "0" * 64,
            ))
        self.assertEqual(stale.exception.status_code, 409)
        with self.assertRaises(ValidationError):
            TrustedDependencyBaselineApprove(
                project_path=str(self.project), scan_id=first["id"], fingerprint=fingerprint,
                snapshot={"entries": []},
            )

        other_scan = self.scan(self.other)
        with self.assertRaises(HTTPException) as cross_project:
            main.approve_trusted_dependency_baseline(TrustedDependencyBaselineApprove(
                project_path=str(self.project), scan_id=other_scan["id"],
                fingerprint=other_scan["dependencyTrust"]["trustedBaseline"]["approval"]["fingerprint"],
            ))
        self.assertEqual(cross_project.exception.status_code, 403)

        (self.project / "package.json").unlink()
        (self.project / "package-lock.json").unlink()
        empty = main.run_scan(ProjectPathRequest(project_path=str(self.project)))
        self.assertFalse(empty["dependencyTrust"]["trustedBaseline"]["approval"]["eligible"])
        with self.assertRaises(HTTPException) as ineligible:
            main.approve_trusted_dependency_baseline(TrustedDependencyBaselineApprove(
                project_path=str(self.project), scan_id=empty["id"], fingerprint="cfdb2_" + "0" * 64,
            ))
        self.assertEqual(ineligible.exception.status_code, 409)
        with self.assertRaises(ValidationError):
            TrustedDependencyBaselineNote(project_path=str(self.project), note="x" * 1001)
        with self.assertRaises(ValidationError):
            TrustedDependencyBaselineNote(project_path=str(self.project), snapshot={"entries": []})

    def test_approved_snapshot_stores_only_sanitized_source_identity(self) -> None:
        (self.project / "package.json").write_text(
            json.dumps({"dependencies": {"alpha": "1.0.0"}}), encoding="utf-8",
        )
        (self.project / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"alpha": "1.0.0"}},
                "node_modules/alpha": {
                    "version": "1.0.0",
                    "resolved": "https://user:token@packages.example/alpha.tgz?auth=secret#fragment",
                    "integrity": INTEGRITY_A,
                },
            },
        }), encoding="utf-8")
        scanned = main.run_scan(ProjectPathRequest(project_path=str(self.project)))
        self.approve(scanned)
        with database.get_connection() as connection:
            stored = connection.execute(
                "SELECT snapshot_json FROM trusted_dependency_baselines WHERE project_path = ?", (str(self.project),),
            ).fetchone()["snapshot_json"]
        self.assertIn("packages.example", stored)
        for sensitive in ("user", "token", "auth", "secret", "fragment", "?"):
            self.assertNotIn(sensitive, stored)

    def test_approved_vcs_snapshot_persists_only_opaque_revision_identity(self) -> None:
        source = "https://vcs-user:VCS_PASSWORD@github.com/org/repo.git?token=VCS_QUERY#VCS_FRAGMENT"
        (self.project / "pyproject.toml").write_text(
            "[tool.poetry.dependencies]\npython = \"^3.11\"\n"
            f'vcsdep = {{ git = "{source}", rev = "RAW_VCS_SELECTOR" }}\n',
            encoding="utf-8",
        )
        (self.project / "poetry.lock").write_text(
            '[[package]]\nname = "vcsdep"\nversion = "0.0.0"\noptional = false\n'
            f'[package.source]\ntype = "git"\nurl = "{source}"\n'
            'reference = "RAW_LOCK_REFERENCE"\nresolved_reference = "RAW_RESOLVED_REFERENCE"\n',
            encoding="utf-8",
        )

        scanned = main.run_scan(ProjectPathRequest(project_path=str(self.project)))
        approved = self.approve(scanned)
        with database.get_connection() as connection:
            stored = connection.execute(
                "SELECT snapshot_json FROM trusted_dependency_baselines WHERE project_path = ?", (str(self.project),),
            ).fetchone()["snapshot_json"]

        self.assertRegex(approved["fingerprint"], r"^cfdb2_[0-9a-f]{64}$")
        self.assertIn("rev:sha256:", stored)
        self.assertIn("reference:sha256:", stored)
        self.assertIn("resolved:sha256:", stored)
        serialized = json.dumps({"scan": scanned, "approved": approved, "stored": json.loads(stored)})
        for secret in (
            "vcs-user", "VCS_PASSWORD", "VCS_QUERY", "VCS_FRAGMENT", "RAW_VCS_SELECTOR",
            "RAW_LOCK_REFERENCE", "RAW_RESOLVED_REFERENCE",
        ):
            self.assertNotIn(secret, serialized)

    def test_approval_revalidates_latest_scan_inside_the_write_transaction(self) -> None:
        scanned = self.scan(self.project)
        fingerprint = scanned["dependencyTrust"]["trustedBaseline"]["approval"]["fingerprint"]

        def insert_newer_scan(snapshot: dict[str, object]) -> str:
            with database.get_connection() as connection:
                connection.execute(
                    "INSERT INTO scans (project_path, scan_date, overall_risk, findings_json) VALUES (?, ?, 'none', '[]')",
                    (str(self.project), "2030-01-01T00:00:00+00:00"),
                )
            return snapshot_json(snapshot)

        with patch.object(main, "snapshot_json", side_effect=insert_newer_scan):
            with self.assertRaises(HTTPException) as stale:
                main.approve_trusted_dependency_baseline(TrustedDependencyBaselineApprove(
                    project_path=str(self.project), scan_id=scanned["id"], fingerprint=fingerprint,
                ))
        self.assertEqual(stale.exception.status_code, 409)
        self.assertFalse(main.get_trusted_dependency_baseline(str(self.project))["configured"])

    def test_unregister_and_history_retention_do_not_orphan_or_destroy_baseline(self) -> None:
        first = self.scan(self.project)
        self.approve(first)
        with database.get_connection() as connection:
            for index in range(25):
                connection.execute(
                    "INSERT INTO scans (project_path, scan_date, overall_risk, findings_json) VALUES (?, ?, 'none', '[]')",
                    (str(self.project), f"2027-{index + 1:02d}-01"),
                )
        self.assertEqual(len(main.scan_history(str(self.project))["scans"]), 20)
        self.assertTrue(main.get_trusted_dependency_baseline(str(self.project))["configured"])
        package = self.project / "package.json"
        main.unregister_project(ProjectPathRequest(project_path=str(self.project)))
        self.assertTrue(package.is_file())
        with database.get_connection() as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM trusted_dependency_baselines WHERE project_path = ?", (str(self.project),),
            ).fetchone()[0]
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
