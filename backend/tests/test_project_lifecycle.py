from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError

from app import database, main, safety
from app.schemas import ProjectMetadataUpdate, ProjectPathRequest, ProjectRootUpdate, TrustProfileRequest


class ProjectLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
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
        self.register(self.project, description="Old description", project_type="Python")

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

    def register(self, path: Path, *, description: str = "", project_type: str = "") -> None:
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO projects (path, name, description, project_type, created_at) VALUES (?, ?, ?, ?, ?)",
                (str(path), path.name, description, project_type, "2026-01-01T00:00:00+00:00"),
            )

    def test_workspace_root_update_validates_and_persists(self) -> None:
        other_root = self.base / "other-workspace"
        other_root.mkdir()
        other_project = other_root / "other-project"
        other_project.mkdir()
        self.register(other_project)

        result = main.update_project_root(ProjectRootUpdate(project_root=str(other_root)))

        self.assertEqual(result["project_root"], str(other_root))
        self.assertEqual(main.get_config()["project_root"], str(other_root))
        self.assertEqual([project["path"] for project in main.list_projects()["projects"]], [str(other_project)])

    def test_workspace_root_rejects_relative_missing_file_and_unsafe_paths(self) -> None:
        with self.assertRaises(HTTPException) as relative:
            main.update_project_root(ProjectRootUpdate(project_root="relative/path"))
        self.assertEqual(relative.exception.status_code, 400)

        with self.assertRaises(HTTPException) as missing:
            main.update_project_root(ProjectRootUpdate(project_root=str(self.base / "missing")))
        self.assertEqual(missing.exception.status_code, 404)

        regular_file = self.base / "file.txt"
        regular_file.write_text("not a directory", encoding="utf-8")
        with self.assertRaises(HTTPException) as file_error:
            main.update_project_root(ProjectRootUpdate(project_root=str(regular_file)))
        self.assertEqual(file_error.exception.status_code, 400)

        with patch.object(safety, "is_reparse_point_or_symlink", return_value=True):
            with self.assertRaises(HTTPException) as unsafe:
                safety.existing_workspace_root(str(self.root))
        self.assertEqual(unsafe.exception.status_code, 403)

    def test_metadata_update_trims_clears_and_validates(self) -> None:
        updated = main.update_project_metadata(ProjectMetadataUpdate(
            project_path=str(self.project),
            description="  New description  ",
            project_type="  TypeScript  ",
        ))
        self.assertEqual(updated["description"], "New description")
        self.assertEqual(updated["project_type"], "TypeScript")
        listed = main.list_projects()["projects"][0]
        self.assertEqual(listed["description"], "New description")

        cleared = main.update_project_metadata(ProjectMetadataUpdate(project_path=str(self.project), description="", project_type=""))
        self.assertEqual(cleared["description"], "")
        with self.assertRaises(ValidationError):
            ProjectMetadataUpdate(project_path=str(self.project), description="x" * 2001)
        with self.assertRaises(HTTPException) as missing:
            main.update_project_metadata(ProjectMetadataUpdate(project_path=str(self.root / "missing")))
        self.assertEqual(missing.exception.status_code, 404)

    def test_unregister_removes_database_state_but_never_project_files(self) -> None:
        marker = self.project / "keep.txt"
        marker.write_text("keep", encoding="utf-8")
        with database.get_connection() as connection:
            connection.execute("INSERT INTO notes (project_path, body, created_at) VALUES (?, 'note', 'now')", (str(self.project),))
            connection.execute("INSERT INTO scans (project_path, scan_date, overall_risk, findings_json) VALUES (?, 'now', 'none', '[]')", (str(self.project),))
            connection.execute("INSERT INTO project_trust_profiles (project_path, profile_json, updated_at) VALUES (?, '{}', 'now')", (str(self.project),))

        with (
            patch.object(Path, "unlink", side_effect=AssertionError("filesystem deletion is forbidden")),
            patch.object(Path, "rmdir", side_effect=AssertionError("filesystem deletion is forbidden")),
            patch.object(Path, "rename", side_effect=AssertionError("filesystem modification is forbidden")),
            patch.object(Path, "replace", side_effect=AssertionError("filesystem modification is forbidden")),
            patch.object(Path, "write_text", side_effect=AssertionError("filesystem modification is forbidden")),
            patch.object(Path, "write_bytes", side_effect=AssertionError("filesystem modification is forbidden")),
            patch.object(Path, "touch", side_effect=AssertionError("filesystem modification is forbidden")),
            patch("os.remove", side_effect=AssertionError("filesystem deletion is forbidden")),
            patch("os.unlink", side_effect=AssertionError("filesystem deletion is forbidden")),
            patch("shutil.rmtree", side_effect=AssertionError("filesystem deletion is forbidden")),
        ):
            result = main.unregister_project(ProjectPathRequest(project_path=str(self.project)))

        self.assertTrue(result["unregistered"])
        self.assertTrue(marker.is_file())
        with database.get_connection() as connection:
            for table, column in (("projects", "path"), ("notes", "project_path"), ("scans", "project_path"), ("project_trust_profiles", "project_path")):
                self.assertEqual(connection.execute(f"SELECT COUNT(*) FROM {table} WHERE {column} = ?", (str(self.project),)).fetchone()[0], 0)
        with self.assertRaises(HTTPException) as missing:
            main.unregister_project(ProjectPathRequest(project_path=str(self.project)))
        self.assertEqual(missing.exception.status_code, 404)

    def test_missing_registration_remains_listed_and_can_be_unregistered(self) -> None:
        self.project.rmdir()

        listed = main.list_projects()["projects"][0]

        self.assertFalse(listed["available"])
        self.assertEqual(listed["availability"], "missing")
        self.assertEqual(listed["scan_state"], "not_scanned")
        main.unregister_project(ProjectPathRequest(project_path=str(self.project)))
        self.assertEqual(main.list_projects()["projects"], [])

    def test_legacy_trust_profile_loads_as_backward_compatible_project_expectations(self) -> None:
        legacy = {
            "trustedPackageManagers": ["npm"],
            "expectedManifestFiles": ["package.json"],
            "reviewedPaths": ["src/"],
            "riskTolerance": "cautious",
            "notes": "Reviewed locally.",
        }
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO project_trust_profiles (project_path, profile_json, updated_at) VALUES (?, ?, 'now')",
                (str(self.project), json.dumps(legacy)),
            )

        profile = main.get_trust_profile(str(self.project))

        self.assertEqual(profile["trustedPackageManagers"], ["npm"])
        self.assertEqual(profile["expectedManifestFiles"], ["package.json"])
        self.assertEqual(profile["reviewedPaths"], ["src/"])
        self.assertEqual(profile["expectedEcosystems"], [])
        self.assertEqual(profile["expectationProvenance"], {})
        self.assertEqual(profile["dismissedSuggestions"], {})
        self.assertEqual(profile["riskTolerance"], "cautious")
        self.assertEqual(profile["updated_at"], "now")

    def test_project_expectation_provenance_and_dismissals_round_trip_fail_closed(self) -> None:
        updated = main.update_trust_profile(TrustProfileRequest(
            project_path=str(self.project),
            trustedPackageManagers=["npm", "npm"],
            expectedEcosystems=["node"],
            expectationProvenance={
                "trustedPackageManagers": {
                    "npm": "accepted-suggestion",
                    "ghost": "manual",
                },
                "expectedEcosystems": {"node": "untrusted-source"},
                "unknownField": {"value": "manual"},
            },
            dismissedSuggestions={
                "trustedPackageManagers": ["npm", "pip", "pip"],
                "expectedLockfiles": ["package-lock.json"],
                "unknownField": ["ignored"],
            },
            riskTolerance="INVALID",
        ))

        self.assertEqual(updated["trustedPackageManagers"], ["npm"])
        self.assertEqual(updated["expectedEcosystems"], ["node"])
        self.assertEqual(updated["expectationProvenance"], {
            "trustedPackageManagers": {"npm": "accepted-suggestion"},
        })
        self.assertEqual(updated["dismissedSuggestions"], {
            "trustedPackageManagers": ["pip"],
            "expectedLockfiles": ["package-lock.json"],
        })
        self.assertEqual(updated["riskTolerance"], "normal")
        self.assertEqual(main.get_trust_profile(str(self.project)), updated)

        with database.get_connection() as connection:
            stored = json.loads(connection.execute(
                "SELECT profile_json FROM project_trust_profiles WHERE project_path = ?",
                (str(self.project),),
            ).fetchone()["profile_json"])
        self.assertNotIn("project_path", stored)
        self.assertNotIn("updated_at", stored)
        self.assertEqual(stored["expectedEcosystems"], ["node"])

    def test_malformed_stored_project_expectations_return_conservative_defaults(self) -> None:
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO project_trust_profiles (project_path, profile_json, updated_at) VALUES (?, '[]', 'now')",
                (str(self.project),),
            )

        profile = main.get_trust_profile(str(self.project))

        self.assertEqual(profile["trustedPackageManagers"], [])
        self.assertEqual(profile["expectationProvenance"], {})
        self.assertEqual(profile["dismissedSuggestions"], {})
        self.assertEqual(profile["riskTolerance"], "normal")

        with database.get_connection() as connection:
            connection.execute(
                "UPDATE project_trust_profiles SET profile_json = ? WHERE project_path = ?",
                (json.dumps({
                    "trustedPackageManagers": [None, {"name": "npm"}, "pip"],
                    "riskTolerance": {"value": "permissive"},
                    "notes": ["not", "text"],
                }), str(self.project)),
            )
        partially_malformed = main.get_trust_profile(str(self.project))
        self.assertEqual(partially_malformed["trustedPackageManagers"], ["pip"])
        self.assertEqual(partially_malformed["riskTolerance"], "normal")
        self.assertEqual(partially_malformed["notes"], "")


if __name__ == "__main__":
    unittest.main()
