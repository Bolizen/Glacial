from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import database, installed_lifecycle
from app.state_lifecycle import DatabaseStateError


class InstalledLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            dir=Path(__file__).resolve().parent
        )
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.data_directory = self.root / "app-data" / "data"
        self.database_path = self.data_directory / "glacial.db"
        self.database_patch = patch.object(database, "DB_PATH", self.database_path)
        self.database_patch.start()
        self.addCleanup(self.database_patch.stop)

    def test_runtime_contract_reports_resolved_owned_paths_and_uninstall_policy(self) -> None:
        install = self.root / "installed" / "Glacial"
        environments = {
            environment: str(
                {
                    "applicationExecutable": install / "glacial.exe",
                    "installationDirectory": install,
                    "backendExecutable": install / "glacial-backend.exe",
                    "runtimeFiles": install / "_internal",
                    "logDirectory": self.root / "app-data" / "logs",
                    "temporaryDirectory": self.root / "temp",
                }[name]
            )
            for name, environment in installed_lifecycle.RUNTIME_PATH_ENVIRONMENTS.items()
        }
        with patch.dict(installed_lifecycle.os.environ, environments, clear=False):
            contract = installed_lifecycle.runtime_path_contract(self.database_path)

        paths = contract["paths"]
        self.assertEqual(paths["installationDirectory"], str(install.resolve()))
        self.assertEqual(paths["database"], str(self.database_path.resolve()))
        self.assertEqual(
            paths["recoveryBackups"],
            str((self.data_directory / "recovery-backups").resolve()),
        )
        self.assertEqual(paths["uninstaller"], str((install / "uninstall.exe").resolve()))
        self.assertEqual(contract["uninstall"]["default"], "preserve-application-data")
        self.assertEqual(contract["uninstall"]["projectFiles"], "never removed")

    def test_confirmed_reset_preserves_project_files_and_publishes_valid_backup(self) -> None:
        project = self.root / "projects" / "kept-project"
        project.mkdir(parents=True)
        project_file = project / "keep.txt"
        project_file.write_text("project-owned", encoding="utf-8")
        database.init_db()
        connection = database.get_connection()
        try:
            connection.execute(
                "UPDATE settings SET value = ? WHERE key = ?",
                (str(project.parent), database.WORKSPACE_ROOT_SETTING),
            )
            connection.execute(
                "INSERT INTO projects "
                "(path, name, description, project_type, created_at) "
                "VALUES (?, 'kept-project', 'description', 'Python', '2026-07-27')",
                (str(project),),
            )
            connection.commit()
        finally:
            connection.close()
        before = self.database_path.read_bytes()

        result = installed_lifecycle.reset_application_state(
            self.database_path,
            database.init_db,
            confirmation=installed_lifecycle.RESET_CONFIRMATION,
            default_workspace_root=database.DEFAULT_WORKSPACE_ROOT,
        )

        self.assertTrue(result["reset"])
        backup_path = Path(result["backup"])
        self.assertTrue(backup_path.is_file())
        self.assertEqual(project_file.read_text(encoding="utf-8"), "project-owned")
        backup = sqlite3.connect(backup_path)
        try:
            self.assertEqual(backup.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(backup.execute("SELECT COUNT(*) FROM projects").fetchone()[0], 1)
        finally:
            backup.close()
        current = database.get_connection()
        try:
            self.assertEqual(current.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(current.execute("SELECT COUNT(*) FROM projects").fetchone()[0], 0)
        finally:
            current.close()
        self.assertNotEqual(self.database_path.read_bytes(), before)
        self.assertFalse(any(self.data_directory.glob(".glacial-reset-*.pending*")))

    def test_malformed_database_is_preserved_as_raw_backup_then_reset(self) -> None:
        self.data_directory.mkdir(parents=True)
        corrupt = b"not a sqlite database\x00preserve for recovery"
        self.database_path.write_bytes(corrupt)

        result = installed_lifecycle.reset_application_state(
            self.database_path,
            database.init_db,
            confirmation=installed_lifecycle.RESET_CONFIRMATION,
            default_workspace_root=database.DEFAULT_WORKSPACE_ROOT,
        )

        self.assertEqual(Path(result["backup"]).read_bytes(), corrupt)
        connection = database.get_connection()
        try:
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM projects").fetchone()[0], 0)
        finally:
            connection.close()

    def test_unavailable_database_initializes_clean_state_without_backup(self) -> None:
        result = installed_lifecycle.reset_application_state(
            self.database_path,
            database.init_db,
            confirmation=installed_lifecycle.RESET_CONFIRMATION,
            default_workspace_root=database.DEFAULT_WORKSPACE_ROOT,
        )
        self.assertTrue(result["reset"])
        self.assertIsNone(result["backup"])
        self.assertTrue(self.database_path.is_file())

    def test_failed_exclusive_replacement_preserves_original_state(self) -> None:
        database.init_db()
        before = self.database_path.read_bytes()
        with (
            patch.object(
                installed_lifecycle,
                "_reset_valid_database",
                side_effect=DatabaseStateError("injected lock"),
            ),
            self.assertRaises(DatabaseStateError),
        ):
            installed_lifecycle.reset_application_state(
                self.database_path,
                database.init_db,
                confirmation=installed_lifecycle.RESET_CONFIRMATION,
                default_workspace_root=database.DEFAULT_WORKSPACE_ROOT,
            )
        self.assertEqual(self.database_path.read_bytes(), before)
        self.assertEqual(
            len(list((self.data_directory / "recovery-backups").glob("*.db"))),
            1,
        )

    def test_reset_rejects_missing_confirmation_without_writing(self) -> None:
        database.init_db()
        before = self.database_path.read_bytes()
        with self.assertRaisesRegex(DatabaseStateError, "confirmation phrase"):
            installed_lifecycle.reset_application_state(
                self.database_path,
                database.init_db,
                confirmation="reset",
                default_workspace_root=database.DEFAULT_WORKSPACE_ROOT,
            )
        self.assertEqual(self.database_path.read_bytes(), before)
        self.assertFalse((self.data_directory / "recovery-backups").exists())


if __name__ == "__main__":
    unittest.main()
