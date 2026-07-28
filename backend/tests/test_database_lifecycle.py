from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import database, state_lifecycle


CORE_SCHEMA = """
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE projects (
    path TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    project_type TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_path TEXT NOT NULL,
    scan_date TEXT NOT NULL,
    overall_risk TEXT NOT NULL,
    findings_json TEXT NOT NULL
);
CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_path TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

LEGACY_CHECKPOINT_SCHEMA = """
CREATE TABLE project_review_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    scan_id INTEGER NOT NULL,
    baseline_scan_id INTEGER,
    baseline_provenance TEXT NOT NULL
        CHECK (baseline_provenance IN ('manual', 'automatic', 'none')),
    expectations_fingerprint TEXT NOT NULL,
    dependency_analysis_fingerprint TEXT NOT NULL,
    dependency_approval_fingerprint TEXT NOT NULL DEFAULT '',
    dependency_approval_state TEXT NOT NULL,
    finding_reviews_fingerprint TEXT NOT NULL,
    finding_review_complete INTEGER NOT NULL
        CHECK (finding_review_complete IN (0, 1)),
    unresolved_critical_count INTEGER NOT NULL,
    unresolved_high_count INTEGER NOT NULL,
    coverage_fingerprint TEXT NOT NULL,
    metadata_reliable INTEGER NOT NULL
        CHECK (metadata_reliable IN (0, 1)),
    checkpoint_schema_version INTEGER NOT NULL,
    evaluator_version INTEGER NOT NULL,
    evidence_fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    provenance TEXT NOT NULL DEFAULT 'manual'
        CHECK (provenance IN ('manual')),
    FOREIGN KEY (scan_id) REFERENCES scans(id),
    FOREIGN KEY (baseline_scan_id) REFERENCES scans(id)
);
CREATE INDEX project_review_checkpoints_project_time
ON project_review_checkpoints (project_id, created_at DESC, checkpoint_id DESC);
"""


class DatabaseLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            dir=Path(__file__).resolve().parent
        )
        self.addCleanup(self.temporary_directory.cleanup)
        self.base = Path(self.temporary_directory.name)
        self.database_path = self.base / "glacial.db"
        self.database_patch = patch.object(database, "DB_PATH", self.database_path)
        self.database_patch.start()
        self.addCleanup(self.database_patch.stop)

    def raw_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def create_core_legacy(self, *, with_record: bool = True) -> None:
        connection = self.raw_connection()
        try:
            connection.executescript(CORE_SCHEMA)
            if with_record:
                connection.execute(
                    "INSERT INTO settings (key, value) VALUES ('project_root', 'C:/legacy')"
                )
                connection.execute(
                    "INSERT INTO projects "
                    "(path, name, description, project_type, created_at) "
                    "VALUES ('C:/legacy/project', 'project', 'kept', 'Python', '2026-01-01')"
                )
                connection.execute(
                    "INSERT INTO scans "
                    "(project_path, scan_date, overall_risk, findings_json) "
                    "VALUES ('C:/legacy/project', '2026-01-02', 'high', "
                    "'[{\"path\":\"src/app.py\",\"type\":\"test\",\"severity\":\"high\"}]')"
                )
                connection.execute(
                    "INSERT INTO notes (project_path, body, created_at) "
                    "VALUES ('C:/legacy/project', 'keep note', '2026-01-03')"
                )
            connection.commit()
        finally:
            connection.close()

    def create_current_unversioned(self, *, realistic: bool = False) -> None:
        connection = self.raw_connection()
        try:
            for statement in state_lifecycle.SCHEMA_STATEMENTS:
                connection.execute(statement)
            if realistic:
                project = "C:/legacy/project"
                connection.execute(
                    "INSERT INTO settings (key, value) VALUES ('project_root', 'C:/legacy')"
                )
                connection.execute(
                    "INSERT INTO projects "
                    "(path, name, description, project_type, created_at) "
                    "VALUES (?, 'project', 'description', 'Python', '2026-01-01')",
                    (project,),
                )
                findings = json.dumps(
                    [{"path": "src/app.py", "type": "test", "severity": "high"}]
                )
                metadata = json.dumps(
                    {
                        "manifests": [],
                        "lockfiles": [],
                        "lifecycleScripts": [],
                        "ignoredFiles": [],
                        "reviewedFiles": ["src/app.py"],
                        "scanCompleteness": {
                            "complete": True,
                            "traversalFailureCount": 0,
                            "fileInspectionFailureCount": 0,
                            "oversizedFileCount": 0,
                            "unsafePathCount": 0,
                            "dependencyAnalysisFailureCount": 0,
                            "policyExcludedFileCount": 0,
                            "resourceBudgetExceededCount": 0,
                            "issueCount": 0,
                        },
                    }
                )
                connection.execute(
                    "INSERT INTO scans "
                    "(id, project_path, scan_date, overall_risk, findings_json, "
                    "finding_count, finding_summary_json, scan_metadata_json) "
                    "VALUES (1, ?, '2026-01-02', 'high', ?, 1, '{\"test\":1}', ?)",
                    (project, findings, metadata),
                )
                connection.execute(
                    "INSERT INTO notes (project_path, body, created_at) "
                    "VALUES (?, 'keep note', '2026-01-03')",
                    (project,),
                )
                connection.execute(
                    "INSERT INTO project_trust_profiles "
                    "(project_path, profile_json, updated_at) VALUES (?, '{}', '2026-01-04')",
                    (project,),
                )
                connection.execute(
                    "INSERT INTO finding_reviews "
                    "(project_path, fingerprint, status, note, created_at, updated_at) "
                    "VALUES (?, 'cf1_legacy', 'reviewed', 'keep review', "
                    "'2026-01-05', '2026-01-05')",
                    (project,),
                )
                connection.execute(
                    "INSERT INTO trusted_dependency_baselines "
                    "(project_path, baseline_schema_version, dependency_schema_version, "
                    "fingerprint, snapshot_json, source_scan_id, source_scan_date, note, "
                    "created_at, updated_at) "
                    "VALUES (?, 1, 1, 'cfdb2_legacy', '{}', 1, '2026-01-02', "
                    "'keep baseline', '2026-01-06', '2026-01-06')",
                    (project,),
                )
                connection.execute(
                    "INSERT INTO trusted_scan_baselines "
                    "(project_id, scan_id, pinned_at, provenance) "
                    "VALUES (?, 1, '2026-01-07', 'manual')",
                    (project,),
                )
                connection.execute(
                    "INSERT INTO project_activity_events "
                    "(event_id, project_id, event_type, occurred_at, related_scan_id, "
                    "details_json, dedupe_key) "
                    "VALUES ('evt_legacy', ?, 'trusted_scan_baseline_set', "
                    "'2026-01-07', 1, '{}', 'legacy')",
                    (project,),
                )
                connection.execute(
                    "INSERT INTO project_review_checkpoints "
                    "(checkpoint_id, project_id, scan_id, baseline_scan_id, "
                    "baseline_provenance, expectations_fingerprint, "
                    "dependency_analysis_fingerprint, dependency_approval_fingerprint, "
                    "dependency_approval_state, finding_reviews_fingerprint, "
                    "baseline_findings_fingerprint, new_critical_high_count, "
                    "finding_review_complete, unresolved_critical_count, "
                    "unresolved_high_count, coverage_fingerprint, metadata_reliable, "
                    "checkpoint_schema_version, evaluator_version, evidence_fingerprint, "
                    "created_at, provenance) "
                    "VALUES ('checkpoint_legacy', ?, 1, 1, 'manual', 'cpex1_legacy', "
                    "'cfdb2_legacy', 'cfdb2_legacy', 'approved', 'cpfr1_legacy', "
                    "'cpbf1_legacy', 0, 1, 0, 0, 'cpcov1_legacy', 1, 1, 2, "
                    "'cp1_legacy', '2026-01-08', 'manual')",
                    (project,),
                )
            connection.commit()
        finally:
            connection.close()

    def create_pre_checkpoint_column_legacy(self) -> None:
        connection = self.raw_connection()
        try:
            for statement in state_lifecycle.SCHEMA_STATEMENTS:
                if "project_review_checkpoints" not in statement:
                    connection.execute(statement)
            connection.executescript(LEGACY_CHECKPOINT_SCHEMA)
            connection.commit()
        finally:
            connection.close()

    def create_v1(self, *, realistic: bool = False) -> None:
        self.create_current_unversioned(realistic=realistic)
        connection = self.raw_connection()
        try:
            connection.execute("PRAGMA user_version = 1")
            connection.commit()
        finally:
            connection.close()

    def backup_files(self) -> list[Path]:
        directory = state_lifecycle.migration_backup_directory(self.database_path)
        return sorted(directory.glob("*")) if directory.exists() else []

    def schema_snapshot(self) -> dict[str, list[tuple[object, ...]]]:
        connection = self.raw_connection()
        try:
            tables = [
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_schema "
                    "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
                )
            ]
            return {
                table: [
                    tuple(row)
                    for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid")
                ]
                for table in tables
            }
        finally:
            connection.close()

    def assert_current_database(self) -> None:
        connection = self.raw_connection()
        try:
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                state_lifecycle.DATABASE_SCHEMA_VERSION,
            )
            self.assertEqual(
                connection.execute("PRAGMA integrity_check").fetchone()[0],
                "ok",
            )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(scans)")
            }
            self.assertTrue(
                {
                    "finding_count",
                    "reviewed_file_count",
                    "ignored_file_count",
                    "finding_summary_json",
                    "scan_metadata_json",
                }.issubset(columns)
            )
            checkpoint_columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(project_review_checkpoints)"
                )
            }
            self.assertTrue(
                {
                    "baseline_findings_fingerprint",
                    "new_critical_high_count",
                }.issubset(checkpoint_columns)
            )
            self.assertEqual(
                connection.execute("PRAGMA foreign_key_check").fetchall(),
                [],
            )
        finally:
            connection.close()

    def test_new_and_empty_databases_publish_v1_without_backup(self) -> None:
        database.init_db()
        self.assert_current_database()
        self.assertEqual(self.backup_files(), [])
        connection = database.get_connection()
        try:
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(
                connection.execute("PRAGMA busy_timeout").fetchone()[0],
                state_lifecycle.DATABASE_BUSY_TIMEOUT_MS,
            )
        finally:
            connection.close()

        empty_path = self.base / "empty.db"
        database.DB_PATH = empty_path
        connection = sqlite3.connect(empty_path)
        connection.execute("PRAGMA application_id = 1196180289")
        connection.commit()
        connection.close()
        database.init_db()
        self.assertEqual(
            self._pragma_value(empty_path, "user_version"),
            state_lifecycle.DATABASE_SCHEMA_VERSION,
        )
        self.assertFalse(
            state_lifecycle.migration_backup_directory(empty_path).exists()
        )

    def test_current_database_startup_is_byte_idempotent_and_creates_no_backup(self) -> None:
        database.init_db()
        before = self.database_path.read_bytes()
        database.init_db()
        database.init_db()
        self.assertEqual(self.database_path.read_bytes(), before)
        self.assertEqual(self.backup_files(), [])

    def test_supported_historical_shapes_migrate_once(self) -> None:
        creators = {
            "minimal early": lambda: self.create_core_legacy(with_record=False),
            "core with records": self.create_core_legacy,
            "scan history before checkpoint additions": self.create_pre_checkpoint_column_legacy,
            "complete 0.9.2": self.create_current_unversioned,
            "installed 0.9.5 schema v1": self.create_v1,
        }
        for index, (label, creator) in enumerate(creators.items()):
            with self.subTest(shape=label):
                case_directory = self.base / f"legacy-{index}"
                case_directory.mkdir()
                path = case_directory / "glacial.db"
                database.DB_PATH = path
                self.database_path = path
                creator()
                database.init_db()
                self.assert_current_database()
                self.assertEqual(len(self.backup_files()), 1)
                database.init_db()
                self.assertEqual(len(self.backup_files()), 1)

    def test_v1_installed_predecessor_migrates_once_without_changing_records(self) -> None:
        self.create_v1(realistic=True)
        before = self.schema_snapshot()

        database.init_db()

        self.assert_current_database()
        self.assertEqual(self.schema_snapshot(), before)
        backups = self.backup_files()
        self.assertEqual(len(backups), 1)
        self.assertEqual(self._pragma_value(backups[0], "user_version"), 1)
        after_first_start = self.database_path.read_bytes()
        database.init_db()
        self.assertEqual(self.database_path.read_bytes(), after_first_start)
        self.assertEqual(len(self.backup_files()), 1)

    def test_realistic_related_records_and_verified_backup_survive_migration(self) -> None:
        self.create_current_unversioned(realistic=True)
        before = self.schema_snapshot()

        database.init_db()

        self.assert_current_database()
        after = self.schema_snapshot()
        self.assertEqual(after, before)
        backups = self.backup_files()
        self.assertEqual(len(backups), 1)
        backup = sqlite3.connect(backups[0])
        try:
            self.assertEqual(backup.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertEqual(backup.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(
                backup.execute("SELECT COUNT(*) FROM project_review_checkpoints").fetchone()[0],
                1,
            )
        finally:
            backup.close()

    def test_future_unsupported_and_corrupt_state_fail_without_mutation(self) -> None:
        cases: list[tuple[str, object, str]] = []

        def future() -> None:
            connection = self.raw_connection()
            connection.execute(
                f"PRAGMA user_version = {state_lifecycle.DATABASE_SCHEMA_VERSION + 1}"
            )
            connection.commit()
            connection.close()

        def unsupported() -> None:
            connection = self.raw_connection()
            connection.execute("CREATE TABLE unrelated_state (id INTEGER)")
            connection.commit()
            connection.close()

        def corrupt() -> None:
            self.database_path.write_bytes(b"not a sqlite database")

        cases.extend(
            [
                ("future", future, "newer Glacial version"),
                ("unsupported", unsupported, "unsupported unversioned database shape"),
                ("corrupt", corrupt, "original state was preserved"),
            ]
        )
        for index, (label, creator, message) in enumerate(cases):
            with self.subTest(case=label):
                path = self.base / f"{label}-{index}.db"
                database.DB_PATH = path
                self.database_path = path
                creator()
                before = path.read_bytes()
                with self.assertRaisesRegex(
                    state_lifecycle.DatabaseStateError,
                    message,
                ):
                    database.init_db()
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(self.backup_files(), [])

    def test_malformed_legacy_json_fails_closed_without_backup(self) -> None:
        self.create_core_legacy(with_record=False)
        connection = self.raw_connection()
        connection.execute(
            "INSERT INTO scans "
            "(project_path, scan_date, overall_risk, findings_json) "
            "VALUES ('C:/project', '2026-01-01', 'high', '{bad json')"
        )
        connection.commit()
        connection.close()
        before = self.database_path.read_bytes()

        with self.assertRaisesRegex(
            state_lifecycle.DatabaseStateError,
            "malformed persisted JSON",
        ):
            database.init_db()

        self.assertEqual(self.database_path.read_bytes(), before)
        self.assertEqual(self.backup_files(), [])

    def test_backup_publication_is_atomic_and_collision_never_overwrites(self) -> None:
        self.create_core_legacy()
        real_link = state_lifecycle.os.link
        observed: list[tuple[bool, bool]] = []

        def observed_link(source: Path, destination: Path) -> None:
            observed.append((source.is_file(), destination.exists()))
            real_link(source, destination)

        with (
            patch.object(
                state_lifecycle,
                "_backup_name",
                return_value="glacial-pre-migration-test.db",
            ),
            patch.object(state_lifecycle.os, "link", side_effect=observed_link),
        ):
            database.init_db()
        self.assertEqual(observed, [(True, False)])
        self.assertEqual(
            [path.name for path in self.backup_files()],
            ["glacial-pre-migration-test.db"],
        )
        self.assertFalse(any(path.name.endswith(".tmp") for path in self.backup_files()))

        collision_path = self.base / "collision.db"
        database.DB_PATH = collision_path
        self.database_path = collision_path
        self.create_core_legacy()
        backup_directory = state_lifecycle.migration_backup_directory(collision_path)
        backup_directory.mkdir(exist_ok=True)
        collision = backup_directory / "glacial-pre-migration-test.db"
        collision.write_bytes(b"existing backup")
        with (
            patch.object(
                state_lifecycle,
                "_backup_name",
                return_value=collision.name,
            ),
            self.assertRaisesRegex(
                state_lifecycle.DatabaseStateError,
                "collision",
            ),
        ):
            database.init_db()
        self.assertEqual(collision.read_bytes(), b"existing backup")
        connection = self.raw_connection()
        try:
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                0,
            )
        finally:
            connection.close()

    def test_backup_failure_cleans_temporary_file_and_prevents_migration(self) -> None:
        self.create_core_legacy()
        before = self.schema_snapshot()

        def fail_backup(source: sqlite3.Connection, temporary: Path) -> None:
            temporary.write_bytes(b"incomplete")
            raise sqlite3.OperationalError("injected backup failure")

        with (
            patch.object(
                state_lifecycle,
                "_copy_database_to_backup",
                side_effect=fail_backup,
            ),
            self.assertRaisesRegex(
                state_lifecycle.DatabaseStateError,
                "original state was preserved",
            ),
        ):
            database.init_db()

        self.assertEqual(self.schema_snapshot(), before)
        self.assertEqual(self.backup_files(), [])
        self.assertFalse(
            any(
                path.name.endswith((".tmp", "-journal", "-wal", "-shm"))
                for path in self.base.rglob("*")
            )
        )

    def test_migration_failure_rolls_back_schema_and_version_then_retry_recovers(self) -> None:
        self.create_core_legacy()
        before = self.schema_snapshot()

        with (
            patch.object(
                state_lifecycle,
                "_publish_schema_version",
                side_effect=RuntimeError("injected publication failure"),
            ),
            self.assertRaisesRegex(RuntimeError, "injected publication failure"),
        ):
            database.init_db()

        self.assertEqual(self.schema_snapshot(), before)
        connection = self.raw_connection()
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertNotIn(
                "finding_count",
                {
                    row["name"]
                    for row in connection.execute("PRAGMA table_info(scans)")
                },
            )
        finally:
            connection.close()
        backups = self.backup_files()
        self.assertEqual(len(backups), 1)
        self.assertEqual(self._pragma_value(backups[0], "integrity_check"), "ok")

        database.init_db()
        self.assert_current_database()
        self.assertEqual(len(self.backup_files()), 2)
        self.assertFalse(
            any(path.name.endswith(".tmp") for path in self.backup_files())
        )

    @staticmethod
    def _pragma_value(path: Path, pragma: str) -> object:
        connection = sqlite3.connect(path)
        try:
            return connection.execute(f"PRAGMA {pragma}").fetchone()[0]
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
