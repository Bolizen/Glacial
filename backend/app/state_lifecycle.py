from __future__ import annotations

import os
import secrets
import sqlite3
import stat
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ContextManager


DATABASE_SCHEMA_VERSION = 2
DATABASE_BUSY_TIMEOUT_MS = 5_000
MIGRATION_BACKUP_DIRECTORY = "migration-backups"


class DatabaseStateError(RuntimeError):
    """A bounded startup failure that preserves application-owned state."""


SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS projects (
        path TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        project_type TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_path TEXT NOT NULL,
        scan_date TEXT NOT NULL,
        overall_risk TEXT NOT NULL,
        findings_json TEXT NOT NULL,
        finding_count INTEGER NOT NULL DEFAULT 0,
        reviewed_file_count INTEGER NOT NULL DEFAULT 0,
        ignored_file_count INTEGER NOT NULL DEFAULT 0,
        finding_summary_json TEXT NOT NULL DEFAULT '{}',
        scan_metadata_json TEXT NOT NULL DEFAULT '{}'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_path TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS project_trust_profiles (
        project_path TEXT PRIMARY KEY,
        profile_json TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS finding_reviews (
        project_path TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('reviewed', 'expected')),
        note TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (project_path, fingerprint)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS finding_reviews_project_path
    ON finding_reviews (project_path)
    """,
    """
    CREATE TABLE IF NOT EXISTS trusted_dependency_baselines (
        project_path TEXT PRIMARY KEY,
        baseline_schema_version INTEGER NOT NULL,
        dependency_schema_version INTEGER NOT NULL,
        fingerprint TEXT NOT NULL,
        snapshot_json TEXT NOT NULL,
        source_scan_id INTEGER,
        source_scan_date TEXT NOT NULL DEFAULT '',
        note TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS trusted_scan_baselines (
        project_id TEXT PRIMARY KEY,
        scan_id INTEGER NOT NULL,
        pinned_at TEXT NOT NULL,
        provenance TEXT NOT NULL DEFAULT 'manual'
            CHECK (provenance IN ('manual')),
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS project_activity_events (
        event_id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        occurred_at TEXT NOT NULL,
        related_scan_id INTEGER,
        details_json TEXT NOT NULL DEFAULT '{}',
        dedupe_key TEXT,
        UNIQUE (project_id, dedupe_key)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS project_activity_events_project_time
    ON project_activity_events (project_id, occurred_at DESC, event_id DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS project_review_checkpoints (
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
        baseline_findings_fingerprint TEXT NOT NULL DEFAULT '',
        new_critical_high_count INTEGER NOT NULL DEFAULT 0,
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
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS project_review_checkpoints_project_time
    ON project_review_checkpoints (project_id, created_at DESC, checkpoint_id DESC)
    """,
)

REQUIRED_COLUMNS = {
    "settings": {"key", "value"},
    "projects": {"path", "name", "description", "project_type", "created_at"},
    "scans": {
        "id",
        "project_path",
        "scan_date",
        "overall_risk",
        "findings_json",
        "finding_count",
        "reviewed_file_count",
        "ignored_file_count",
        "finding_summary_json",
        "scan_metadata_json",
    },
    "notes": {"id", "project_path", "body", "created_at"},
    "project_trust_profiles": {"project_path", "profile_json", "updated_at"},
    "finding_reviews": {
        "project_path",
        "fingerprint",
        "status",
        "note",
        "created_at",
        "updated_at",
    },
    "trusted_dependency_baselines": {
        "project_path",
        "baseline_schema_version",
        "dependency_schema_version",
        "fingerprint",
        "snapshot_json",
        "source_scan_id",
        "source_scan_date",
        "note",
        "created_at",
        "updated_at",
    },
    "trusted_scan_baselines": {
        "project_id",
        "scan_id",
        "pinned_at",
        "provenance",
    },
    "project_activity_events": {
        "event_id",
        "project_id",
        "event_type",
        "occurred_at",
        "related_scan_id",
        "details_json",
        "dedupe_key",
    },
    "project_review_checkpoints": {
        "checkpoint_id",
        "project_id",
        "scan_id",
        "baseline_scan_id",
        "baseline_provenance",
        "expectations_fingerprint",
        "dependency_analysis_fingerprint",
        "dependency_approval_fingerprint",
        "dependency_approval_state",
        "finding_reviews_fingerprint",
        "baseline_findings_fingerprint",
        "new_critical_high_count",
        "finding_review_complete",
        "unresolved_critical_count",
        "unresolved_high_count",
        "coverage_fingerprint",
        "metadata_reliable",
        "checkpoint_schema_version",
        "evaluator_version",
        "evidence_fingerprint",
        "created_at",
        "provenance",
    },
}

LEGACY_REQUIRED_COLUMNS = {
    **REQUIRED_COLUMNS,
    "scans": {
        "id",
        "project_path",
        "scan_date",
        "overall_risk",
        "findings_json",
    },
    "project_review_checkpoints": REQUIRED_COLUMNS[
        "project_review_checkpoints"
    ].difference({"baseline_findings_fingerprint", "new_critical_high_count"}),
}

CORE_LEGACY_TABLES = {"settings", "projects", "scans", "notes"}
REQUIRED_INDEXES = {
    "finding_reviews_project_path",
    "project_activity_events_project_time",
    "project_review_checkpoints_project_time",
}
REQUIRED_FOREIGN_KEYS = {
    ("trusted_scan_baselines", "scan_id", "scans", "id"),
    ("project_review_checkpoints", "scan_id", "scans", "id"),
    ("project_review_checkpoints", "baseline_scan_id", "scans", "id"),
}
REQUIRED_SQL_MARKERS = {
    "finding_reviews": (
        "primary key (project_path, fingerprint)",
        "check (status in ('reviewed', 'expected'))",
    ),
    "trusted_scan_baselines": (
        "check (provenance in ('manual'))",
        "foreign key (scan_id) references scans(id)",
    ),
    "project_activity_events": ("unique (project_id, dedupe_key)",),
    "project_review_checkpoints": (
        "check (baseline_provenance in ('manual', 'automatic', 'none'))",
        "check (finding_review_complete in (0, 1))",
        "check (metadata_reliable in (0, 1))",
        "foreign key (scan_id) references scans(id)",
        "foreign key (baseline_scan_id) references scans(id)",
    ),
}
def configure_connection(connection: sqlite3.Connection) -> None:
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(f"PRAGMA busy_timeout = {DATABASE_BUSY_TIMEOUT_MS}")


def initialize_database(
    database_path: Path,
    connection_factory: Callable[[], ContextManager[sqlite3.Connection]],
    *,
    default_workspace_root: str,
) -> None:
    backup_path: Path | None = None
    connection: sqlite3.Connection | None = None
    try:
        try:
            with connection_factory() as connection:
                configure_connection(connection)
                source_version = _user_version(connection)
                if source_version > DATABASE_SCHEMA_VERSION:
                    raise DatabaseStateError(
                        "Glacial state uses unsupported database schema version "
                        f"{source_version}; open it with a newer Glacial version. "
                        "The database was not changed."
                    )
                if source_version == DATABASE_SCHEMA_VERSION:
                    _verify_current_database(connection, require_version=True)
                    return
                if source_version not in {0, 1}:
                    raise DatabaseStateError(
                        f"Glacial does not support database schema version {source_version}. "
                        "The database was not changed; restore a verified compatible backup."
                    )

                _require_integrity(connection, "source database")
                source_shape = _schema_shape(connection)
                application_tables = set(source_shape)
                is_new_database = not application_tables
                if not is_new_database:
                    if source_version == 0:
                        _validate_legacy_shape(connection, source_shape)
                    else:
                        _verify_current_database(connection, require_version=False)
                    schema_version_before_backup = _schema_change_counter(connection)
                    data_version_before_backup = _data_change_counter(connection)
                    backup_path = _create_verified_backup(
                        connection,
                        database_path,
                        source_version=source_version,
                    )
                else:
                    schema_version_before_backup = _schema_change_counter(connection)
                    data_version_before_backup = _data_change_counter(connection)

                connection.execute("BEGIN IMMEDIATE")
                try:
                    if (
                        _user_version(connection) != source_version
                        or _schema_change_counter(connection) != schema_version_before_backup
                        or _data_change_counter(connection) != data_version_before_backup
                    ):
                        raise DatabaseStateError(
                            "Glacial state changed while startup was preparing the schema. "
                            "Close other Glacial processes and retry; the database was not migrated."
                        )
                    _apply_migrations(
                        connection,
                        source_version,
                        default_workspace_root=default_workspace_root,
                    )
                    _verify_current_database(connection, require_version=False)
                    _publish_schema_version(connection, DATABASE_SCHEMA_VERSION)
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
        finally:
            if connection is not None:
                connection.close()
    except DatabaseStateError:
        raise
    except (OSError, sqlite3.DatabaseError) as exc:
        recovery = (
            f" A verified pre-migration backup remains at {backup_path.name}."
            if backup_path
            else ""
        )
        raise DatabaseStateError(
            "Glacial could not validate or migrate its database. The original state "
            "was preserved; close Glacial and restore a verified compatible backup "
            f"or explicitly reset application-owned state.{recovery}"
        ) from exc

    try:
        _verify_published_database(database_path)
    except (OSError, sqlite3.DatabaseError, DatabaseStateError) as exc:
        recovery = (
            f" A verified pre-migration backup remains at {backup_path.name}."
            if backup_path
            else ""
        )
        raise DatabaseStateError(
            "Glacial published a database migration but could not verify the resulting "
            f"state, so normal startup was stopped.{recovery}"
        ) from exc


def migration_backup_directory(database_path: Path) -> Path:
    return database_path.parent / MIGRATION_BACKUP_DIRECTORY


def _apply_migrations(
    connection: sqlite3.Connection,
    source_version: int,
    *,
    default_workspace_root: str,
) -> None:
    version = source_version
    migrations = {
        0: _migrate_legacy_to_v1,
        1: _migrate_v1_to_v2,
    }
    while version < DATABASE_SCHEMA_VERSION:
        migration = migrations.get(version)
        if migration is None:
            raise DatabaseStateError(
                f"No supported migration starts at database schema version {version}."
            )
        migration(connection, default_workspace_root=default_workspace_root)
        version += 1


def _migrate_legacy_to_v1(
    connection: sqlite3.Connection,
    *,
    default_workspace_root: str,
) -> None:
    for statement in SCHEMA_STATEMENTS:
        connection.execute(statement)
    _add_column_if_missing(
        connection,
        "scans",
        "finding_count",
        "INTEGER NOT NULL DEFAULT 0",
    )
    _add_column_if_missing(
        connection,
        "scans",
        "reviewed_file_count",
        "INTEGER NOT NULL DEFAULT 0",
    )
    _add_column_if_missing(
        connection,
        "scans",
        "ignored_file_count",
        "INTEGER NOT NULL DEFAULT 0",
    )
    _add_column_if_missing(
        connection,
        "scans",
        "finding_summary_json",
        "TEXT NOT NULL DEFAULT '{}'",
    )
    _add_column_if_missing(
        connection,
        "scans",
        "scan_metadata_json",
        "TEXT NOT NULL DEFAULT '{}'",
    )
    _add_column_if_missing(
        connection,
        "project_review_checkpoints",
        "baseline_findings_fingerprint",
        "TEXT NOT NULL DEFAULT ''",
    )
    _add_column_if_missing(
        connection,
        "project_review_checkpoints",
        "new_critical_high_count",
        "INTEGER NOT NULL DEFAULT 0",
    )
    connection.execute(
        "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
        ("project_root", default_workspace_root),
    )


def _migrate_v1_to_v2(
    connection: sqlite3.Connection,
    *,
    default_workspace_root: str,
) -> None:
    del default_workspace_root
    _verify_current_database(connection, require_version=False)


def _add_column_if_missing(
    connection: sqlite3.Connection,
    table: str,
    column: str,
    definition: str,
) -> None:
    columns = _table_columns(connection, table)
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _publish_schema_version(
    connection: sqlite3.Connection,
    version: int,
) -> None:
    connection.execute(f"PRAGMA user_version = {version}")


def _validate_legacy_shape(
    connection: sqlite3.Connection,
    shape: dict[str, dict[str, Any]],
) -> None:
    tables = set(shape)
    unknown = tables.difference(REQUIRED_COLUMNS)
    missing_core = CORE_LEGACY_TABLES.difference(tables)
    if unknown or missing_core:
        raise DatabaseStateError(
            "Glacial found an unsupported unversioned database shape. The database "
            "was not changed; use a documented compatible backup or explicit reset."
        )
    for table, details in shape.items():
        missing = LEGACY_REQUIRED_COLUMNS[table].difference(details["columns"])
        if missing:
            raise DatabaseStateError(
                "Glacial found an unsupported unversioned database shape. The database "
                "was not changed; use a documented compatible backup or explicit reset."
            )
        _require_sql_markers(table, details["sql"])


def _verify_current_database(
    connection: sqlite3.Connection,
    *,
    require_version: bool,
) -> None:
    if require_version and _user_version(connection) != DATABASE_SCHEMA_VERSION:
        raise DatabaseStateError("The database schema version was not published correctly.")
    shape = _schema_shape(connection)
    if set(shape) != set(REQUIRED_COLUMNS):
        raise DatabaseStateError(
            "The database does not contain the complete supported Glacial schema."
        )
    for table, required in REQUIRED_COLUMNS.items():
        if required.difference(shape[table]["columns"]):
            raise DatabaseStateError(
                f"The database table {table} is missing required schema columns."
            )
        _require_sql_markers(table, shape[table]["sql"])
    indexes = {
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'index' AND name NOT LIKE 'sqlite_%'"
        )
    }
    if REQUIRED_INDEXES.difference(indexes):
        raise DatabaseStateError("The database is missing required Glacial indexes.")
    foreign_keys = {
        (table, row["from"], row["table"], row["to"])
        for table in REQUIRED_COLUMNS
        for row in connection.execute(f"PRAGMA foreign_key_list({table})")
    }
    if REQUIRED_FOREIGN_KEYS.difference(foreign_keys):
        raise DatabaseStateError(
            "The database is missing required Glacial foreign-key relationships."
        )
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise DatabaseStateError(
            "The database contains invalid foreign-key relationships."
        )
    _require_integrity(connection, "database")
def _require_sql_markers(table: str, sql: str) -> None:
    normalized = " ".join(str(sql or "").lower().split())
    if any(marker not in normalized for marker in REQUIRED_SQL_MARKERS.get(table, ())):
        raise DatabaseStateError(
            f"The database table {table} is missing required constraints."
        )


def _schema_shape(connection: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    rows = connection.execute(
        "SELECT name, sql FROM sqlite_schema "
        "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return {
        row["name"]: {
            "sql": row["sql"] or "",
            "columns": _table_columns(connection, row["name"]),
        }
        for row in rows
    }


def _table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}


def _user_version(connection: sqlite3.Connection) -> int:
    row = connection.execute("PRAGMA user_version").fetchone()
    if row is None:
        raise DatabaseStateError("The database schema version could not be read.")
    return int(row[0])


def _schema_change_counter(connection: sqlite3.Connection) -> int:
    row = connection.execute("PRAGMA schema_version").fetchone()
    return int(row[0])


def _data_change_counter(connection: sqlite3.Connection) -> int:
    row = connection.execute("PRAGMA data_version").fetchone()
    return int(row[0])


def _require_integrity(connection: sqlite3.Connection, label: str) -> None:
    row = connection.execute("PRAGMA integrity_check").fetchone()
    if row is None or row[0] != "ok":
        raise DatabaseStateError(
            f"Glacial could not verify the {label}; the original state was preserved."
        )


def _create_verified_backup(
    source: sqlite3.Connection,
    database_path: Path,
    *,
    source_version: int,
) -> Path:
    backup_directory = migration_backup_directory(database_path)
    _prepare_safe_backup_directory(database_path.parent, backup_directory)
    final_name = _backup_name(source_version)
    final_path = backup_directory / final_name
    temporary_path = backup_directory / f".{final_name}.{secrets.token_hex(8)}.tmp"
    if final_path.exists():
        raise DatabaseStateError(
            "A migration backup name collision was detected; no existing backup "
            "was overwritten and the database was not migrated."
        )
    temporary_created = False
    published = False
    try:
        descriptor = os.open(
            temporary_path,
            os.O_CREAT | os.O_EXCL | os.O_RDWR,
            stat.S_IRUSR | stat.S_IWUSR,
        )
        os.close(descriptor)
        temporary_created = True
        _copy_database_to_backup(source, temporary_path)
        _verify_backup(temporary_path, source_version)
        if final_path.exists():
            raise DatabaseStateError(
                "A migration backup name collision was detected; no existing backup "
                "was overwritten and the database was not migrated."
            )
        os.link(temporary_path, final_path)
        published = True
        temporary_path.unlink()
        temporary_created = False
        _verify_backup(final_path, source_version)
        return final_path
    except Exception:
        if published:
            _remove_owned_backup_artifact(final_path)
        raise
    finally:
        if temporary_created:
            _remove_owned_backup_artifact(temporary_path)
        for suffix in ("-journal", "-wal", "-shm"):
            _remove_owned_backup_artifact(Path(f"{temporary_path}{suffix}"))


def _copy_database_to_backup(
    source: sqlite3.Connection,
    temporary_path: Path,
) -> None:
    destination = sqlite3.connect(temporary_path)
    try:
        source.backup(destination)
    finally:
        destination.close()


def _verify_backup(path: Path, source_version: int) -> None:
    status = path.lstat()
    if not stat.S_ISREG(status.st_mode) or _is_linked_or_reparse(path, status):
        raise DatabaseStateError("The migration backup is not a safe regular file.")
    connection = _open_read_only(path)
    try:
        connection.row_factory = sqlite3.Row
        if _user_version(connection) != source_version:
            raise DatabaseStateError(
                "The migration backup schema version does not match its source."
            )
        _require_integrity(connection, "migration backup")
        if source_version == 0:
            _validate_legacy_shape(connection, _schema_shape(connection))
        else:
            _verify_current_database(connection, require_version=False)
    finally:
        connection.close()


def _verify_published_database(path: Path) -> None:
    connection = _open_read_only(path)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        _verify_current_database(connection, require_version=True)
    finally:
        connection.close()


def _open_read_only(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"{path.resolve(strict=True).as_uri()}?mode=ro", uri=True)


def _prepare_safe_backup_directory(data_directory: Path, backup_directory: Path) -> None:
    data_status = data_directory.lstat()
    if (
        not stat.S_ISDIR(data_status.st_mode)
        or _is_linked_or_reparse(data_directory, data_status)
    ):
        raise DatabaseStateError(
            "The application data directory is linked or unsafe for migration backups."
        )
    backup_directory.mkdir(mode=0o700, exist_ok=True)
    backup_status = backup_directory.lstat()
    if (
        not stat.S_ISDIR(backup_status.st_mode)
        or _is_linked_or_reparse(backup_directory, backup_status)
        or backup_directory.parent.resolve(strict=True)
        != data_directory.resolve(strict=True)
    ):
        raise DatabaseStateError(
            "The migration backup directory is linked or outside application-owned state."
        )


def _is_linked_or_reparse(path: Path, status: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(status, "st_file_attributes", 0)
    return path.is_symlink() or bool(attributes & reparse_flag)


def _backup_name(source_version: int) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return (
        f"glacial-pre-migration-v{source_version}-to-v{DATABASE_SCHEMA_VERSION}-"
        f"{timestamp}-{secrets.token_hex(6)}.db"
    )


def _remove_owned_backup_artifact(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
