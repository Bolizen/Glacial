from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import stat
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from .state_lifecycle import (
    DATABASE_SCHEMA_VERSION,
    SCHEMA_STATEMENTS,
    DatabaseStateError,
    _is_linked_or_reparse,
    _prepare_safe_backup_directory,
    migration_backup_directory,
)


RESET_CONFIRMATION = "RESET GLACIAL APPLICATION DATA"
RECOVERY_BACKUP_DIRECTORY = "recovery-backups"
RUNTIME_PATH_ENVIRONMENTS = {
    "applicationExecutable": "GLACIAL_DESKTOP_APPLICATION_EXECUTABLE",
    "installationDirectory": "GLACIAL_DESKTOP_INSTALL_DIR",
    "backendExecutable": "GLACIAL_DESKTOP_BACKEND_EXECUTABLE",
    "runtimeFiles": "GLACIAL_DESKTOP_RUNTIME_DIR",
    "logDirectory": "GLACIAL_DESKTOP_LOG_DIR",
    "temporaryDirectory": "GLACIAL_DESKTOP_TEMP_DIR",
}


def recovery_backup_directory(database_path: Path) -> Path:
    return database_path.parent / RECOVERY_BACKUP_DIRECTORY


def runtime_path_contract(database_path: Path) -> dict[str, object]:
    resolved_database = database_path.resolve(strict=False)
    data_directory = resolved_database.parent
    runtime = {
        name: str(_absolute_runtime_path(environment))
        for name, environment in RUNTIME_PATH_ENVIRONMENTS.items()
    }
    runtime.update(
        {
            "applicationData": str(data_directory),
            "database": str(resolved_database),
            "configuration": (
                f"{resolved_database} (settings table; no separate configuration file)"
            ),
            "migrationBackups": str(migration_backup_directory(resolved_database)),
            "recoveryBackups": str(recovery_backup_directory(resolved_database)),
            "installerMetadata": (
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Glacial"
            ),
            "uninstaller": str(
                Path(runtime["installationDirectory"]) / "uninstall.exe"
            ),
        }
    )
    return {
        "paths": runtime,
        "uninstall": {
            "default": "preserve-application-data",
            "optionalRemoval": (
                "Selecting “Delete the application data” removes both "
                r"%APPDATA%\com.glacial.desktop and "
                r"%LOCALAPPDATA%\com.glacial.desktop."
            ),
            "projectFiles": "never removed",
        },
    }


def reset_application_state(
    database_path: Path,
    initializer: Callable[[], None],
    *,
    confirmation: str,
    default_workspace_root: str,
) -> dict[str, object]:
    if confirmation != RESET_CONFIRMATION:
        raise DatabaseStateError(
            "Application-state reset requires the exact confirmation phrase."
        )

    database_path = database_path.resolve(strict=False)
    data_directory = database_path.parent
    data_directory.mkdir(parents=True, exist_ok=True)
    _require_safe_directory(data_directory)

    if not database_path.exists():
        initializer()
        return {
            "reset": True,
            "backup": None,
            "message": (
                "No existing SQLite state was present. Glacial initialized clean "
                "application state; project files were not changed."
            ),
        }

    _require_safe_regular_file(database_path, "database")
    backup_path = _create_recovery_backup(database_path)
    if _database_is_valid(database_path):
        _reset_valid_database(
            database_path,
            default_workspace_root=default_workspace_root,
        )
        initializer()
        return _reset_result(backup_path)

    pending_path = data_directory / (
        f".glacial-reset-{secrets.token_hex(12)}.pending"
    )
    moved_sidecars: list[tuple[Path, Path]] = []
    sidecars = [
        Path(f"{database_path}{suffix}")
        for suffix in ("-journal", "-wal", "-shm")
        if Path(f"{database_path}{suffix}").exists()
    ]
    for sidecar in sidecars:
        _require_safe_regular_file(sidecar, "database sidecar")
    database_moved = False
    initializer_started = False

    try:
        os.replace(database_path, pending_path)
        database_moved = True
        for sidecar in sidecars:
            pending_sidecar = Path(f"{pending_path}{sidecar.name.removeprefix(database_path.name)}")
            os.replace(sidecar, pending_sidecar)
            moved_sidecars.append((sidecar, pending_sidecar))
        initializer_started = True
        initializer()
    except Exception as exc:
        if initializer_started:
            _remove_new_database_files(database_path)
        try:
            if database_moved:
                os.replace(pending_path, database_path)
            for sidecar, pending_sidecar in moved_sidecars:
                if pending_sidecar.exists():
                    os.replace(pending_sidecar, sidecar)
        except OSError as restore_exc:
            raise DatabaseStateError(
                "Glacial could not initialize clean state or restore the prior "
                f"database. A recovery backup remains at {backup_path}."
            ) from restore_exc
        if not database_moved:
            raise DatabaseStateError(
                "Glacial could not obtain exclusive access to reset the database. "
                "The original state was preserved; close other Glacial processes "
                f"and retry. A recovery backup remains at {backup_path}."
            ) from exc
        raise DatabaseStateError(
            "Glacial could not initialize clean state. The prior database was "
            f"restored and a recovery backup remains at {backup_path}."
        ) from exc

    _remove_regular_file(pending_path)
    for _, pending_sidecar in moved_sidecars:
        _remove_regular_file(pending_sidecar)
    return _reset_result(backup_path)


def _reset_valid_database(
    database_path: Path,
    *,
    default_workspace_root: str,
) -> None:
    connection = sqlite3.connect(database_path, timeout=5)
    try:
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("BEGIN EXCLUSIVE")
        try:
            objects = connection.execute(
                "SELECT name FROM sqlite_schema "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
                "ORDER BY name DESC"
            ).fetchall()
            for (name,) in objects:
                quoted = str(name).replace('"', '""')
                connection.execute(f'DROP TABLE "{quoted}"')
            for statement in SCHEMA_STATEMENTS:
                connection.execute(statement)
            connection.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)",
                ("project_root", default_workspace_root),
            )
            connection.execute(
                f"PRAGMA user_version = {DATABASE_SCHEMA_VERSION}"
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        connection.execute("PRAGMA foreign_keys = ON")
        row = connection.execute("PRAGMA integrity_check").fetchone()
        if row is None or row[0] != "ok":
            raise DatabaseStateError(
                "Glacial reset the database but could not verify clean state. "
                f"A recovery backup remains at {recovery_backup_directory(database_path)}."
            )
    except DatabaseStateError:
        raise
    except (OSError, sqlite3.DatabaseError) as exc:
        raise DatabaseStateError(
            "Glacial could not obtain exclusive access to reset the database. "
            "The original state was preserved; close other Glacial processes "
            "and retry."
        ) from exc
    finally:
        connection.close()


def _reset_result(backup_path: Path) -> dict[str, object]:
    return {
        "reset": True,
        "backup": str(backup_path),
        "message": (
            "Glacial application state was reset and a recovery backup was "
            "preserved. Registered project files were not changed."
        ),
    }


def _absolute_runtime_path(environment: str) -> Path:
    value = os.getenv(environment)
    if value is None or not value or "\0" in value:
        raise DatabaseStateError(
            "Glacial could not determine its installed runtime paths."
        )
    path = Path(value)
    if not path.is_absolute() or any(part == ".." for part in path.parts):
        raise DatabaseStateError(
            "Glacial could not determine its installed runtime paths."
        )
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise DatabaseStateError(
            "Glacial could not determine its installed runtime paths."
        ) from exc


def _create_recovery_backup(database_path: Path) -> Path:
    backup_directory = recovery_backup_directory(database_path)
    _prepare_safe_backup_directory(database_path.parent, backup_directory)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    final_path = backup_directory / (
        f"glacial-before-reset-{timestamp}-{secrets.token_hex(6)}.db"
    )
    temporary_path = backup_directory / f".{final_path.name}.{secrets.token_hex(8)}.tmp"
    descriptor = os.open(
        temporary_path,
        os.O_CREAT | os.O_EXCL | os.O_RDWR,
        stat.S_IRUSR | stat.S_IWUSR,
    )
    os.close(descriptor)
    published = False
    try:
        if _database_is_valid(database_path):
            source = sqlite3.connect(
                f"{database_path.resolve(strict=True).as_uri()}?mode=ro",
                uri=True,
                timeout=0.25,
            )
            destination = sqlite3.connect(temporary_path)
            try:
                source.backup(destination)
            finally:
                destination.close()
                source.close()
            _require_valid_sqlite_backup(temporary_path)
        else:
            _copy_and_verify_raw(database_path, temporary_path)
        os.link(temporary_path, final_path)
        published = True
        temporary_path.unlink()
        _require_safe_regular_file(final_path, "recovery backup")
        return final_path
    except Exception:
        if published:
            _remove_regular_file(final_path)
        raise
    finally:
        _remove_regular_file(temporary_path)
        for suffix in ("-journal", "-wal", "-shm"):
            _remove_regular_file(Path(f"{temporary_path}{suffix}"))


def _database_is_valid(database_path: Path) -> bool:
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            f"{database_path.resolve(strict=True).as_uri()}?mode=ro",
            uri=True,
            timeout=0.25,
        )
        row = connection.execute("PRAGMA integrity_check").fetchone()
        return row is not None and row[0] == "ok"
    except sqlite3.DatabaseError as exc:
        message = str(exc).lower()
        if "not a database" in message or "malformed" in message:
            return False
        raise DatabaseStateError(
            "Glacial could not read the database for reset. Close other Glacial "
            "processes and retry; no application state was deleted."
        ) from exc
    finally:
        if connection is not None:
            connection.close()


def _require_valid_sqlite_backup(path: Path) -> None:
    connection = sqlite3.connect(
        f"{path.resolve(strict=True).as_uri()}?mode=ro",
        uri=True,
    )
    try:
        row = connection.execute("PRAGMA integrity_check").fetchone()
        if row is None or row[0] != "ok":
            raise DatabaseStateError(
                "Glacial could not verify the recovery backup; no state was reset."
            )
    finally:
        connection.close()


def _copy_and_verify_raw(source: Path, destination: Path) -> None:
    source_hash = hashlib.sha256()
    with source.open("rb") as reader, destination.open("wb") as writer:
        while chunk := reader.read(1024 * 1024):
            source_hash.update(chunk)
            writer.write(chunk)
        writer.flush()
        os.fsync(writer.fileno())
    destination_hash = hashlib.sha256()
    with destination.open("rb") as reader:
        while chunk := reader.read(1024 * 1024):
            destination_hash.update(chunk)
    if (
        source.stat().st_size != destination.stat().st_size
        or source_hash.digest() != destination_hash.digest()
    ):
        raise DatabaseStateError(
            "Glacial could not verify the raw recovery backup; no state was reset."
        )


def _require_safe_directory(path: Path) -> None:
    status = path.lstat()
    if (
        not stat.S_ISDIR(status.st_mode)
        or _is_linked_or_reparse(path, status)
        or path.resolve(strict=True) != path
    ):
        raise DatabaseStateError(
            "The application data directory is linked or unsafe for reset."
        )


def _require_safe_regular_file(path: Path, label: str) -> None:
    status = path.lstat()
    if not stat.S_ISREG(status.st_mode) or _is_linked_or_reparse(path, status):
        raise DatabaseStateError(
            f"The {label} is linked or unsafe; no application state was reset."
        )


def _remove_new_database_files(database_path: Path) -> None:
    for path in (
        database_path,
        Path(f"{database_path}-journal"),
        Path(f"{database_path}-wal"),
        Path(f"{database_path}-shm"),
    ):
        _remove_regular_file(path)


def _remove_regular_file(path: Path) -> None:
    try:
        if path.exists():
            _require_safe_regular_file(path, "reset artifact")
            path.unlink()
    except FileNotFoundError:
        pass
