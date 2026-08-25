from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from .finding_evidence import normalize_suspicious_text_evidence
from .finding_explainability import normalize_finding_explainability
from .privacy import sanitize_scan_value
from .state_lifecycle import (
    DATABASE_SCHEMA_VERSION,
    configure_connection,
    initialize_database,
)


DESKTOP_DATA_DIR_ENV = "GLACIAL_DESKTOP_DATA_DIR"
REPOSITORY_DB_DIR = Path(__file__).resolve().parent.parent / "data"
def resolved_database_path(value: str | None, *, environment_present: bool) -> Path:
    if not environment_present:
        return REPOSITORY_DB_DIR / "glacial.db"
    if value is None or not value or "\0" in value:
        raise ValueError(f"{DESKTOP_DATA_DIR_ENV} must contain an absolute data directory")

    candidate = Path(value)
    if not candidate.is_absolute() or any(part == ".." for part in candidate.parts):
        raise ValueError(f"{DESKTOP_DATA_DIR_ENV} must contain an absolute data directory")
    try:
        normalized = candidate.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{DESKTOP_DATA_DIR_ENV} contains an invalid data directory") from exc
    return normalized / "glacial.db"


DB_PATH = resolved_database_path(
    os.getenv(DESKTOP_DATA_DIR_ENV),
    environment_present=DESKTOP_DATA_DIR_ENV in os.environ,
)
DB_DIR = DB_PATH.parent
DEFAULT_WORKSPACE_ROOT = str(Path.home() / "GlacialProjects")
WORKSPACE_ROOT_SETTING = "project_root"


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    configure_connection(connection)
    return connection


def prepare_database_directory() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def init_db() -> None:
    initialize_database(
        DB_PATH,
        get_connection,
        default_workspace_root=DEFAULT_WORKSPACE_ROOT,
    )


def get_setting(key: str) -> str | None:
    with get_connection() as connection:
        row = connection.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None


def set_setting(key: str, value: str) -> None:
    with get_connection() as connection:
        connection.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def latest_scan_map() -> dict[str, sqlite3.Row]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT s.*
            FROM scans s
            JOIN (
                SELECT project_path, MAX(scan_date) AS scan_date
                FROM scans
                GROUP BY project_path
            ) latest
            ON latest.project_path = s.project_path AND latest.scan_date = s.scan_date
            """
        ).fetchall()
        return {row["project_path"]: row for row in rows}


def note_counts() -> dict[str, int]:
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT project_path, COUNT(*) AS note_count FROM notes GROUP BY project_path"
        ).fetchall()
        return {row["project_path"]: row["note_count"] for row in rows}


def row_to_scan(row: sqlite3.Row) -> dict[str, Any]:
    findings, findings_reliable = _load_findings(row)
    finding_count = _row_value(row, "finding_count", len(findings))
    if not isinstance(finding_count, int) or isinstance(finding_count, bool) or finding_count < 0:
        finding_count = len(findings)
    metadata = sanitize_scan_value(
        _load_scan_metadata(row),
        project_root=row["project_path"],
    )
    if finding_count == 0 and findings:
        finding_count = len(findings)
    return {
        "id": row["id"],
        "project_path": row["project_path"],
        "scan_date": row["scan_date"],
        "overall_risk": row["overall_risk"],
        "findings": findings,
        "findingCount": finding_count,
        "reviewedFileCount": _row_value(row, "reviewed_file_count", 0),
        "ignoredFileCount": _row_value(row, "ignored_file_count", 0),
        "findingSummary": _load_finding_summary(row, findings),
        "manifests": _metadata_list(metadata, "manifests"),
        "lockfiles": _metadata_list(metadata, "lockfiles"),
        "lifecycleScripts": _metadata_list(metadata, "lifecycleScripts"),
        "secretFiles": _metadata_list(metadata, "secretFiles"),
        "ignoredFiles": _metadata_list(metadata, "ignoredFiles"),
        "builtInExcludedDirectories": _metadata_list(metadata, "builtInExcludedDirectories"),
        "reviewedFiles": _metadata_list(metadata, "reviewedFiles"),
        "reviewedFilesTruncated": metadata.get("reviewedFilesTruncated") is True,
        "zone": str(metadata.get("zone") or "Unknown"),
        "scanCompleteness": _scan_completeness(metadata) if findings_reliable else None,
        "scanMetadataReliable": findings_reliable and _scan_metadata_reliable(metadata),
        "dependencyTrust": _dependency_trust(metadata) if findings_reliable else None,
    }


def _load_findings(row: sqlite3.Row) -> tuple[list[dict[str, Any]], bool]:
    try:
        value = json.loads(row["findings_json"])
    except (TypeError, json.JSONDecodeError):
        return [], False
    if not isinstance(value, list) or any(not isinstance(finding, dict) for finding in value):
        return [], False
    findings = sanitize_scan_value(
        [_normalize_finding(finding) for finding in value],
        project_root=row["project_path"],
    )
    return (findings, True) if isinstance(findings, list) else ([], False)


def scan_completeness_for_row(row: sqlite3.Row) -> dict[str, Any] | None:
    return _scan_completeness(_load_scan_metadata(row))


def _normalize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(finding)
    normalized.update({
        "path": finding.get("path") or finding.get("file_path") or "",
        "type": finding.get("type") or finding.get("finding_type") or "unknown",
        "severity": finding.get("severity") or "low",
        "explanation": finding.get("explanation") or "Review this finding manually.",
    })
    if normalized["type"] == "suspicious-text-pattern":
        normalized.pop("evidence", None)
        evidence = normalize_suspicious_text_evidence(finding.get("evidence"))
        finding_pattern = finding.get("pattern")
        if (
            evidence
            and isinstance(finding_pattern, str)
            and evidence["pattern"] == finding_pattern
        ):
            normalized["evidence"] = evidence
    normalized.pop("explainability", None)
    explainability = normalize_finding_explainability(
        finding.get("explainability"),
        finding=normalized,
    )
    if explainability:
        normalized["explainability"] = explainability
    return normalized


def _row_value(row: sqlite3.Row, key: str, default: Any) -> Any:
    return row[key] if key in row.keys() else default


def _load_finding_summary(row: sqlite3.Row, findings: list[dict[str, str]]) -> dict[str, int]:
    if "finding_summary_json" not in row.keys():
        return _summarize_findings(findings)

    try:
        summary = json.loads(row["finding_summary_json"])
    except (TypeError, json.JSONDecodeError):
        return _summarize_findings(findings)

    if not isinstance(summary, dict):
        return _summarize_findings(findings)
    normalized = {str(key): int(value) for key, value in summary.items() if isinstance(value, int)}
    return normalized or _summarize_findings(findings)


def _load_scan_metadata(row: sqlite3.Row) -> dict[str, Any]:
    if "scan_metadata_json" not in row.keys():
        return {}

    try:
        metadata = json.loads(row["scan_metadata_json"])
    except (TypeError, json.JSONDecodeError):
        return {}

    return metadata if isinstance(metadata, dict) else {}


def _metadata_list(metadata: dict[str, Any], key: str) -> list[Any]:
    value = metadata.get(key)
    return value if isinstance(value, list) else []


def _scan_completeness(metadata: dict[str, Any]) -> dict[str, Any] | None:
    value = metadata.get("scanCompleteness")
    if not isinstance(value, dict):
        return None
    count_fields = (
        "traversalFailureCount",
        "fileInspectionFailureCount",
        "oversizedFileCount",
        "unsafePathCount",
        "dependencyAnalysisFailureCount",
        "policyExcludedFileCount",
        "builtInExcludedDirectoryCount",
        "unsupportedEncodingFileCount",
        "resourceBudgetExceededCount",
    )
    if any(
        not isinstance(value.get(field), int)
        or isinstance(value.get(field), bool)
        or value[field] < 0
        for field in count_fields
    ):
        return None
    counts = {field: value[field] for field in count_fields}
    issue_count = sum(counts.values())
    stored_issue_count = value.get("issueCount")
    complete = value.get("complete")
    if (
        not isinstance(stored_issue_count, int)
        or isinstance(stored_issue_count, bool)
        or stored_issue_count != issue_count
        or not isinstance(complete, bool)
        or complete is not (issue_count == 0)
        or counts["policyExcludedFileCount"] < len(_metadata_list(metadata, "ignoredFiles"))
        or counts["builtInExcludedDirectoryCount"]
        < len(_metadata_list(metadata, "builtInExcludedDirectories"))
    ):
        return None
    return {
        "complete": complete,
        **counts,
        "issueCount": issue_count,
    }


def _dependency_trust(metadata: dict[str, Any]) -> dict[str, Any] | None:
    value = metadata.get("dependencyTrust")
    return value if isinstance(value, dict) else None


def _scan_metadata_reliable(metadata: dict[str, Any]) -> bool:
    if metadata.get("reviewedFilesTruncated") is True:
        return False
    string_list_fields = ("manifests", "lockfiles", "ignoredFiles", "reviewedFiles")
    if any(
        not isinstance(metadata.get(field), list)
        or any(not isinstance(item, str) for item in metadata[field])
        for field in string_list_fields
    ):
        return False

    built_in_exclusions = metadata.get("builtInExcludedDirectories", [])
    if not isinstance(built_in_exclusions, list) or any(
        not isinstance(item, str) for item in built_in_exclusions
    ):
        return False

    lifecycle_scripts = metadata.get("lifecycleScripts")
    return isinstance(lifecycle_scripts, list) and all(
        isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and isinstance(item.get("script"), str)
        for item in lifecycle_scripts
    )


def _summarize_findings(findings: list[dict[str, str]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for finding in findings:
        finding_type = finding.get("type") or "unknown"
        summary[finding_type] = summary.get(finding_type, 0) + 1
    return summary
