from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime

from .database import row_to_scan
from .finding_reviews import enrich_scan


EVENT_PROJECT_EXPECTATIONS_UPDATED = "project_expectations_updated"
EVENT_OBSERVED_DRIFT_ADOPTED = "observed_drift_adopted"
EVENT_FINDING_REVIEW_COMPLETED = "finding_review_completed"
EVENT_DEPENDENCY_REVIEW_COMPLETED = "dependency_review_completed"
KNOWN_STORED_EVENT_TYPES = {
    EVENT_PROJECT_EXPECTATIONS_UPDATED,
    EVENT_OBSERVED_DRIFT_ADOPTED,
    EVENT_FINDING_REVIEW_COMPLETED,
    EVENT_DEPENDENCY_REVIEW_COMPLETED,
}
MAX_ACTIVITY_PAGE_SIZE = 50
MAX_ACTIVITY_OFFSET = 1000
MAX_DETAILS_JSON_BYTES = 4096
MAX_DETAIL_STRING_LENGTH = 500
MAX_DETAIL_LIST_LENGTH = 20


def append_activity_event(
    connection: sqlite3.Connection,
    *,
    project_id: str,
    event_type: str,
    occurred_at: str,
    details: dict[str, object] | None = None,
    related_scan_id: int | None = None,
    dedupe_key: str | None = None,
) -> str | None:
    if event_type not in KNOWN_STORED_EVENT_TYPES:
        raise ValueError("Unsupported activity event type.")
    normalized_details = _bounded_details(details or {})
    serialized = json.dumps(normalized_details, sort_keys=True, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > MAX_DETAILS_JSON_BYTES:
        raise ValueError("Activity event details exceed the storage limit.")

    event_id = f"evt_{uuid.uuid4().hex}"
    cursor = connection.execute(
        "INSERT INTO project_activity_events "
        "(event_id, project_id, event_type, occurred_at, related_scan_id, details_json, dedupe_key) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(project_id, dedupe_key) DO NOTHING",
        (
            event_id,
            project_id,
            event_type,
            occurred_at,
            related_scan_id if isinstance(related_scan_id, int) and related_scan_id > 0 else None,
            serialized,
            _bounded_text(dedupe_key, 300) if dedupe_key else None,
        ),
    )
    return event_id if cursor.rowcount == 1 else None


def activity_page(
    connection: sqlite3.Connection,
    *,
    project_id: str,
    limit: int,
    offset: int,
) -> dict[str, object]:
    candidate_limit = min(MAX_ACTIVITY_OFFSET + MAX_ACTIVITY_PAGE_SIZE + 1, offset + limit + 1)
    stored_rows = connection.execute(
        "SELECT event_id, project_id, event_type, occurred_at, related_scan_id, details_json "
        "FROM project_activity_events WHERE project_id = ? "
        "ORDER BY occurred_at DESC, event_id DESC LIMIT ?",
        (project_id, candidate_limit),
    ).fetchall()
    scan_rows = connection.execute(
        "SELECT id, project_path, scan_date FROM scans "
        "WHERE project_path = ? ORDER BY scan_date DESC, id DESC LIMIT ?",
        (project_id, candidate_limit),
    ).fetchall()
    project_row = connection.execute(
        "SELECT path, name, created_at FROM projects WHERE path = ?",
        (project_id,),
    ).fetchone()
    candidates = [
        {
            "source": "stored",
            "eventId": _bounded_text(row["event_id"], 100) or "unknown",
            "timestamp": _timestamp(row["occurred_at"]),
            "row": row,
        }
        for row in stored_rows
    ]
    candidates.extend({
        "source": "scan",
        "eventId": f"scan:{row['id']}",
        "timestamp": _timestamp(row["scan_date"]),
        "scanId": row["id"],
    } for row in scan_rows)
    if project_row:
        registration = _registration_event(project_row)
        candidates.append({
            "source": "registration",
            "eventId": registration["eventId"],
            "timestamp": registration["timestamp"],
            "event": registration,
        })
    candidates.sort(key=lambda event: (event["timestamp"], event["eventId"]), reverse=True)

    selected = candidates[offset:offset + limit + 1]
    has_more = len(selected) > limit
    page_candidates = selected[:limit]
    scan_ids = [
        candidate["scanId"]
        for candidate in page_candidates
        if candidate["source"] == "scan"
    ]
    full_scan_rows: dict[int, sqlite3.Row] = {}
    reviews: list[dict[str, object]] = []
    if scan_ids:
        placeholders = ",".join("?" for _ in scan_ids)
        rows = connection.execute(
            f"SELECT * FROM scans WHERE project_path = ? AND id IN ({placeholders})",
            (project_id, *scan_ids),
        ).fetchall()
        full_scan_rows = {row["id"]: row for row in rows}
        review_rows = connection.execute(
            "SELECT fingerprint, status, note, created_at, updated_at FROM finding_reviews "
            "WHERE project_path = ?",
            (project_id,),
        ).fetchall()
        reviews = [dict(row) for row in review_rows]

    page = []
    for candidate in page_candidates:
        if candidate["source"] == "stored":
            page.append(_stored_event(candidate["row"]))
        elif candidate["source"] == "registration":
            page.append(candidate["event"])
        elif candidate["scanId"] in full_scan_rows:
            page.append(_scan_event(full_scan_rows[candidate["scanId"]], reviews))
    return {
        "events": page,
        "has_more": has_more,
        "next_offset": offset + len(page) if has_more else None,
    }


def _stored_event(row: sqlite3.Row) -> dict[str, object]:
    raw_type = _bounded_text(row["event_type"], 80) or "unknown"
    known_type = raw_type in KNOWN_STORED_EVENT_TYPES
    details, malformed = _load_details(row["details_json"], raw_type)
    return {
        "eventId": _bounded_text(row["event_id"], 100) or "unknown",
        "projectId": _bounded_text(row["project_id"], 1000),
        "eventType": raw_type,
        "timestamp": _timestamp(row["occurred_at"]),
        "relatedScanId": row["related_scan_id"]
        if isinstance(row["related_scan_id"], int) and row["related_scan_id"] > 0
        else None,
        "details": details,
        "malformed": malformed or not known_type,
    }


def _scan_event(row: sqlite3.Row, reviews: list[dict[str, object]]) -> dict[str, object]:
    scan = enrich_scan(row_to_scan(row), reviews)
    completeness = scan.get("scanCompleteness")
    if not isinstance(completeness, dict):
        coverage_status = "unknown"
        status = "unknown"
    elif completeness.get("complete") is True:
        coverage_status = "complete"
        status = "completed"
    else:
        coverage_status = "incomplete"
        status = "incomplete"
    dependency = scan.get("dependencyTrust")
    dependency_status = (
        _bounded_text(dependency.get("status"), 80)
        if isinstance(dependency, dict)
        else "unavailable"
    ) or "unavailable"
    review_summary = scan.get("reviewSummary")
    reviewed_count = (
        review_summary.get("reviewedFindingCount", 0)
        if isinstance(review_summary, dict)
        else 0
    )
    return {
        "eventId": f"scan:{scan['id']}",
        "projectId": scan["project_path"],
        "eventType": "scan_completed",
        "timestamp": _timestamp(scan["scan_date"]),
        "relatedScanId": scan["id"],
        "details": {
            "status": status,
            "findingCount": max(0, int(scan.get("findingCount") or 0)),
            "reviewedCount": max(0, int(reviewed_count or 0)),
            "dependencyStatus": dependency_status,
            "coverageStatus": coverage_status,
        },
        "malformed": status == "unknown",
    }


def _registration_event(row: sqlite3.Row) -> dict[str, object]:
    digest = hashlib.sha256(str(row["path"]).encode("utf-8")).hexdigest()[:24]
    return {
        "eventId": f"project:{digest}:registered",
        "projectId": row["path"],
        "eventType": "project_registered",
        "timestamp": _timestamp(row["created_at"]),
        "relatedScanId": None,
        "details": {"projectName": _bounded_text(row["name"], 120)},
        "malformed": not bool(_timestamp(row["created_at"])),
    }


def _load_details(value: object, event_type: str) -> tuple[dict[str, object], bool]:
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_DETAILS_JSON_BYTES:
        return {}, True
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}, True
    if not isinstance(parsed, dict):
        return {}, True
    bounded = _bounded_details(parsed)

    if event_type == EVENT_PROJECT_EXPECTATIONS_UPDATED:
        categories = bounded.get("changedCategories")
        context_changed = bounded.get("reviewContextChanged")
        valid = isinstance(categories, list) and all(isinstance(item, str) for item in categories)
        if not valid or not isinstance(context_changed, bool):
            return {}, True
        return {
            "changedCategories": categories,
            "reviewContextChanged": context_changed,
        }, False
    if event_type == EVENT_OBSERVED_DRIFT_ADOPTED:
        category = bounded.get("category")
        adopted = bounded.get("adoptedValue")
        replaced = bounded.get("replacedValue")
        if not isinstance(category, str) or not category or not isinstance(adopted, str) or not adopted:
            return {}, True
        if replaced is not None and not isinstance(replaced, str):
            return {}, True
        details: dict[str, object] = {"category": category, "adoptedValue": adopted}
        if replaced:
            details["replacedValue"] = replaced
        return details, False
    if event_type == EVENT_FINDING_REVIEW_COMPLETED:
        reviewed = bounded.get("reviewedCount")
        total = bounded.get("totalFindingCount")
        if not isinstance(reviewed, int) or not isinstance(total, int):
            return {}, True
        return {"reviewedCount": max(0, reviewed), "totalFindingCount": max(0, total)}, False
    if event_type == EVENT_DEPENDENCY_REVIEW_COMPLETED:
        status = bounded.get("status")
        if status != "approved":
            return {}, True
        return {"status": status}, False
    return {}, True


def _bounded_details(value: dict[str, object]) -> dict[str, object]:
    bounded: dict[str, object] = {}
    for raw_key, raw_value in list(value.items())[:MAX_DETAIL_LIST_LENGTH]:
        key = _bounded_text(raw_key, 80)
        if not key:
            continue
        if isinstance(raw_value, bool):
            bounded[key] = raw_value
        elif isinstance(raw_value, int):
            bounded[key] = max(-1_000_000, min(1_000_000, raw_value))
        elif isinstance(raw_value, str):
            bounded[key] = _bounded_text(raw_value, MAX_DETAIL_STRING_LENGTH)
        elif isinstance(raw_value, list):
            bounded[key] = [
                _bounded_text(item, MAX_DETAIL_STRING_LENGTH)
                for item in raw_value[:MAX_DETAIL_LIST_LENGTH]
                if isinstance(item, str) and _bounded_text(item, MAX_DETAIL_STRING_LENGTH)
            ]
    return bounded


def _bounded_text(value: object, limit: int) -> str:
    return str(value or "").strip()[:limit]


def _timestamp(value: object) -> str:
    text = _bounded_text(value, 100)
    if not text:
        return ""
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return ""
    return text
