from __future__ import annotations

import sqlite3
from typing import Any

from .database import row_to_scan
from .finding_reviews import enrich_scan
from .scan_comparison import trusted_scan_summary


PROVENANCE_MANUAL = "manual"


def trusted_scan_baseline_state(
    connection: sqlite3.Connection,
    *,
    project_id: str,
) -> dict[str, Any]:
    baseline_row = connection.execute(
        "SELECT project_id, scan_id, pinned_at, provenance "
        "FROM trusted_scan_baselines WHERE project_id = ?",
        (project_id,),
    ).fetchone()
    latest_row = connection.execute(
        "SELECT * FROM scans WHERE project_path = ? ORDER BY scan_date DESC, id DESC LIMIT 1",
        (project_id,),
    ).fetchone()
    latest = trusted_scan_summary(latest_row) if latest_row else None
    if not baseline_row:
        return {
            "configured": False,
            "status": "not-configured",
            "baseline": None,
            "latestScan": latest,
            "isLatest": False,
            "message": "No trusted scan baseline is configured. Automatic baseline selection remains active.",
        }

    scan_row = connection.execute(
        "SELECT * FROM scans WHERE id = ? AND project_path = ?",
        (baseline_row["scan_id"], project_id),
    ).fetchone()
    baseline = {
        "scanId": int(baseline_row["scan_id"]),
        "pinnedAt": str(baseline_row["pinned_at"] or "")[:100],
        "provenance": (
            PROVENANCE_MANUAL
            if baseline_row["provenance"] == PROVENANCE_MANUAL
            else "unknown"
        ),
    }
    if not scan_row:
        return {
            "configured": True,
            "status": "unavailable",
            "baseline": baseline,
            "latestScan": latest,
            "isLatest": bool(latest and latest["id"] == baseline["scanId"]),
            "message": "Trusted baseline unavailable. The stored scan reference was preserved and no automatic baseline was substituted.",
        }

    summary = trusted_scan_summary(scan_row, include_metadata=True)
    baseline.update(summary)
    eligible = summary["eligibility"]["eligible"] is True
    if eligible:
        try:
            full_scan = enrich_scan(row_to_scan(scan_row), [])
        except (TypeError, ValueError):
            eligible = False
        else:
            finding_keys = [
                finding.get("fingerprint")
                for finding in full_scan["findings"]
                if isinstance(finding, dict)
            ]
            if (
                len(finding_keys) != full_scan["findingCount"]
                or any(not isinstance(key, str) or not key for key in finding_keys)
            ):
                eligible = False
            else:
                baseline["scan"]["findings"] = [
                    {"fingerprint": key}
                    for key in finding_keys
                ]
                baseline["scan"]["findingCount"] = len(finding_keys)
    return {
        "configured": True,
        "status": "valid" if eligible else "invalid",
        "baseline": baseline,
        "latestScan": latest,
        "isLatest": bool(latest and latest["id"] == baseline["scanId"]),
        "message": (
            "This exact scan is the trusted comparison baseline."
            if eligible
            else "Trusted baseline unavailable. The stored scan is no longer compatible with current reliability requirements, and no automatic baseline was substituted."
        ),
    }
