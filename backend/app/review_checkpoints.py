from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

from fastapi import HTTPException

from .activity import EVENT_REVIEW_CHECKPOINT_CREATED, append_activity_event
from .database import row_to_scan
from .finding_reviews import (
    enrich_scan as enrich_finding_reviews,
    finding_fingerprint,
)
from .trusted_dependency_baseline import (
    approval_for_analysis,
    compare_with_baseline,
    public_baseline,
)
from .trusted_scan_baseline import trusted_scan_baseline_state


CHECKPOINT_SCHEMA_VERSION = 1
SECURITY_STATUS_EVALUATOR_VERSION = 2
PROVENANCE_MANUAL = "manual"
MAX_CHECKPOINT_PAGE_SIZE = 20
MAX_CHECKPOINT_OFFSET = 200
MAX_REASONS = 3
MAX_EXPECTATION_VALUES = 500
MAX_AUTOMATIC_BASELINE_CANDIDATES = 19
EXPECTATION_FIELDS = (
    "trustedPackageManagers",
    "expectedManifestFiles",
    "expectedLockfiles",
    "allowedLifecycleScripts",
    "expectedEcosystems",
    "reviewedPaths",
    "ignoredPaths",
)
PATH_FIELDS = {
    "expectedManifestFiles",
    "expectedLockfiles",
    "reviewedPaths",
    "ignoredPaths",
}
LOWERCASE_FIELDS = {
    "trustedPackageManagers",
    "allowedLifecycleScripts",
    "expectedEcosystems",
}
FINGERPRINT_PATTERN = re.compile(r"^cpr1_[0-9a-f]{64}$")
CHECKPOINT_ID_PATTERN = re.compile(r"^rcp_[0-9a-f]{32}$")


def checkpoint_page(
    connection: sqlite3.Connection,
    *,
    project_id: str,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    evidence = current_checkpoint_evidence(connection, project_id=project_id)
    latest_row = connection.execute(
        "SELECT * FROM project_review_checkpoints WHERE project_id = ? "
        "ORDER BY created_at DESC, checkpoint_id DESC LIMIT 1",
        (project_id,),
    ).fetchone()
    rows = connection.execute(
        "SELECT * FROM project_review_checkpoints WHERE project_id = ? "
        "ORDER BY created_at DESC, checkpoint_id DESC LIMIT ? OFFSET ?",
        (project_id, limit + 1, offset),
    ).fetchall()
    state = checkpoint_state(
        connection,
        project_id=project_id,
        evidence=evidence,
        checkpoint_row=latest_row,
    )
    return {
        "state": state,
        "currentEvidence": _public_evidence(evidence),
        "history": [_public_checkpoint(connection, project_id, row) for row in rows[:limit]],
        "hasMore": len(rows) > limit,
        "nextOffset": offset + limit if len(rows) > limit else None,
        "limits": {"history": limit, "reasons": MAX_REASONS},
    }


def create_checkpoint(
    connection: sqlite3.Connection,
    *,
    project_id: str,
    scan_id: int,
    expected_evidence_fingerprint: str,
    security_status: str,
    evaluator_version: int,
    provenance: str,
    created_at: str,
) -> dict[str, Any]:
    requested_scan = connection.execute(
        "SELECT id, project_path FROM scans WHERE id = ?",
        (scan_id,),
    ).fetchone()
    if not requested_scan:
        raise HTTPException(status_code=404, detail="The selected scan was not found.")
    if requested_scan["project_path"] != project_id:
        raise HTTPException(status_code=403, detail="The selected scan belongs to another project.")
    if (
        evaluator_version != SECURITY_STATUS_EVALUATOR_VERSION
        or provenance != PROVENANCE_MANUAL
    ):
        raise HTTPException(
            status_code=409,
            detail="The checkpoint preview uses unsupported evaluator or provenance metadata.",
        )

    evidence = current_checkpoint_evidence(connection, project_id=project_id)
    if evidence.get("reliable") is not True:
        raise HTTPException(
            status_code=409,
            detail="Current checkpoint evidence is indeterminate. Refresh the project review before retrying.",
        )
    if evidence["scanId"] != scan_id:
        raise HTTPException(
            status_code=409,
            detail="A newer scan is now current. Review it before recording a checkpoint.",
        )
    if (
        not FINGERPRINT_PATTERN.fullmatch(expected_evidence_fingerprint)
        or evidence["evidenceFingerprint"] != expected_evidence_fingerprint
    ):
        raise HTTPException(
            status_code=409,
            detail="Current review evidence changed. Refresh the checkpoint preview.",
        )
    if evidence.get("readyForCheckpoint") is not True:
        raise HTTPException(
            status_code=409,
            detail="The current evidence does not satisfy Ready for reviewed work requirements.",
        )
    if security_status != "ready":
        raise HTTPException(
            status_code=409,
            detail="The checkpoint preview no longer identifies Ready for reviewed work.",
        )

    latest = connection.execute(
        "SELECT * FROM project_review_checkpoints WHERE project_id = ? "
        "ORDER BY created_at DESC, checkpoint_id DESC LIMIT 1",
        (project_id,),
    ).fetchone()
    if latest and latest["evidence_fingerprint"] == evidence["evidenceFingerprint"]:
        return {
            **checkpoint_page(connection, project_id=project_id, limit=5, offset=0),
            "created": False,
            "activityRecorded": False,
            "checkpoint": _public_checkpoint(connection, project_id, latest),
        }

    checkpoint_id = f"rcp_{uuid.uuid4().hex}"
    connection.execute(
        "INSERT INTO project_review_checkpoints ("
        "checkpoint_id, project_id, scan_id, baseline_scan_id, baseline_provenance, "
        "expectations_fingerprint, dependency_analysis_fingerprint, "
        "dependency_approval_fingerprint, dependency_approval_state, "
        "finding_reviews_fingerprint, baseline_findings_fingerprint, "
        "new_critical_high_count, finding_review_complete, "
        "unresolved_critical_count, unresolved_high_count, coverage_fingerprint, "
        "metadata_reliable, checkpoint_schema_version, evaluator_version, "
        "evidence_fingerprint, created_at, provenance"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            checkpoint_id,
            project_id,
            evidence["scanId"],
            evidence["baselineScanId"],
            evidence["baselineProvenance"],
            evidence["expectationsFingerprint"],
            evidence["dependencyAnalysisFingerprint"],
            evidence["dependencyApprovalFingerprint"],
            evidence["dependencyApprovalState"],
            evidence["findingReviewsFingerprint"],
            evidence["baselineFindingsFingerprint"],
            evidence["newCriticalHighCount"],
            1 if evidence["findingReviewComplete"] else 0,
            evidence["unresolvedCriticalCount"],
            evidence["unresolvedHighCount"],
            evidence["coverageFingerprint"],
            1 if evidence["metadataReliable"] else 0,
            CHECKPOINT_SCHEMA_VERSION,
            SECURITY_STATUS_EVALUATOR_VERSION,
            evidence["evidenceFingerprint"],
            created_at,
            PROVENANCE_MANUAL,
        ),
    )
    event_id = append_activity_event(
        connection,
        project_id=project_id,
        event_type=EVENT_REVIEW_CHECKPOINT_CREATED,
        occurred_at=created_at,
        related_scan_id=evidence["scanId"],
        details={
            "checkpointId": checkpoint_id,
            "evaluatorVersion": SECURITY_STATUS_EVALUATOR_VERSION,
            "provenance": PROVENANCE_MANUAL,
        },
        dedupe_key=f"review-checkpoint:{checkpoint_id}",
    )
    if not event_id:
        raise RuntimeError("Checkpoint activity event was not recorded.")
    row = connection.execute(
        "SELECT * FROM project_review_checkpoints WHERE checkpoint_id = ?",
        (checkpoint_id,),
    ).fetchone()
    return {
        **checkpoint_page(connection, project_id=project_id, limit=5, offset=0),
        "created": True,
        "activityRecorded": True,
        "checkpoint": _public_checkpoint(connection, project_id, row),
    }


def current_checkpoint_evidence(
    connection: sqlite3.Connection,
    *,
    project_id: str,
) -> dict[str, Any]:
    reasons: list[str] = []
    scan_row = connection.execute(
        "SELECT * FROM scans WHERE project_path = ? ORDER BY scan_date DESC, id DESC LIMIT 1",
        (project_id,),
    ).fetchone()
    if not scan_row:
        return _indeterminate_evidence("No current scan is available.")

    try:
        scan = row_to_scan(scan_row)
    except (TypeError, ValueError, json.JSONDecodeError):
        return _indeterminate_evidence("The latest persisted scan is malformed.")
    if scan.get("project_path") != project_id:
        return _indeterminate_evidence("The latest scan does not belong to this project.")

    coverage = _coverage_identity(scan_row)
    if coverage is None:
        reasons.append("Coverage metadata is missing, malformed, or internally inconsistent.")
    metadata_reliable = scan.get("scanMetadataReliable") is True
    if not metadata_reliable:
        reasons.append("Persisted project metadata is unreliable.")

    reviews = connection.execute(
        "SELECT fingerprint, status, note, created_at, updated_at FROM finding_reviews "
        "WHERE project_path = ? ORDER BY fingerprint",
        (project_id,),
    ).fetchall()
    try:
        enriched_scan = enrich_finding_reviews(scan, [dict(row) for row in reviews])
    except (TypeError, ValueError):
        return _indeterminate_evidence("Persisted finding evidence is malformed.")
    findings = _finding_identity(enriched_scan.get("findings"))
    if findings is None:
        reasons.append("Persisted finding evidence is malformed or unsupported.")

    expectations = _expectations_identity(connection, project_id, scan)
    if expectations is None:
        reasons.append("Project Expectations are malformed or cannot be compared reliably.")

    dependency = _dependency_identity(connection, project_id, scan)
    if dependency is None:
        reasons.append("Dependency analysis or approval evidence is malformed or unsupported.")

    baseline = (
        _baseline_identity(
            connection,
            project_id,
            scan_row,
            scan,
            current_findings=findings,
        )
        if findings is not None
        else None
    )
    if baseline is None:
        reasons.append("Trusted or automatic baseline evidence cannot be compared reliably.")

    if reasons:
        evidence = _indeterminate_evidence(*reasons)
        evidence["scanId"] = int(scan_row["id"])
        evidence["scanTimestamp"] = str(scan_row["scan_date"] or "")[:100]
        return evidence

    identity = {
        "checkpointSchemaVersion": CHECKPOINT_SCHEMA_VERSION,
        "evaluatorVersion": SECURITY_STATUS_EVALUATOR_VERSION,
        "projectId": project_id,
        "scanId": int(scan_row["id"]),
        "baselineScanId": baseline["scanId"],
        "baselineProvenance": baseline["provenance"],
        "expectationsFingerprint": expectations["fingerprint"],
        "dependencyAnalysisFingerprint": dependency["analysisFingerprint"],
        "dependencyApprovalFingerprint": dependency["approvalFingerprint"],
        "dependencyApprovalState": dependency["approvalState"],
        "findingReviewsFingerprint": findings["fingerprint"],
        "baselineFindingsFingerprint": baseline["findingsFingerprint"],
        "newCriticalHighCount": baseline["newCriticalHighCount"],
        "findingReviewComplete": findings["complete"],
        "unresolvedCriticalCount": findings["unresolvedCritical"],
        "unresolvedHighCount": findings["unresolvedHigh"],
        "coverageFingerprint": coverage["fingerprint"],
        "metadataReliable": metadata_reliable,
    }
    ready = bool(
        coverage["complete"]
        and metadata_reliable
        and findings["complete"]
        and findings["unresolvedCritical"] == 0
        and findings["unresolvedHigh"] == 0
        and baseline["newCriticalHighCount"] == 0
        and dependency["approvalState"] in {"approved", "not-applicable"}
        and expectations["configured"]
        and expectations["matches"]
        and baseline["comparisonState"] in {"unchanged", "no-baseline", "baseline-is-latest"}
    )
    return {
        **identity,
        "reliable": True,
        "readyForCheckpoint": ready,
        "scanTimestamp": str(scan_row["scan_date"] or "")[:100],
        "findingCount": findings["total"],
        "reviewedFindingCount": findings["reviewed"],
        "coverageComplete": coverage["complete"],
        "coverageIssueCount": coverage["issueCount"],
        "expectationsConfigured": expectations["configured"],
        "expectationsMatch": expectations["matches"],
        "baselineComparisonState": baseline["comparisonState"],
        "evidenceFingerprint": _fingerprint("cpr1_", identity),
        "reasons": [],
    }


def checkpoint_state(
    connection: sqlite3.Connection,
    *,
    project_id: str,
    evidence: Mapping[str, Any],
    checkpoint_row: Any | None,
) -> dict[str, Any]:
    if checkpoint_row is None:
        return {
            "id": "no-checkpoint",
            "label": "No checkpoint",
            "reasons": ["No manual project review checkpoint has been recorded."],
        }
    malformed_reason = _checkpoint_row_problem(connection, project_id, checkpoint_row)
    if malformed_reason:
        return {
            "id": "indeterminate",
            "label": "Indeterminate",
            "reasons": [malformed_reason],
        }
    if evidence.get("reliable") is not True:
        return {
            "id": "indeterminate",
            "label": "Indeterminate",
            "reasons": list(evidence.get("reasons") or ["Current evidence cannot be compared reliably."])[:MAX_REASONS],
        }
    if (
        checkpoint_row["checkpoint_schema_version"] != CHECKPOINT_SCHEMA_VERSION
        or checkpoint_row["evaluator_version"] != SECURITY_STATUS_EVALUATOR_VERSION
    ):
        return {
            "id": "indeterminate",
            "label": "Indeterminate",
            "reasons": ["The checkpoint uses an unsupported schema or security-status evaluator version."],
        }

    differences: list[str] = []
    if checkpoint_row["scan_id"] != evidence["scanId"]:
        differences.append("A different latest scan exists and has not been manually checkpointed.")
    if (
        checkpoint_row["baseline_scan_id"] != evidence["baselineScanId"]
        or checkpoint_row["baseline_provenance"] != evidence["baselineProvenance"]
    ):
        differences.append("The trusted or automatic baseline reference changed.")
    if checkpoint_row["expectations_fingerprint"] != evidence["expectationsFingerprint"]:
        differences.append("Project Expectations changed.")
    if (
        checkpoint_row["dependency_analysis_fingerprint"] != evidence["dependencyAnalysisFingerprint"]
        or checkpoint_row["dependency_approval_fingerprint"] != evidence["dependencyApprovalFingerprint"]
        or checkpoint_row["dependency_approval_state"] != evidence["dependencyApprovalState"]
    ):
        differences.append("Dependency analysis or approval evidence changed.")
    if (
        checkpoint_row["finding_reviews_fingerprint"] != evidence["findingReviewsFingerprint"]
        or checkpoint_row["baseline_findings_fingerprint"] != evidence["baselineFindingsFingerprint"]
        or checkpoint_row["new_critical_high_count"] != evidence["newCriticalHighCount"]
        or bool(checkpoint_row["finding_review_complete"]) != evidence["findingReviewComplete"]
        or checkpoint_row["unresolved_critical_count"] != evidence["unresolvedCriticalCount"]
        or checkpoint_row["unresolved_high_count"] != evidence["unresolvedHighCount"]
    ):
        differences.append("Finding review state or relevant unresolved findings changed.")
    if (
        checkpoint_row["coverage_fingerprint"] != evidence["coverageFingerprint"]
        or bool(checkpoint_row["metadata_reliable"]) != evidence["metadataReliable"]
    ):
        differences.append("Coverage or persisted metadata reliability changed.")
    if checkpoint_row["evidence_fingerprint"] != evidence["evidenceFingerprint"] and not differences:
        differences.append("Normalized checkpoint evidence changed.")
    if differences:
        return {
            "id": "review-required",
            "label": "Review required",
            "reasons": differences[:MAX_REASONS],
        }
    return {
        "id": "current",
        "label": "Current",
        "reasons": ["The latest checkpoint corresponds exactly to the current normalized evidence."],
    }


def _expectations_identity(
    connection: sqlite3.Connection,
    project_id: str,
    scan: Mapping[str, Any],
) -> dict[str, Any] | None:
    row = connection.execute(
        "SELECT profile_json FROM project_trust_profiles WHERE project_path = ?",
        (project_id,),
    ).fetchone()
    stored: Mapping[str, Any] = {}
    if row:
        try:
            value = json.loads(row["profile_json"])
        except (TypeError, json.JSONDecodeError):
            return None
        if not isinstance(value, Mapping):
            return None
        stored = value
    profile: dict[str, list[str]] = {}
    for field in EXPECTATION_FIELDS:
        normalized = _normalized_values(field, stored.get(field, []))
        if normalized is None:
            return None
        profile[field] = normalized
    observed = _observed_expectations(scan)
    if observed is None:
        return None
    configured = sum(len(profile[field]) for field in EXPECTATION_FIELDS) > 0
    return {
        "fingerprint": _fingerprint("cpex1_", profile),
        "configured": configured,
        "matches": all(profile[field] == observed[field] for field in EXPECTATION_FIELDS),
    }


def _observed_expectations(scan: Mapping[str, Any]) -> dict[str, list[str]] | None:
    dependency = scan.get("dependencyTrust")
    dependency_not_applicable = _dependency_not_applicable(dependency)
    if not dependency_not_applicable and (
        not isinstance(dependency, Mapping)
        or dependency.get("schemaVersion") != 1
        or dependency.get("status") != "complete"
    ):
        return None
    source = {
        "trustedPackageManagers": []
        if dependency_not_applicable
        else dependency.get("packageManagers"),
        "expectedManifestFiles": scan.get("manifests"),
        "expectedLockfiles": scan.get("lockfiles"),
        "expectedEcosystems": []
        if dependency_not_applicable
        else dependency.get("ecosystems"),
        "reviewedPaths": scan.get("reviewedFiles"),
        "ignoredPaths": scan.get("ignoredFiles"),
    }
    scripts = scan.get("lifecycleScripts")
    if not isinstance(scripts, list) or any(
        not isinstance(item, Mapping) or not isinstance(item.get("script"), str)
        for item in scripts
    ):
        return None
    source["allowedLifecycleScripts"] = [item["script"] for item in scripts]
    observed: dict[str, list[str]] = {}
    for field in EXPECTATION_FIELDS:
        values = _normalized_values(field, source.get(field))
        if values is None:
            return None
        observed[field] = values
    return observed


def _normalized_values(field: str, value: Any) -> list[str] | None:
    if (
        not isinstance(value, list)
        or len(value) > MAX_EXPECTATION_VALUES
        or any(not isinstance(item, str) for item in value)
    ):
        return None
    normalized: set[str] = set()
    for item in value:
        text = " ".join(item.split())
        if field in PATH_FIELDS:
            text = text.replace("\\", "/")
            while text.startswith("./"):
                text = text[2:]
        if field in LOWERCASE_FIELDS:
            text = text.lower()
        if text:
            normalized.add(text)
    return sorted(normalized)


def _dependency_identity(
    connection: sqlite3.Connection,
    project_id: str,
    scan: Mapping[str, Any],
) -> dict[str, Any] | None:
    analysis = scan.get("dependencyTrust")
    if _dependency_not_applicable(analysis):
        return {
            "analysisFingerprint": _fingerprint(
                "cpda1_",
                {
                    "applicability": "not-applicable",
                    "schemaVersion": 1,
                    "status": "unsupported",
                },
            ),
            "approvalFingerprint": "",
            "approvalState": "not-applicable",
        }
    approval = approval_for_analysis(analysis)
    if approval.get("eligible") is not True:
        return None
    row = connection.execute(
        "SELECT * FROM trusted_dependency_baselines WHERE project_path = ?",
        (project_id,),
    ).fetchone()
    if not row:
        return {
            "analysisFingerprint": approval["fingerprint"],
            "approvalFingerprint": "",
            "approvalState": "not-configured",
        }
    baseline_row = dict(row)
    baseline = public_baseline(baseline_row)
    if baseline.get("valid") is not True:
        return None
    comparison = compare_with_baseline(analysis, baseline_row)
    comparison_status = comparison.get("status")
    if comparison_status not in {"identical", "drift"}:
        return None
    significant_change = _dependency_comparison_is_significant(analysis)
    return {
        "analysisFingerprint": approval["fingerprint"],
        "approvalFingerprint": baseline["fingerprint"],
        "approvalState": (
            "significant-change"
            if significant_change
            else "approved"
            if comparison_status == "identical"
            else "changed"
        ),
    }


def _dependency_comparison_is_significant(value: Any) -> bool:
    comparison = value.get("comparison") if isinstance(value, Mapping) else None
    comparison = comparison if isinstance(comparison, Mapping) else {}
    change_count = comparison.get("changeCount")
    if (
        isinstance(change_count, int)
        and not isinstance(change_count, bool)
        and change_count >= 3
    ):
        return True
    changes = comparison.get("changes")
    if not isinstance(changes, list):
        return False
    significant_types = {
        "version-changed",
        "source-changed",
        "integrity-changed",
        "install-script-changed",
    }
    return any(
        isinstance(change, Mapping)
        and change.get("changeType") in significant_types
        for change in changes
    )


def _dependency_not_applicable(value: Any) -> bool:
    if (
        not isinstance(value, Mapping)
        or value.get("schemaVersion") != 1
        or value.get("status") != "unsupported"
    ):
        return False
    fields = ("ecosystems", "manifests", "lockfiles", "packageManagers", "entries")
    return all(isinstance(value.get(field), list) and not value[field] for field in fields)


def _finding_identity(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, list):
        return None
    entries: list[dict[str, str]] = []
    unresolved_critical = 0
    unresolved_high = 0
    reviewed = 0
    critical_high_keys: list[str] = []
    for finding in value:
        if not isinstance(finding, Mapping):
            return None
        fingerprint = finding.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            return None
        review = finding.get("review")
        status = review.get("status") if isinstance(review, Mapping) else ""
        if status not in {"", "reviewed", "expected"}:
            return None
        if status:
            reviewed += 1
        severity = str(finding.get("severity") or "low").lower()
        if severity not in {"critical", "high", "medium", "low"}:
            severity = "high"
        if severity == "critical" and status != "expected":
            unresolved_critical += 1
        if severity == "high" and status != "expected":
            unresolved_high += 1
        if severity in {"critical", "high"}:
            critical_high_keys.append(fingerprint)
        entries.append({"fingerprint": fingerprint, "status": status})
    entries.sort(key=lambda item: item["fingerprint"])
    return {
        "fingerprint": _fingerprint("cpfr1_", entries),
        "complete": reviewed == len(value),
        "total": len(value),
        "reviewed": reviewed,
        "unresolvedCritical": unresolved_critical,
        "unresolvedHigh": unresolved_high,
        "criticalHighKeys": sorted(set(critical_high_keys)),
    }


def _coverage_identity(row: Any) -> dict[str, Any] | None:
    try:
        metadata = json.loads(row["scan_metadata_json"])
    except (KeyError, TypeError, json.JSONDecodeError):
        return None
    if not isinstance(metadata, Mapping):
        return None
    value = metadata.get("scanCompleteness")
    if not isinstance(value, Mapping):
        return None
    fields = (
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
        for field in fields
    ):
        return None
    issue_count = sum(value[field] for field in fields)
    if (
        not isinstance(value.get("issueCount"), int)
        or isinstance(value.get("issueCount"), bool)
        or value["issueCount"] != issue_count
        or value.get("complete") is not (issue_count == 0)
    ):
        return None
    identity = {
        "complete": value["complete"],
        "issueCount": issue_count,
        **{field: value[field] for field in fields},
    }
    return {
        **identity,
        "fingerprint": _fingerprint("cpcov1_", identity),
    }


def _baseline_identity(
    connection: sqlite3.Connection,
    project_id: str,
    current_row: Any,
    current_scan: Mapping[str, Any],
    *,
    current_findings: Mapping[str, Any],
) -> dict[str, Any] | None:
    state = trusted_scan_baseline_state(connection, project_id=project_id)
    if state.get("configured") is True:
        if state.get("status") != "valid" or not isinstance(state.get("baseline"), Mapping):
            return None
        scan_id = state["baseline"].get("scanId")
        provenance = state["baseline"].get("provenance")
        if not isinstance(scan_id, int) or provenance != PROVENANCE_MANUAL:
            return None
        baseline_row = connection.execute(
            "SELECT * FROM scans WHERE id = ? AND project_path = ?",
            (scan_id, project_id),
        ).fetchone()
        if not baseline_row:
            return None
        try:
            baseline_scan = row_to_scan(baseline_row)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        baseline_findings = _baseline_findings_identity(
            baseline_row,
            baseline_scan,
            current_findings,
        )
        if baseline_findings is None:
            return None
        if scan_id == current_row["id"]:
            return {
                "scanId": scan_id,
                "provenance": PROVENANCE_MANUAL,
                "comparisonState": "baseline-is-latest",
                **baseline_findings,
            }
        baseline_observed = _observed_expectations(baseline_scan)
        current_observed = _observed_expectations(current_scan)
        if baseline_observed is None or current_observed is None:
            return None
        return {
            "scanId": scan_id,
            "provenance": PROVENANCE_MANUAL,
            "comparisonState": "unchanged" if baseline_observed == current_observed else "drift",
            **baseline_findings,
        }

    rows = connection.execute(
        "SELECT * FROM scans WHERE project_path = ? AND id != ? "
        "ORDER BY scan_date DESC, id DESC LIMIT ?",
        (
            project_id,
            current_row["id"],
            MAX_AUTOMATIC_BASELINE_CANDIDATES,
        ),
    )
    current_observed = _observed_expectations(current_scan)
    if current_observed is None:
        rows.close()
        return None
    try:
        for row in rows:
            baseline_coverage = _coverage_identity(row)
            if (
                baseline_coverage is None
                or baseline_coverage["complete"] is not True
            ):
                continue
            baseline_metadata = _baseline_metadata_snapshot(row)
            if baseline_metadata is None:
                continue
            baseline_observed = _observed_expectations(baseline_metadata)
            if baseline_observed is None:
                continue
            try:
                baseline_scan = row_to_scan(row)
            except (TypeError, ValueError, json.JSONDecodeError):
                return None
            baseline_findings = _baseline_findings_identity(
                row,
                baseline_scan,
                current_findings,
            )
            if baseline_findings is None:
                return None
            return {
                "scanId": int(row["id"]),
                "provenance": "automatic",
                "comparisonState": "unchanged" if baseline_observed == current_observed else "drift",
                **baseline_findings,
            }
    finally:
        rows.close()
    return {
        "scanId": None,
        "provenance": "none",
        "comparisonState": "no-baseline",
        "findingsFingerprint": "",
        "newCriticalHighCount": 0,
    }


def _baseline_metadata_snapshot(row: Any) -> dict[str, Any] | None:
    try:
        metadata = json.loads(row["scan_metadata_json"])
    except (KeyError, TypeError, json.JSONDecodeError):
        return None
    if not isinstance(metadata, Mapping):
        return None
    string_fields = ("manifests", "lockfiles", "ignoredFiles", "reviewedFiles")
    if any(
        not isinstance(metadata.get(field), list)
        or any(not isinstance(item, str) for item in metadata[field])
        for field in string_fields
    ):
        return None
    built_in_exclusions = metadata.get("builtInExcludedDirectories", [])
    if not isinstance(built_in_exclusions, list) or any(not isinstance(item, str) for item in built_in_exclusions):
        return None
    scripts = metadata.get("lifecycleScripts")
    if (
        not isinstance(scripts, list)
        or any(
            not isinstance(item, Mapping)
            or not isinstance(item.get("path"), str)
            or not isinstance(item.get("script"), str)
            for item in scripts
        )
    ):
        return None
    return {
        **{field: metadata[field] for field in string_fields},
        "builtInExcludedDirectories": built_in_exclusions,
        "lifecycleScripts": scripts,
        "dependencyTrust": metadata.get("dependencyTrust"),
        "scanMetadataReliable": True,
    }


def _baseline_findings_identity(
    row: Any,
    scan: Mapping[str, Any],
    current_findings: Mapping[str, Any],
) -> dict[str, Any] | None:
    findings = scan.get("findings")
    if not isinstance(findings, list):
        return None
    try:
        stored_count = row["finding_count"]
    except (KeyError, IndexError):
        return None
    if (
        not isinstance(stored_count, int)
        or isinstance(stored_count, bool)
        or stored_count != len(findings)
    ):
        return None
    keys: list[str] = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            return None
        try:
            key = finding_fingerprint(dict(finding))
        except (TypeError, ValueError):
            return None
        if not key:
            return None
        keys.append(key)
    normalized_keys = sorted(set(keys))
    current_high = set(current_findings.get("criticalHighKeys") or [])
    return {
        "findingsFingerprint": _fingerprint("cpbf1_", normalized_keys),
        "newCriticalHighCount": len(current_high.difference(normalized_keys)),
    }


def _checkpoint_row_problem(
    connection: sqlite3.Connection,
    project_id: str,
    row: Any,
) -> str:
    if row["project_id"] != project_id:
        return "The stored checkpoint belongs to another project."
    scan = connection.execute(
        "SELECT project_path FROM scans WHERE id = ?",
        (row["scan_id"],),
    ).fetchone()
    if not scan or scan["project_path"] != project_id:
        return "The checkpoint scan is unavailable or belongs to another project."
    baseline_id = row["baseline_scan_id"]
    if baseline_id is not None:
        baseline = connection.execute(
            "SELECT project_path FROM scans WHERE id = ?",
            (baseline_id,),
        ).fetchone()
        if not baseline or baseline["project_path"] != project_id:
            return "The checkpoint baseline scan is unavailable or belongs to another project."
    if (
        row["baseline_provenance"] not in {"manual", "automatic", "none"}
        or (
            row["baseline_provenance"] == "none"
            and row["baseline_scan_id"] is not None
        )
        or (
            row["baseline_provenance"] != "none"
            and (not isinstance(row["baseline_scan_id"], int) or row["baseline_scan_id"] <= 0)
        )
        or row["provenance"] != PROVENANCE_MANUAL
        or not CHECKPOINT_ID_PATTERN.fullmatch(str(row["checkpoint_id"] or ""))
        or not _utc_timestamp(row["created_at"])
        or not FINGERPRINT_PATTERN.fullmatch(str(row["evidence_fingerprint"] or ""))
        or not _stored_fingerprint(row["expectations_fingerprint"], "cpex1_")
        or not (
            _stored_fingerprint(row["dependency_analysis_fingerprint"], "cfdb2_")
            or _stored_fingerprint(row["dependency_analysis_fingerprint"], "cpda1_")
        )
        or not _stored_fingerprint(row["finding_reviews_fingerprint"], "cpfr1_")
        or not _stored_fingerprint(row["coverage_fingerprint"], "cpcov1_")
        or row["dependency_approval_state"] not in {
            "approved",
            "changed",
            "significant-change",
            "not-applicable",
            "not-configured",
        }
        or (
            row["dependency_approval_state"] in {
                "approved",
                "changed",
                "significant-change",
            }
            and not _stored_fingerprint(row["dependency_approval_fingerprint"], "cfdb2_")
        )
        or (
            row["dependency_approval_state"] in {"not-applicable", "not-configured"}
            and row["dependency_approval_fingerprint"] != ""
        )
        or (
            row["dependency_approval_state"] == "not-applicable"
            and not _stored_fingerprint(row["dependency_analysis_fingerprint"], "cpda1_")
        )
        or (
            row["dependency_approval_state"] != "not-applicable"
            and not _stored_fingerprint(row["dependency_analysis_fingerprint"], "cfdb2_")
        )
        or (
            row["evaluator_version"] == SECURITY_STATUS_EVALUATOR_VERSION
            and (
                (
                    row["baseline_scan_id"] is None
                    and row["baseline_findings_fingerprint"] != ""
                )
                or (
                    row["baseline_scan_id"] is not None
                    and not _stored_fingerprint(
                        row["baseline_findings_fingerprint"],
                        "cpbf1_",
                    )
                )
                or not isinstance(row["new_critical_high_count"], int)
                or isinstance(row["new_critical_high_count"], bool)
                or row["new_critical_high_count"] < 0
            )
        )
        or row["finding_review_complete"] not in {0, 1}
        or row["metadata_reliable"] not in {0, 1}
        or not isinstance(row["unresolved_critical_count"], int)
        or not isinstance(row["unresolved_high_count"], int)
        or row["unresolved_critical_count"] < 0
        or row["unresolved_high_count"] < 0
    ):
        return "The stored checkpoint contains malformed or unsupported evidence."
    return ""


def _public_checkpoint(
    connection: sqlite3.Connection,
    project_id: str,
    row: Any,
) -> dict[str, Any]:
    malformed = bool(_checkpoint_row_problem(connection, project_id, row))
    return {
        "checkpointId": str(row["checkpoint_id"] or "")[:100],
        "projectId": project_id,
        "scanId": row["scan_id"] if isinstance(row["scan_id"], int) else None,
        "baselineScanId": row["baseline_scan_id"]
        if isinstance(row["baseline_scan_id"], int)
        else None,
        "baselineProvenance": str(row["baseline_provenance"] or "")[:40],
        "createdAt": str(row["created_at"] or "")[:100],
        "provenance": str(row["provenance"] or "")[:40],
        "checkpointSchemaVersion": row["checkpoint_schema_version"],
        "evaluatorVersion": row["evaluator_version"],
        "evidenceFingerprint": str(row["evidence_fingerprint"] or "")[:100],
        "malformed": malformed,
    }


def _public_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    keys = (
        "reliable",
        "readyForCheckpoint",
        "projectId",
        "scanId",
        "scanTimestamp",
        "baselineScanId",
        "baselineProvenance",
        "baselineComparisonState",
        "expectationsFingerprint",
        "expectationsConfigured",
        "expectationsMatch",
        "dependencyAnalysisFingerprint",
        "dependencyApprovalFingerprint",
        "dependencyApprovalState",
        "findingReviewsFingerprint",
        "baselineFindingsFingerprint",
        "newCriticalHighCount",
        "findingReviewComplete",
        "findingCount",
        "reviewedFindingCount",
        "unresolvedCriticalCount",
        "unresolvedHighCount",
        "coverageFingerprint",
        "coverageComplete",
        "coverageIssueCount",
        "metadataReliable",
        "checkpointSchemaVersion",
        "evaluatorVersion",
        "evidenceFingerprint",
        "reasons",
    )
    return {key: value.get(key) for key in keys}


def _indeterminate_evidence(*reasons: str) -> dict[str, Any]:
    return {
        "reliable": False,
        "readyForCheckpoint": False,
        "reasons": [str(reason)[:300] for reason in reasons if reason][:MAX_REASONS],
        "checkpointSchemaVersion": CHECKPOINT_SCHEMA_VERSION,
        "evaluatorVersion": SECURITY_STATUS_EVALUATOR_VERSION,
        "evidenceFingerprint": "",
    }


def _fingerprint(prefix: str, value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return prefix + hashlib.sha256(encoded).hexdigest()


def _stored_fingerprint(value: Any, prefix: str) -> bool:
    return bool(re.fullmatch(re.escape(prefix) + r"[0-9a-f]{64}", str(value or "")))


def _utc_timestamp(value: Any) -> bool:
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)
