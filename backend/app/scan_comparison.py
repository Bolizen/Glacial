from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable

from .finding_reviews import finding_fingerprint


MAX_COMPARISON_EXAMPLES = 10
MAX_COMPARISON_OPTIONS_PAGE = 100
MAX_COMPARISON_OPTIONS_OFFSET = 5000
MAX_METADATA_VALUES = 500
COMPLETENESS_COUNT_FIELDS = (
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


def comparison_options_page(
    rows: Iterable[Any],
    *,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    selected = list(rows)
    has_more = len(selected) > limit
    scans = [_scan_summary(row, _comparison_scan(row)) for row in selected[:limit]]
    return {
        "scans": scans,
        "hasMore": has_more,
        "nextOffset": offset + limit if has_more else None,
    }


def compare_scan_rows(first_row: Any, second_row: Any) -> dict[str, Any]:
    base_row, target_row = _chronological_rows(first_row, second_row)
    base = _comparison_scan(base_row)
    target = _comparison_scan(target_row)
    findings = _compare_findings(base_row, target_row, base, target)
    dependencies = _compare_dependencies(base, target)
    coverage = _compare_coverage(base_row, target_row)
    metadata_base = _metadata_source(base)
    metadata_target = _metadata_source(target)
    metadata_status = (
        "comparable"
        if metadata_base["reliable"] and metadata_target["reliable"]
        else "indeterminate"
    )
    statuses = [
        findings["status"],
        dependencies["status"],
        coverage["status"],
        metadata_status,
    ]
    return {
        "baseScan": {**_scan_summary(base_row, base), "metadataSource": metadata_base},
        "targetScan": {**_scan_summary(target_row, target), "metadataSource": metadata_target},
        "overallStatus": _overall_status(statuses),
        "sections": {
            "findings": findings,
            "dependencies": dependencies,
            "coverage": coverage,
            "projectMetadataStatus": metadata_status,
        },
    }


def trusted_scan_eligibility(row: Any) -> dict[str, Any]:
    scan = _comparison_scan(row)
    coverage = _coverage_snapshot(row)
    if coverage is None:
        return {
            "eligible": False,
            "status": "indeterminate",
            "reason": "Coverage metadata is missing, malformed, or internally inconsistent.",
        }
    if coverage["complete"] is not True:
        return {
            "eligible": False,
            "status": "incomplete",
            "reason": "Scan coverage is incomplete.",
        }
    metadata = _metadata_source(scan)
    if metadata.get("reliable") is not True:
        return {
            "eligible": False,
            "status": "indeterminate",
            "reason": str(metadata.get("reason") or "Persisted scan metadata is unreliable."),
        }
    dependency = _dependency_inventory(scan.get("dependencyTrust"))
    if dependency["state"] != "complete":
        return {
            "eligible": False,
            "status": "indeterminate" if dependency["state"] == "indeterminate" else dependency["state"],
            "reason": "Dependency metadata is not in a supported complete state.",
        }
    return {
        "eligible": True,
        "status": "reliable",
        "reason": "Coverage, persisted project metadata, and supported dependency metadata are complete and reliable.",
    }


def trusted_scan_summary(row: Any, *, include_metadata: bool = False) -> dict[str, Any]:
    scan = _comparison_scan(row)
    eligibility = trusted_scan_eligibility(row)
    summary = {
        **_scan_summary(row, scan),
        "eligibility": eligibility,
    }
    summary["scanDate"] = str(summary["scanDate"])[:100]
    if include_metadata and eligibility["eligible"]:
        summary["scan"] = {
            "id": int(row["id"]),
            "scan_date": str(row["scan_date"] or "")[:100],
            **_trusted_metadata_snapshot(scan),
        }
    return summary


def _trusted_metadata_snapshot(scan: dict[str, Any]) -> dict[str, Any]:
    def strings(value: Any) -> list[str]:
        return [
            _bounded_text(item, 500)
            for item in value[:MAX_METADATA_VALUES]
            if isinstance(item, str)
        ] if isinstance(value, list) else []

    scripts = scan.get("lifecycleScripts")
    dependency = scan.get("dependencyTrust")
    return {
        "manifests": strings(scan.get("manifests")),
        "lockfiles": strings(scan.get("lockfiles")),
        "lifecycleScripts": [
            {
                "path": _bounded_text(item.get("path"), 500),
                "script": _bounded_text(item.get("script"), 300),
            }
            for item in scripts[:MAX_METADATA_VALUES]
            if isinstance(item, dict)
        ] if isinstance(scripts, list) else [],
        "ignoredFiles": strings(scan.get("ignoredFiles")),
        "reviewedFiles": strings(scan.get("reviewedFiles")),
        "scanCompleteness": _bounded_value(scan.get("scanCompleteness")),
        "scanMetadataReliable": True,
        "dependencyTrust": {
            "schemaVersion": dependency.get("schemaVersion"),
            "status": _bounded_text(dependency.get("status"), 40),
            "packageManagers": strings(dependency.get("packageManagers")),
            "ecosystems": strings(dependency.get("ecosystems")),
        } if isinstance(dependency, dict) else {},
    }


def _chronological_rows(first: Any, second: Any) -> tuple[Any, Any]:
    def key(row: Any) -> tuple[datetime, int]:
        raw = str(row["scan_date"] or "")
        try:
            timestamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
        except ValueError:
            timestamp = datetime.min.replace(tzinfo=timezone.utc)
        return timestamp, int(row["id"])

    return tuple(sorted((first, second), key=key))  # type: ignore[return-value]


def _scan_summary(row: Any, scan: dict[str, Any]) -> dict[str, Any]:
    coverage = _coverage_snapshot(row)
    complete = coverage["complete"] if coverage else None
    metadata_reliable = scan.get("scanMetadataReliable") is True
    if complete is True and metadata_reliable:
        reliability = "reliable"
    elif complete is False or metadata_reliable is False:
        reliability = "limited"
    else:
        reliability = "indeterminate"
    return {
        "id": int(row["id"]),
        "scanDate": str(row["scan_date"] or ""),
        "completionState": "complete" if complete is True else "incomplete" if complete is False else "unknown",
        "reliabilityStatus": reliability,
    }


def _compare_findings(
    base_row: Any,
    target_row: Any,
    base: dict[str, Any],
    target: dict[str, Any],
) -> dict[str, Any]:
    base_findings = _raw_object_list(base_row["findings_json"])
    target_findings = _raw_object_list(target_row["findings_json"])
    if base_findings is None or target_findings is None:
        return _unavailable_section(
            "indeterminate",
            "Persisted findings are malformed, so the findings comparison is indeterminate.",
            ("added", "resolved", "changed", "unchanged"),
        )
    if not _findings_reliable(base_findings) or not _findings_reliable(target_findings):
        return _unavailable_section(
            "indeterminate",
            "Persisted finding identity fields are malformed, so the findings comparison is indeterminate.",
            ("added", "resolved", "changed", "unchanged"),
        )

    base_complete = _scan_complete(base_row)
    target_complete = _scan_complete(target_row)
    base_groups = _finding_groups(base_findings)
    target_groups = _finding_groups(target_findings)
    unchanged: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    base_only: list[dict[str, Any]] = []
    target_only: list[dict[str, Any]] = []
    for identity in sorted(set(base_groups) | set(target_groups)):
        old = base_groups.get(identity, [])
        new = target_groups.get(identity, [])
        common = min(len(old), len(new))
        for index in range(common):
            before = old[index]
            after = new[index]
            changed_properties = _finding_changes(before, after)
            example = _finding_example(after)
            if changed_properties:
                changed.append({
                    **example,
                    "changedProperties": changed_properties,
                    "beforeSeverity": _bounded_text(before.get("severity"), 30),
                    "afterSeverity": _bounded_text(after.get("severity"), 30),
                })
            else:
                unchanged.append(example)
        base_only.extend(old[common:])
        target_only.extend(new[common:])

    removals_reliable = base_complete and target_complete
    additions_reliable = base_complete and target_complete
    status = "comparable" if additions_reliable and removals_reliable else "partially-comparable"
    counts = {
        "added": len(target_only) if additions_reliable else None,
        "resolved": len(base_only) if removals_reliable else None,
        "changed": len(changed),
        "unchanged": len(unchanged),
    }
    return {
        "status": status,
        "message": (
            "Persisted findings are comparable across both complete scans."
            if status == "comparable"
            else "Shared findings can be compared, but absence from an incomplete scan is not treated as introduction or resolution."
        ),
        "counts": counts,
        "examples": {
            "added": [_finding_example(item) for item in target_only[:MAX_COMPARISON_EXAMPLES]]
            if additions_reliable else [],
            "resolved": [_finding_example(item) for item in base_only[:MAX_COMPARISON_EXAMPLES]]
            if removals_reliable else [],
            "changed": changed[:MAX_COMPARISON_EXAMPLES],
            "unchanged": unchanged[:MAX_COMPARISON_EXAMPLES],
        },
        "omittedDetailCounts": {
            "added": max(0, len(target_only) - MAX_COMPARISON_EXAMPLES) if additions_reliable else 0,
            "resolved": max(0, len(base_only) - MAX_COMPARISON_EXAMPLES) if removals_reliable else 0,
            "changed": max(0, len(changed) - MAX_COMPARISON_EXAMPLES),
            "unchanged": max(0, len(unchanged) - MAX_COMPARISON_EXAMPLES),
        },
    }


def _finding_groups(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        identity = "|".join((
            _bounded_text(finding.get("type") or finding.get("finding_type") or "unknown", 120).lower(),
            _normalized_path(finding.get("path") or finding.get("file_path")),
            _bounded_text(
                finding.get("rule")
                or finding.get("ruleId")
                or finding.get("detector")
                or finding.get("detectorId"),
                120,
            ).lower(),
        ))
        groups.setdefault(identity, []).append(finding)
    for values in groups.values():
        values.sort(key=_finding_sort_key)
    return groups


def _finding_sort_key(finding: dict[str, Any]) -> str:
    try:
        return finding_fingerprint(finding)
    except ValueError:
        return json.dumps(_finding_properties(finding), sort_keys=True, default=str)


def _finding_changes(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    old = _finding_properties(before)
    new = _finding_properties(after)
    return sorted(key for key in set(old) | set(new) if old.get(key) != new.get(key))


def _finding_properties(finding: dict[str, Any]) -> dict[str, Any]:
    properties = {
        "severity": _bounded_text(finding.get("severity") or "low", 30).lower(),
        "category": _bounded_text(finding.get("category"), 120),
        "rule": _bounded_text(
            finding.get("rule")
            or finding.get("ruleId")
            or finding.get("detector")
            or finding.get("detectorId"),
            120,
        ),
        "path": _normalized_path(finding.get("path") or finding.get("file_path")),
    }
    evidence_fields = (
        "pattern",
        "script",
        "operation",
        "reason",
        "ecosystem",
        "package",
        "dependencyGroup",
        "requestedSpecification",
        "resolvedVersion",
        "metadata",
    )
    properties["evidence"] = {
        key: _bounded_value(finding.get(key))
        for key in evidence_fields
        if finding.get(key) not in (None, "", [], {})
    }
    return properties


def _finding_example(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": _bounded_text(finding.get("type") or finding.get("finding_type") or "unknown", 120),
        "severity": _bounded_text(finding.get("severity") or "low", 30),
        "path": _normalized_path(finding.get("path") or finding.get("file_path")),
    }


def _compare_dependencies(base: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    old = _dependency_inventory(base.get("dependencyTrust"))
    new = _dependency_inventory(target.get("dependencyTrust"))
    if old["state"] == "unavailable" or new["state"] == "unavailable":
        return _unavailable_section(
            "unavailable",
            "Dependency analysis is unavailable for at least one selected scan.",
            ("added", "removed", "versionChanged", "unchanged"),
            extra={"baseAnalysisStatus": old["status"], "targetAnalysisStatus": new["status"]},
        )
    if old["state"] == "indeterminate" or new["state"] == "indeterminate":
        return _unavailable_section(
            "indeterminate",
            "Dependency analysis is malformed or uses an unknown schema, so comparison is indeterminate.",
            ("added", "removed", "versionChanged", "unchanged"),
            extra={"baseAnalysisStatus": old["status"], "targetAnalysisStatus": new["status"]},
        )

    old_entries = old["entries"]
    new_entries = new["entries"]
    shared_keys = sorted(set(old_entries) & set(new_entries))
    version_changed = [
        {
            **_dependency_example(new_entries[key]),
            "beforeVersion": _dependency_version(old_entries[key]),
            "afterVersion": _dependency_version(new_entries[key]),
        }
        for key in shared_keys
        if _dependency_version(old_entries[key]) != _dependency_version(new_entries[key])
    ]
    unchanged = [
        _dependency_example(new_entries[key])
        for key in shared_keys
        if _dependency_version(old_entries[key]) == _dependency_version(new_entries[key])
    ]
    fully_comparable = old["state"] == "complete" and new["state"] == "complete"
    added_keys = sorted(set(new_entries) - set(old_entries)) if fully_comparable else []
    removed_keys = sorted(set(old_entries) - set(new_entries)) if fully_comparable else []
    return {
        "status": "comparable" if fully_comparable else "partially-comparable",
        "message": (
            "Normalized dependency inventories are comparable."
            if fully_comparable
            else "Shared dependency versions can be compared, but incomplete analysis cannot prove additions or removals."
        ),
        "baseAnalysisStatus": old["status"],
        "targetAnalysisStatus": new["status"],
        "counts": {
            "added": len(added_keys) if fully_comparable else None,
            "removed": len(removed_keys) if fully_comparable else None,
            "versionChanged": len(version_changed),
            "unchanged": len(unchanged),
        },
        "examples": {
            "added": [_dependency_example(new_entries[key]) for key in added_keys[:MAX_COMPARISON_EXAMPLES]],
            "removed": [_dependency_example(old_entries[key]) for key in removed_keys[:MAX_COMPARISON_EXAMPLES]],
            "versionChanged": version_changed[:MAX_COMPARISON_EXAMPLES],
            "unchanged": unchanged[:MAX_COMPARISON_EXAMPLES],
        },
        "omittedDetailCounts": {
            "added": max(0, len(added_keys) - MAX_COMPARISON_EXAMPLES),
            "removed": max(0, len(removed_keys) - MAX_COMPARISON_EXAMPLES),
            "versionChanged": max(0, len(version_changed) - MAX_COMPARISON_EXAMPLES),
            "unchanged": max(0, len(unchanged) - MAX_COMPARISON_EXAMPLES),
        },
    }


def _dependency_inventory(value: Any) -> dict[str, Any]:
    if value is None:
        return {"state": "unavailable", "status": "unavailable", "entries": {}}
    if not isinstance(value, dict) or value.get("schemaVersion") != 1:
        return {"state": "indeterminate", "status": "unknown", "entries": {}}
    status = _bounded_text(value.get("status") or "unknown", 40).lower()
    entries = value.get("entries")
    if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
        return {"state": "indeterminate", "status": status, "entries": {}}
    normalized: dict[str, dict[str, Any]] = {}
    for entry in entries:
        name = _bounded_text(entry.get("name"), 200).lower()
        ecosystem = _bounded_text(entry.get("ecosystem"), 60).lower()
        group = _bounded_text(entry.get("group"), 80).lower()
        direct = entry.get("direct") is True
        if not name or not ecosystem:
            return {"state": "indeterminate", "status": status, "entries": {}}
        key = f"{ecosystem}|{name}|{group}|{int(direct)}"
        if key in normalized:
            return {"state": "indeterminate", "status": status, "entries": {}}
        normalized[key] = entry
    state = "complete" if status == "complete" else "partial" if status == "incomplete" else "indeterminate"
    return {"state": state, "status": status, "entries": normalized}


def _dependency_version(entry: dict[str, Any]) -> str:
    locked = _bounded_text(entry.get("lockedVersion"), 200)
    if locked:
        return locked
    specification = _bounded_text(entry.get("requestedSpecification"), 200)
    if (
        "://" in specification
        or "\x00" in specification
        or "\\" in specification
        or specification.startswith(("/", "file:"))
        or (len(specification) >= 2 and specification[1] == ":")
        or "@" in specification
    ):
        return "[non-version specification]"
    return specification


def _dependency_example(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "ecosystem": _bounded_text(entry.get("ecosystem"), 60),
        "name": _bounded_text(entry.get("name"), 200),
        "version": _dependency_version(entry),
    }


def _compare_coverage(base_row: Any, target_row: Any) -> dict[str, Any]:
    old = _coverage_snapshot(base_row)
    new = _coverage_snapshot(target_row)
    if old is None or new is None:
        return _unavailable_section(
            "indeterminate",
            "Persisted coverage counts are missing, malformed, or internally inconsistent.",
            ("filesConsidered", "filesScanned", "skippedFiles", "ignoredFiles", "failedFiles"),
        )
    metrics: dict[str, Any] = {}
    for key in ("filesScanned", "skippedFiles", "ignoredFiles", "failedFiles"):
        metrics[key] = {
            "base": old[key],
            "target": new[key],
            "change": new[key] - old[key],
        }
    metrics["filesConsidered"] = {
        "base": None,
        "target": None,
        "change": None,
    }
    return {
        "status": "partially-comparable",
        "message": "Exact persisted coverage counts are compared. Total files considered was not persisted and remains unavailable.",
        "baseComplete": old["complete"],
        "targetComplete": new["complete"],
        "metrics": metrics,
    }


def _coverage_snapshot(row: Any) -> dict[str, Any] | None:
    metadata = _raw_metadata(row)
    completeness = metadata.get("scanCompleteness")
    if not isinstance(completeness, dict):
        return None
    counts: dict[str, int] = {}
    for field in COMPLETENESS_COUNT_FIELDS:
        value = completeness.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return None
        counts[field] = value
    issue_count = completeness.get("issueCount")
    complete = completeness.get("complete")
    if (
        not isinstance(issue_count, int)
        or isinstance(issue_count, bool)
        or issue_count != sum(counts.values())
        or not isinstance(complete, bool)
        or complete != (issue_count == 0)
    ):
        return None
    reviewed = row["reviewed_file_count"]
    ignored = row["ignored_file_count"]
    if (
        not isinstance(reviewed, int)
        or isinstance(reviewed, bool)
        or reviewed < 0
        or not isinstance(ignored, int)
        or isinstance(ignored, bool)
        or ignored < 0
    ):
        return None
    reviewed_paths = metadata.get("reviewedFiles")
    ignored_paths = metadata.get("ignoredFiles")
    built_in_excluded_paths = metadata.get("builtInExcludedDirectories", [])
    if (
        not isinstance(reviewed_paths, list)
        or any(not isinstance(item, str) for item in reviewed_paths)
        or len(reviewed_paths) != reviewed
        or not isinstance(ignored_paths, list)
        or any(not isinstance(item, str) for item in ignored_paths)
        or len(ignored_paths) != ignored
        or not isinstance(built_in_excluded_paths, list)
        or any(not isinstance(item, str) for item in built_in_excluded_paths)
        or len(built_in_excluded_paths) > counts["builtInExcludedDirectoryCount"]
    ):
        return None
    return {
        "complete": complete,
        "filesScanned": reviewed,
        "ignoredFiles": ignored,
        "skippedFiles": (
            counts["oversizedFileCount"]
            + counts["unsafePathCount"]
            + counts["policyExcludedFileCount"]
            + counts["builtInExcludedDirectoryCount"]
        ),
        "failedFiles": (
            counts["traversalFailureCount"]
            + counts["fileInspectionFailureCount"]
            + counts["dependencyAnalysisFailureCount"]
            + counts["unsupportedEncodingFileCount"]
        ),
    }


def _metadata_source(scan: dict[str, Any]) -> dict[str, Any]:
    if scan.get("scanMetadataReliable") is not True:
        return {
            "reliable": False,
            "reason": "Persisted project metadata is missing or malformed.",
        }
    fields = {
        "manifests": scan.get("manifests"),
        "lockfiles": scan.get("lockfiles"),
        "lifecycleScripts": scan.get("lifecycleScripts"),
        "ignoredFiles": scan.get("ignoredFiles"),
        "builtInExcludedDirectories": scan.get("builtInExcludedDirectories"),
        "reviewedFiles": scan.get("reviewedFiles"),
    }
    dependency = scan.get("dependencyTrust")
    total = sum(len(value) for value in fields.values() if isinstance(value, list))
    if isinstance(dependency, dict):
        total += sum(
            len(dependency.get(key, []))
            for key in ("packageManagers", "ecosystems")
            if isinstance(dependency.get(key), list)
        )
    if total > MAX_METADATA_VALUES:
        return {
            "reliable": False,
            "reason": "Observed project metadata exceeds the bounded comparison detail limit.",
        }
    source = {
        key: value
        for key, value in fields.items()
    }
    source.update({
        "scanCompleteness": scan.get("scanCompleteness"),
        "scanMetadataReliable": scan.get("scanMetadataReliable"),
        "dependencyTrust": dependency,
    })
    return {"reliable": True, "scan": source}


def _raw_metadata(row: Any) -> dict[str, Any]:
    try:
        value = json.loads(row["scan_metadata_json"])
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _comparison_scan(row: Any) -> dict[str, Any]:
    metadata = _raw_metadata(row)
    return {
        "manifests": metadata.get("manifests"),
        "lockfiles": metadata.get("lockfiles"),
        "lifecycleScripts": metadata.get("lifecycleScripts"),
        "ignoredFiles": metadata.get("ignoredFiles"),
        "builtInExcludedDirectories": metadata.get("builtInExcludedDirectories", []),
        "reviewedFiles": metadata.get("reviewedFiles"),
        "scanCompleteness": metadata.get("scanCompleteness"),
        "scanMetadataReliable": _raw_scan_metadata_reliable(metadata),
        "dependencyTrust": metadata.get("dependencyTrust"),
    }


def _raw_scan_metadata_reliable(metadata: dict[str, Any]) -> bool:
    for field in ("manifests", "lockfiles", "ignoredFiles", "reviewedFiles"):
        value = metadata.get(field)
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            return False
    built_in_exclusions = metadata.get("builtInExcludedDirectories", [])
    if not isinstance(built_in_exclusions, list) or any(not isinstance(item, str) for item in built_in_exclusions):
        return False
    scripts = metadata.get("lifecycleScripts")
    return isinstance(scripts, list) and all(
        isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and isinstance(item.get("script"), str)
        for item in scripts
    )


def _scan_complete(row: Any) -> bool:
    snapshot = _coverage_snapshot(row)
    return snapshot is not None and snapshot["complete"] is True


def _raw_object_list(value: Any) -> list[dict[str, Any]] | None:
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, list) or any(not isinstance(item, dict) for item in parsed):
        return None
    return parsed


def _findings_reliable(findings: list[dict[str, Any]]) -> bool:
    for finding in findings:
        finding_type = finding.get("type") or finding.get("finding_type")
        path = finding.get("path") or finding.get("file_path") or ""
        if not isinstance(finding_type, str) or not finding_type.strip():
            return False
        if path and (
            not isinstance(path, str)
            or _normalized_path(path) == "[invalid persisted path]"
        ):
            return False
    return True


def _unavailable_section(
    status: str,
    message: str,
    count_keys: tuple[str, ...],
    *,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "message": message,
        "counts": {key: None for key in count_keys},
        "examples": {key: [] for key in count_keys},
        **(extra or {}),
    }


def _overall_status(statuses: list[str]) -> str:
    if statuses and all(status == "comparable" for status in statuses):
        return "comparable"
    if any(status in {"comparable", "partially-comparable"} for status in statuses):
        return "partially-comparable"
    if any(status == "indeterminate" for status in statuses):
        return "indeterminate"
    return "unavailable"


def _normalized_path(value: Any) -> str:
    text = _bounded_text(value, 500).replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    if text.startswith("/") or (len(text) >= 2 and text[1] == ":") or ".." in text.split("/"):
        return "[invalid persisted path]"
    return "/".join(part for part in text.split("/") if part not in ("", "."))


def _bounded_value(value: Any, depth: int = 0) -> Any:
    if depth > 3:
        return None
    if isinstance(value, str):
        return _bounded_text(value, 300)
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    if isinstance(value, list):
        return [_bounded_value(item, depth + 1) for item in value[:20]]
    if isinstance(value, dict):
        return {
            _bounded_text(key, 80): _bounded_value(item, depth + 1)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))[:20]
        }
    return None


def _bounded_text(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]
