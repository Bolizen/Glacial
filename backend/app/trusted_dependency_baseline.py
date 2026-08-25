from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from .privacy import sanitize_private_text, validate_dependency_integrity


BASELINE_SCHEMA_VERSION = 2
FINGERPRINT_PREFIX = "cfdb2_"
FINGERPRINT_PATTERN = re.compile(r"^cfdb2_[0-9a-f]{64}$")
MAX_ENTRIES = 2000
MAX_PATHS = 500
MAX_CHANGES = 300
MAX_STRING = 500
SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}
SUPPORTED_ECOSYSTEMS = {"node", "python"}
SUPPORTED_SOURCE_TYPES = {"registry", "url", "vcs", "local", "unknown"}
_PRIVACY_REDACTION_MARKERS = (
    "[redacted",
    "<glacial_data_dir>",
    "<host_path>",
    "<project_root>",
    "<temp_dir>",
    "<user_profile>",
    "malformed remote source",
    "redacted dependency locator",
)


class BaselineError(ValueError):
    pass


def snapshot_from_analysis(analysis: Mapping[str, Any]) -> dict[str, Any]:
    if analysis.get("schemaVersion") != 1:
        raise BaselineError("Dependency analysis schema is unavailable or incompatible.")
    if analysis.get("status") != "complete":
        raise BaselineError(_ineligible_reason(analysis))
    manifests = _paths(analysis.get("manifests"))
    lockfiles = _paths(analysis.get("lockfiles"))
    if not manifests and not lockfiles:
        raise BaselineError("No supported dependency metadata was analyzed in this scan.")
    entries_value = analysis.get("entries")
    if not isinstance(entries_value, list) or len(entries_value) > MAX_ENTRIES:
        raise BaselineError("Dependency inventory is unavailable or exceeds the trusted baseline limit.")
    entries = [_entry(item) for item in entries_value if isinstance(item, Mapping)]
    if len(entries) != len(entries_value):
        raise BaselineError("Dependency inventory contains invalid entries.")
    snapshot = {
        "baselineSchemaVersion": BASELINE_SCHEMA_VERSION,
        "dependencySchemaVersion": 1,
        "ecosystems": _strings(analysis.get("ecosystems"), 20, 60),
        "manifests": manifests,
        "lockfiles": lockfiles,
        "packageManagers": _strings(analysis.get("packageManagers"), 50, 60),
        "entries": sorted(entries, key=_entry_sort_key),
        "status": "complete",
    }
    _validate_snapshot_relationships(snapshot)
    _bounded_snapshot(snapshot)
    return snapshot


def snapshot_fingerprint(snapshot: Mapping[str, Any]) -> str:
    canonical = _validated_snapshot(snapshot)
    encoded = json.dumps(canonical, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return FINGERPRINT_PREFIX + hashlib.sha256(encoded).hexdigest()


def approval_for_analysis(analysis: Any) -> dict[str, Any]:
    if not isinstance(analysis, Mapping):
        return {"eligible": False, "fingerprint": "", "reason": "This scan predates dependency analysis."}
    try:
        snapshot = snapshot_from_analysis(analysis)
    except BaselineError as error:
        return {"eligible": False, "fingerprint": "", "reason": str(error)}
    return {"eligible": True, "fingerprint": snapshot_fingerprint(snapshot), "reason": ""}


def public_baseline(row: Mapping[str, Any] | None) -> dict[str, Any]:
    if row is None:
        return {"configured": False, "valid": False, "status": "not-configured"}
    try:
        snapshot = _snapshot_from_row(row)
        fingerprint = snapshot_fingerprint(snapshot)
        if fingerprint != str(row.get("fingerprint") or ""):
            raise BaselineError("Stored baseline fingerprint does not match its snapshot.")
    except (BaselineError, TypeError, json.JSONDecodeError):
        return {
            "configured": True,
            "valid": False,
            "status": "invalid",
            "explanation": "The stored trusted baseline is invalid or incompatible and was not used.",
        }
    return {
        "configured": True,
        "valid": True,
        "status": "configured",
        "baselineSchemaVersion": BASELINE_SCHEMA_VERSION,
        "dependencySchemaVersion": snapshot["dependencySchemaVersion"],
        "fingerprint": fingerprint,
        "sourceScanId": row.get("source_scan_id"),
        "sourceScanDate": _text(row.get("source_scan_date"), 100),
        "note": _text(row.get("note"), 1000),
        "createdAt": _text(row.get("created_at"), 100),
        "updatedAt": _text(row.get("updated_at"), 100),
    }


def enrich_scan(scan: Mapping[str, Any], baseline_row: Mapping[str, Any] | None) -> dict[str, Any]:
    enriched = dict(scan)
    analysis_value = scan.get("dependencyTrust")
    analysis = dict(analysis_value) if isinstance(analysis_value, Mapping) else None
    baseline = public_baseline(baseline_row)
    approval = approval_for_analysis(analysis)
    comparison = compare_with_baseline(analysis, baseline_row)
    baseline["approval"] = approval
    baseline["comparison"] = comparison
    if analysis is not None:
        analysis["trustedBaseline"] = baseline
        enriched["dependencyTrust"] = analysis
    else:
        enriched["trustedDependencyBaseline"] = baseline
    return enriched


def compare_with_baseline(
    analysis: Mapping[str, Any] | None,
    baseline_row: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if baseline_row is None:
        return _comparison("not-configured", "No trusted dependency baseline is configured.")
    try:
        baseline = _snapshot_from_row(baseline_row)
        expected_fingerprint = snapshot_fingerprint(baseline)
        if expected_fingerprint != str(baseline_row.get("fingerprint") or ""):
            raise BaselineError("Stored baseline fingerprint mismatch.")
    except (BaselineError, TypeError, json.JSONDecodeError):
        return _comparison("invalid", "The stored trusted baseline is invalid and was not used.", [
            _finding(
                "trusted-baseline-incompatible", "medium",
                "Trusted baseline comparison is unavailable because the stored baseline is invalid or incompatible.",
            ),
        ])
    if not isinstance(analysis, Mapping):
        return _comparison("incompatible", "This scan predates dependency analysis.", [
            _finding(
                "trusted-baseline-incompatible", "low",
                "Trusted baseline comparison is unavailable because this scan predates dependency analysis.",
            ),
        ])
    if analysis.get("schemaVersion") != baseline["dependencySchemaVersion"]:
        return _comparison("incompatible", "Dependency analysis schema is incompatible with the trusted baseline.", [
            _finding(
                "trusted-baseline-incompatible", "medium",
                "Trusted baseline comparison is unavailable because dependency analysis schemas are incompatible.",
            ),
        ])
    current_complete = analysis.get("status") == "complete"
    try:
        current = _snapshot_for_comparison(analysis)
    except BaselineError:
        return _comparison("incomplete", "Current dependency analysis is unavailable, malformed, or unsupported.", [
            _finding("trusted-baseline-comparison-incomplete", "medium", "Trusted baseline comparison is incomplete because current dependency analysis is unavailable.")
        ])
    changes = _compare_snapshots(baseline, current, allow_removals=current_complete)
    if not current_complete:
        findings = [_finding(
            "trusted-baseline-comparison-incomplete",
            "medium",
            "Trusted baseline comparison is incomplete; removals were not inferred from partial dependency analysis.",
        )]
        findings.extend(_findings_for_changes(changes))
        return _comparison("incomplete", "Comparison incomplete; current analysis cannot prove removals.", findings, changes)
    current_fingerprint = snapshot_fingerprint(current)
    if current_fingerprint == expected_fingerprint:
        return _comparison("identical", "Matches approved baseline.")
    return _comparison(
        "drift",
        "Drift detected from approved baseline.",
        _findings_for_changes(changes),
        changes,
    )


def snapshot_json(snapshot: Mapping[str, Any]) -> str:
    return json.dumps(_validated_snapshot(snapshot), ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def valid_fingerprint(value: Any) -> bool:
    return bool(FINGERPRINT_PATTERN.fullmatch(str(value or "")))


def _snapshot_for_comparison(analysis: Mapping[str, Any]) -> dict[str, Any]:
    if analysis.get("schemaVersion") != 1 or not isinstance(analysis.get("entries"), list):
        raise BaselineError("Dependency analysis is incompatible.")
    manifests = _paths(analysis.get("manifests"))
    lockfiles = _paths(analysis.get("lockfiles"))
    entries_value = analysis["entries"]
    if len(entries_value) > MAX_ENTRIES or any(not isinstance(item, Mapping) for item in entries_value):
        raise BaselineError("Dependency inventory is invalid.")
    snapshot = {
        "baselineSchemaVersion": BASELINE_SCHEMA_VERSION,
        "dependencySchemaVersion": 1,
        "ecosystems": _strings(analysis.get("ecosystems"), 20, 60),
        "manifests": manifests,
        "lockfiles": lockfiles,
        "packageManagers": _strings(analysis.get("packageManagers"), 50, 60),
        "entries": sorted((_entry(item) for item in entries_value), key=_entry_sort_key),
        "status": "complete" if analysis.get("status") == "complete" else "incomplete",
    }
    _validate_snapshot_relationships(snapshot)
    _bounded_snapshot(snapshot)
    return snapshot


def _validated_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    if snapshot.get("baselineSchemaVersion") != BASELINE_SCHEMA_VERSION:
        raise BaselineError("Trusted baseline schema is incompatible.")
    if snapshot.get("dependencySchemaVersion") != 1 or snapshot.get("status") != "complete":
        raise BaselineError("Trusted dependency snapshot is incomplete or incompatible.")
    normalized = {
        "baselineSchemaVersion": BASELINE_SCHEMA_VERSION,
        "dependencySchemaVersion": 1,
        "ecosystems": _strings(snapshot.get("ecosystems"), 20, 60),
        "manifests": _paths(snapshot.get("manifests")),
        "lockfiles": _paths(snapshot.get("lockfiles")),
        "packageManagers": _strings(snapshot.get("packageManagers"), 50, 60),
        "entries": sorted((_entry(item) for item in _mapping_list(snapshot.get("entries"))), key=_entry_sort_key),
        "status": "complete",
    }
    if not normalized["manifests"] and not normalized["lockfiles"]:
        raise BaselineError("Trusted baseline contains no supported dependency metadata.")
    _validate_snapshot_relationships(normalized)
    _bounded_snapshot(normalized)
    return normalized


def _snapshot_from_row(row: Mapping[str, Any]) -> dict[str, Any]:
    try:
        stored_version = int(row.get("baseline_schema_version") or 0)
        dependency_version = int(row.get("dependency_schema_version") or 0)
    except (TypeError, ValueError, OverflowError) as error:
        raise BaselineError("Stored baseline schema is invalid.") from error
    if stored_version != BASELINE_SCHEMA_VERSION:
        raise BaselineError("Stored baseline schema is incompatible.")
    raw = row.get("snapshot_json")
    snapshot = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(snapshot, Mapping):
        raise BaselineError("Stored baseline snapshot is invalid.")
    normalized = _validated_snapshot(snapshot)
    if dependency_version != normalized["dependencySchemaVersion"]:
        raise BaselineError("Stored dependency analysis schema is incompatible.")
    return normalized


def _entry(value: Mapping[str, Any]) -> dict[str, Any]:
    string_fields = (
        "ecosystem", "name", "group", "requestedSpecification", "lockedVersion",
        "sourceType", "sourceIdentifier", "vcsRequestedRevision", "vcsLockedRevision",
        "vcsResolvedRevision", "integrity", "manifestPath", "lockfilePath",
    )
    boolean_fields = ("integrityPresent", "direct", "optional", "dev", "peer", "installScriptIndicator")
    if any(value.get(field) is not None and not isinstance(value.get(field), str) for field in string_fields):
        raise BaselineError("Dependency inventory contains invalid text fields.")
    if any(field in value and not isinstance(value.get(field), bool) for field in boolean_fields):
        raise BaselineError("Dependency inventory contains invalid boolean fields.")
    ecosystem = _canonical_text(value.get("ecosystem"), 60, "ecosystem") or "unknown"
    name = _package_name(ecosystem, value.get("name"))
    group = _identity_text(value.get("group"), 100, "dependency group") or "unknown"
    source_type = _canonical_text(value.get("sourceType"), 40, "source type") or "unknown"
    if source_type not in SUPPORTED_SOURCE_TYPES:
        raise BaselineError("Dependency inventory contains an unsupported source type.")
    source_identifier = _source_identifier(value.get("sourceIdentifier"))
    vcs_requested_revision = _vcs_revision_identity(
        value.get("vcsRequestedRevision"), {"rev", "tag", "branch", "ref"}, multiple=True,
    )
    vcs_locked_revision = _vcs_revision_identity(value.get("vcsLockedRevision"), {"reference"})
    vcs_resolved_revision = _vcs_revision_identity(value.get("vcsResolvedRevision"), {"resolved"})
    if source_type != "vcs" and any((vcs_requested_revision, vcs_locked_revision, vcs_resolved_revision)):
        raise BaselineError("Non-VCS dependency inventory contains VCS revision identity.")
    integrity = _canonical_text(value.get("integrity"), 300, "integrity")
    integrity_present = value.get("integrityPresent") is True
    if integrity and not _valid_integrity(integrity):
        raise BaselineError("Dependency inventory contains malformed or unsupported integrity data.")
    if integrity_present != bool(integrity):
        raise BaselineError("Dependency inventory contains inconsistent integrity data.")
    direct = value.get("direct") is True
    if source_type == "vcs" and direct and not vcs_requested_revision:
        raise BaselineError(
            "Direct VCS dependency identity lacks an opaque requested revision."
        )
    if (
        source_type == "vcs"
        and not direct
        and not any((vcs_locked_revision, vcs_resolved_revision))
    ):
        raise BaselineError("Locked VCS dependency identity lacks an opaque revision.")
    if source_type == "url" and not integrity:
        raise BaselineError("URL dependency identity lacks artifact integrity.")
    entry = {
        "ecosystem": ecosystem,
        "name": name,
        "group": group,
        "requestedSpecification": _safe_spec(value.get("requestedSpecification")),
        "lockedVersion": _safe_spec(value.get("lockedVersion")),
        "sourceType": source_type,
        "sourceIdentifier": source_identifier,
        "vcsRequestedRevision": vcs_requested_revision,
        "vcsLockedRevision": vcs_locked_revision,
        "vcsResolvedRevision": vcs_resolved_revision,
        "integrity": integrity,
        "integrityPresent": integrity_present,
        "direct": direct,
        "optional": value.get("optional") is True,
        "dev": value.get("dev") is True,
        "peer": value.get("peer") is True,
        "installScriptIndicator": value.get("installScriptIndicator") is True,
        "manifestPath": _path(value.get("manifestPath"), allow_empty=True),
        "lockfilePath": _path(value.get("lockfilePath"), allow_empty=True),
    }
    return entry


def _compare_snapshots(baseline: Mapping[str, Any], current: Mapping[str, Any], *, allow_removals: bool) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for field, singular in (("ecosystems", "ecosystem"), ("manifests", "manifest"), ("lockfiles", "lockfile"), ("packageManagers", "package-manager")):
        old_values = set(baseline.get(field, []))
        new_values = set(current.get(field, []))
        for value in sorted(new_values - old_values):
            changes.append(_input_change(f"{singular}-added", value))
        if allow_removals:
            for value in sorted(old_values - new_values):
                changes.append(_input_change(f"{singular}-removed", value))

    old_groups = _group_entries(baseline.get("entries", []))
    new_groups = _group_entries(current.get("entries", []))
    for key in sorted(set(old_groups) | set(new_groups)):
        old_entries = old_groups.get(key, [])
        new_entries = new_groups.get(key, [])
        changes.extend(_compare_entry_group(old_entries, new_entries, allow_removals=allow_removals))
    return sorted(changes, key=_change_sort_key)


def _compare_entry_group(
    old_entries: list[dict[str, Any]],
    new_entries: list[dict[str, Any]],
    *,
    allow_removals: bool,
) -> list[dict[str, Any]]:
    old_contexts = _entries_by_context(old_entries)
    new_contexts = _entries_by_context(new_entries)
    changes: list[dict[str, Any]] = []
    for context in sorted(set(old_contexts) | set(new_contexts)):
        changes.extend(_compare_context_entries(
            old_contexts.get(context, []), new_contexts.get(context, []), allow_removals=allow_removals,
        ))
    return changes


def _compare_context_entries(
    old_entries: list[dict[str, Any]],
    new_entries: list[dict[str, Any]],
    *,
    allow_removals: bool,
) -> list[dict[str, Any]]:
    old_exact = _entries_by_full_identity(old_entries)
    new_exact = _entries_by_full_identity(new_entries)
    unmatched_old: list[dict[str, Any]] = []
    unmatched_new: list[dict[str, Any]] = []
    for identity in sorted(set(old_exact) | set(new_exact)):
        old_values = old_exact.get(identity, [])
        new_values = new_exact.get(identity, [])
        paired = min(len(old_values), len(new_values))
        unmatched_old.extend(old_values[paired:])
        unmatched_new.extend(new_values[paired:])

    changes: list[dict[str, Any]] = []
    if len(unmatched_old) == 1 and len(unmatched_new) == 1:
        return _entry_changes(unmatched_old[0], unmatched_new[0])

    old_by_identity = _entries_by_stable_identity(unmatched_old)
    new_by_identity = _entries_by_stable_identity(unmatched_new)
    remaining_old: list[dict[str, Any]] = []
    remaining_new: list[dict[str, Any]] = []
    for identity in sorted(set(old_by_identity) | set(new_by_identity)):
        old_values = old_by_identity.get(identity, [])
        new_values = new_by_identity.get(identity, [])
        paired = min(len(old_values), len(new_values))
        for index in range(paired):
            changes.extend(_entry_changes(old_values[index], new_values[index]))
        remaining_old.extend(old_values[paired:])
        remaining_new.extend(new_values[paired:])

    for entry in remaining_new:
        changes.append(_package_change("direct-dependency-added" if entry["direct"] else "locked-package-added", entry))
    if allow_removals:
        for entry in remaining_old:
            changes.append(_package_change("direct-dependency-removed" if entry["direct"] else "locked-package-removed", entry))
    return changes


def _entry_changes(old: Mapping[str, Any], current: Mapping[str, Any]) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    if old.get("requestedSpecification") != current.get("requestedSpecification"):
        changes.append(_package_change("specification-changed", current, old.get("requestedSpecification"), current.get("requestedSpecification")))
    if old.get("lockedVersion") != current.get("lockedVersion"):
        changes.append(_package_change("version-changed", current, old.get("lockedVersion"), current.get("lockedVersion")))
    old_source = (old.get("sourceType"), old.get("sourceIdentifier"))
    current_source = (current.get("sourceType"), current.get("sourceIdentifier"))
    if old_source != current_source:
        changes.append(_package_change("source-changed", current, ":".join(filter(None, old_source)), ":".join(filter(None, current_source))))
    old_revision = _vcs_revision_summary(old)
    current_revision = _vcs_revision_summary(current)
    if old_revision != current_revision:
        changes.append(_package_change("vcs-revision-changed", current, old_revision, current_revision))
    if (
        old.get("lockedVersion") == current.get("lockedVersion")
        and old_source == current_source
        and _valid_integrity(old.get("integrity"))
        and _valid_integrity(current.get("integrity"))
        and old.get("integrity") != current.get("integrity")
    ):
        changes.append(_package_change("integrity-changed", current, "recorded", "changed"))
    for field in ("integrityPresent", "optional", "dev", "peer", "installScriptIndicator", "manifestPath", "lockfilePath"):
        if old.get(field) != current.get(field):
            changes.append(_package_change(
                "dependency-metadata-changed", current, old.get(field), current.get(field), field=field,
            ))
    return changes


def _findings_for_changes(changes: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for change in changes:
        change_type = str(change.get("changeType") or "")
        finding_type = {
            "direct-dependency-added": "trusted-baseline-direct-dependency-added",
            "direct-dependency-removed": "trusted-baseline-direct-dependency-removed",
            "specification-changed": "trusted-baseline-specification-changed",
            "version-changed": "trusted-baseline-version-changed",
            "source-changed": "trusted-baseline-source-changed",
            "vcs-revision-changed": "trusted-baseline-vcs-revision-changed",
            "integrity-changed": "trusted-baseline-integrity-changed",
        }.get(change_type, "trusted-baseline-input-changed")
        severity = _change_severity(change)
        explanation = _change_explanation(change_type)
        findings.append(_finding(finding_type, severity, explanation, change))
    return findings


def _comparison(
    status: str,
    explanation: str,
    findings: list[dict[str, Any]] | None = None,
    changes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    all_changes = changes or []
    all_findings = findings or []
    return {
        "status": status,
        "explanation": explanation,
        "changeCount": len(all_changes),
        "changes": all_changes[:MAX_CHANGES],
        "findings": all_findings[:MAX_CHANGES],
        "highestSeverity": _highest_severity(all_findings),
        "truncated": len(all_changes) > MAX_CHANGES or len(all_findings) > MAX_CHANGES,
    }


def _finding(finding_type: str, severity: str, explanation: str, change: Mapping[str, Any] | None = None) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "type": finding_type,
        "severity": severity,
        "explanation": explanation,
        "action": "Review this trusted-baseline drift before installing or running dependency tooling.",
        "trustedBaselineDrift": True,
    }
    if change:
        for source, target in (("ecosystem", "ecosystem"), ("name", "package"), ("group", "dependencyGroup"), ("path", "path"), ("changeType", "changeType")):
            if change.get(source):
                finding[target] = change[source]
    return finding


def _package_change(
    change_type: str,
    entry: Mapping[str, Any],
    previous: Any = "",
    current: Any = "",
    *,
    field: str = "",
) -> dict[str, Any]:
    result = {
        "changeType": change_type,
        "ecosystem": entry.get("ecosystem", ""),
        "name": entry.get("name", ""),
        "group": entry.get("group", ""),
        "direct": entry.get("direct") is True,
        "lockedVersion": entry.get("lockedVersion", ""),
        "sourceType": entry.get("sourceType", ""),
        "sourceIdentifier": entry.get("sourceIdentifier", ""),
        "path": entry.get("manifestPath") or entry.get("lockfilePath") or "",
    }
    if field:
        result["field"] = field
    if previous not in (None, ""):
        result["previousValue"] = _text(previous, 300)
    if current not in (None, ""):
        result["currentValue"] = _text(current, 300)
    return result


def _input_change(change_type: str, value: str) -> dict[str, Any]:
    return {"changeType": change_type, "path": value}


def _vcs_revision_summary(entry: Mapping[str, Any]) -> str:
    return "|".join(
        str(entry.get(field) or "")
        for field in ("vcsRequestedRevision", "vcsLockedRevision", "vcsResolvedRevision")
    )


def _group_entries(entries: Any) -> dict[tuple[str, str, str, bool], list[dict[str, Any]]]:
    groups: dict[tuple[str, str, str, bool], list[dict[str, Any]]] = defaultdict(list)
    for entry in entries if isinstance(entries, list) else []:
        key = (entry["ecosystem"], entry["name"], entry["group"], entry["direct"])
        groups[key].append(entry)
    for values in groups.values():
        values.sort(key=_entry_sort_key)
    return groups


def _entries_by_context(entries: Iterable[dict[str, Any]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    contexts: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        contexts[(entry.get("manifestPath", ""), entry.get("lockfilePath", ""))].append(entry)
    for values in contexts.values():
        values.sort(key=_entry_sort_key)
    return contexts


def _entries_by_stable_identity(entries: Iterable[dict[str, Any]]) -> dict[tuple[Any, ...], list[dict[str, Any]]]:
    identities: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        identity = (
            entry.get("requestedSpecification"), entry.get("lockedVersion"),
            entry.get("sourceType"), entry.get("sourceIdentifier"),
        )
        identities[identity].append(entry)
    for values in identities.values():
        values.sort(key=_entry_sort_key)
    return identities


def _entries_by_full_identity(entries: Iterable[dict[str, Any]]) -> dict[tuple[Any, ...], list[dict[str, Any]]]:
    identities: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        identities[_entry_sort_key(entry)].append(entry)
    return identities


def _entry_identity(entry: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        entry.get("ecosystem"), entry.get("name"), entry.get("group"), entry.get("direct"),
        entry.get("requestedSpecification"), entry.get("lockedVersion"), entry.get("sourceType"),
        entry.get("sourceIdentifier"), entry.get("vcsRequestedRevision"), entry.get("vcsLockedRevision"),
        entry.get("vcsResolvedRevision"), entry.get("integrity"), entry.get("manifestPath"), entry.get("lockfilePath"),
    )


def _entry_sort_key(entry: Mapping[str, Any]) -> tuple[Any, ...]:
    return _entry_identity(entry) + (
        entry.get("integrityPresent"), entry.get("optional"), entry.get("dev"), entry.get("peer"),
        entry.get("installScriptIndicator"),
    )


def _change_sort_key(change: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(str(change.get(key) or "") for key in ("changeType", "ecosystem", "name", "group", "path", "field", "currentValue"))


def _change_severity(change: Mapping[str, Any]) -> str:
    change_type = change.get("changeType")
    if change_type == "integrity-changed":
        return "high"
    if change_type in {"source-changed", "vcs-revision-changed"}:
        source_type = change.get("sourceType")
        identifier = str(change.get("sourceIdentifier") or "")
        return "high" if source_type in {"url", "local", "vcs"} or identifier.startswith("http:") else "medium"
    if change_type == "direct-dependency-added":
        return "medium"
    return "low"


def _change_explanation(change_type: str) -> str:
    return {
        "direct-dependency-added": "A direct dependency was added since the approved baseline.",
        "direct-dependency-removed": "A direct dependency was removed since the approved baseline.",
        "specification-changed": "A requested dependency specification changed from the approved baseline.",
        "version-changed": "A resolved dependency version changed from the approved baseline.",
        "source-changed": "A dependency source changed from the approved baseline.",
        "vcs-revision-changed": "A VCS dependency selector or resolved revision changed from the approved baseline.",
        "integrity-changed": "Dependency integrity changed while package, version, and source identity remained equivalent.",
    }.get(change_type, "Dependency inputs changed from the approved baseline.")


def _highest_severity(findings: Iterable[Mapping[str, Any]]) -> str:
    return max(
        (str(item.get("severity") or "low") for item in findings),
        key=lambda value: SEVERITY_ORDER.get(value, 3),
        default="none",
    )


def _paths(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_PATHS:
        if value not in (None, []):
            raise BaselineError("Dependency path inventory is invalid or exceeds the baseline limit.")
        return []
    return sorted({_path(item) for item in value})


def _path(value: Any, *, allow_empty: bool = False) -> str:
    text = _canonical_text(value, MAX_STRING, "dependency path").replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    if not text and allow_empty:
        return ""
    if (
        not text
        or _contains_privacy_redaction(text)
        or text.startswith("/")
        or re.match(r"^[A-Za-z]:", text)
    ):
        raise BaselineError("Dependency paths must be project-relative.")
    parts = [part for part in text.split("/") if part not in ("", ".")]
    if ".." in parts or "\x00" in text:
        raise BaselineError("Dependency paths must not escape the project.")
    return "/".join(parts)


def _strings(value: Any, limit: int, length: int) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        if value not in (None, []):
            raise BaselineError("Dependency metadata list is invalid or exceeds the baseline limit.")
        return []
    if any(not isinstance(item, str) for item in value):
        raise BaselineError("Dependency metadata list contains invalid values.")
    normalized = {_canonical_text(item, length, "dependency metadata") for item in value}
    return sorted(item for item in normalized if item)


def _mapping_list(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_ENTRIES or any(not isinstance(item, Mapping) for item in value):
        raise BaselineError("Trusted dependency inventory is invalid.")
    return value


def _safe_spec(value: Any) -> str:
    text = _canonical_text(value, MAX_STRING, "dependency specification")
    if _contains_privacy_redaction(text):
        raise BaselineError("Dependency specification contains redacted identity data.")
    if "?" in text or "#" in text or re.match(r"^[^@\s]+@[^:\s]+:.+", text):
        raise BaselineError("Dependency specification contains unsafe remote-source data.")
    if "://" in text:
        parsed = urlsplit(text)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise BaselineError("Dependency specification contains unsafe URL data.")
    if re.search(r"(?i)(?:token|password|secret|key)=", text):
        raise BaselineError("Dependency specification contains sensitive-looking data.")
    normalized = text.replace("\\", "/")
    if (
        re.match(r"^(?:[A-Za-z]:/|/|\.\.?/)", normalized)
        or re.match(r"^(?:file|link):(?:/+|[A-Za-z]:/)", normalized, re.IGNORECASE)
        or any(part == ".." for part in normalized.split("/"))
    ):
        raise BaselineError("Dependency specification contains an unsafe path.")
    return text


def _source_identifier(value: Any) -> str:
    text = _canonical_text(value, 200, "dependency source identity")
    if _contains_privacy_redaction(text):
        raise BaselineError("Dependency source identity contains redacted data.")
    if "?" in text or "#" in text or "@" in text or "\\" in text:
        raise BaselineError("Dependency source identity contains unsafe data.")
    if re.match(r"^(?:/|[A-Za-z]:)", text):
        raise BaselineError("Dependency source identity contains an absolute path.")
    if re.search(r"(?:^|:)[A-Za-z]:/", text) or text.lower().startswith(("file:/", "link:/")):
        raise BaselineError("Dependency source identity contains an absolute path.")
    return text


def _vcs_revision_identity(value: Any, selectors: set[str], *, multiple: bool = False) -> str:
    text = _canonical_text(value, MAX_STRING, "VCS revision identity")
    if not text:
        return ""
    values = text.split(",") if multiple else [text]
    if not multiple and len(values) != 1:
        raise BaselineError("VCS revision identity is invalid.")
    pattern = re.compile(r"^([a-z]+):sha256:([0-9a-f]{64})$")
    parsed: list[tuple[str, str]] = []
    for item in values:
        match = pattern.fullmatch(item)
        if not match or match.group(1) not in selectors:
            raise BaselineError("VCS revision identity is invalid.")
        parsed.append((match.group(1), match.group(2)))
    if len({selector for selector, _ in parsed}) != len(parsed):
        raise BaselineError("VCS revision identity contains duplicate selectors.")
    return ",".join(f"{selector}:sha256:{digest}" for selector, digest in parsed)


def _text(value: Any, limit: int) -> str:
    if value is None:
        return ""
    return sanitize_private_text(value, limit=limit)


def _canonical_text(value: Any, limit: int, label: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise BaselineError(f"{label.capitalize()} is invalid.")
    text = " ".join(value.split())
    if len(text) > limit:
        raise BaselineError(f"{label.capitalize()} exceeds the trusted baseline limit.")
    return text


def _identity_text(value: Any, limit: int, label: str) -> str:
    text = _canonical_text(value, limit, label)
    if _contains_privacy_redaction(text) or any(
        marker in text for marker in ("://", "?", "#", "\\", "\x00")
    ):
        raise BaselineError(f"{label.capitalize()} contains unsafe identity data.")
    return text


def _contains_privacy_redaction(value: str) -> bool:
    folded = value.casefold()
    return any(marker in folded for marker in _PRIVACY_REDACTION_MARKERS)


def _package_name(ecosystem: str, value: Any) -> str:
    name = _identity_text(value, 300, "package name")
    patterns = {
        "node": r"(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*",
        "python": r"[a-z0-9][a-z0-9-]*",
    }
    pattern = patterns.get(ecosystem)
    if not name or not pattern or not re.fullmatch(pattern, name):
        raise BaselineError("Dependency inventory contains an invalid normalized package identity.")
    return name


def _validate_snapshot_relationships(snapshot: Mapping[str, Any]) -> None:
    ecosystems = set(snapshot.get("ecosystems", []))
    if not ecosystems or not ecosystems.issubset(SUPPORTED_ECOSYSTEMS):
        raise BaselineError("Dependency ecosystem metadata is unsupported or invalid.")
    if any(not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", manager) for manager in snapshot.get("packageManagers", [])):
        raise BaselineError("Dependency package-manager metadata is invalid.")
    manifests = set(snapshot.get("manifests", []))
    lockfiles = set(snapshot.get("lockfiles", []))
    for entry in snapshot.get("entries", []):
        if entry.get("ecosystem") not in ecosystems:
            raise BaselineError("Dependency inventory ecosystem metadata is inconsistent.")
        if entry.get("manifestPath") and entry["manifestPath"] not in manifests:
            raise BaselineError("Dependency inventory references an unknown manifest path.")
        if entry.get("lockfilePath") and entry["lockfilePath"] not in lockfiles:
            raise BaselineError("Dependency inventory references an unknown lockfile path.")


def _valid_integrity(value: Any) -> bool:
    try:
        validate_dependency_integrity(value)
    except ValueError:
        return False
    return True


def _bounded_snapshot(snapshot: Mapping[str, Any]) -> None:
    if len(json.dumps(snapshot, ensure_ascii=True, separators=(",", ":"))) > 2_000_000:
        raise BaselineError("Trusted dependency snapshot exceeds the safe storage limit.")


def _ineligible_reason(analysis: Mapping[str, Any]) -> str:
    status = str(analysis.get("status") or "unavailable")
    return {
        "incomplete": "Dependency analysis is incomplete and cannot be approved as a trusted baseline.",
        "malformed": "Malformed dependency metadata cannot be approved as a trusted baseline.",
        "unsupported": "Unsupported or absent dependency metadata cannot be approved as a trusted baseline.",
    }.get(status, "Dependency analysis is unavailable and cannot be approved as a trusted baseline.")
