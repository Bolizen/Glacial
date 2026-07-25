from __future__ import annotations

import math
import re
from pathlib import PurePosixPath
from typing import Any, Iterable

from .finding_evidence import normalize_suspicious_text_evidence


FINDING_EXPLAINABILITY_SCHEMA_VERSION = 1
FINDING_RULE_VERSION = 1
MAX_EXPLANATION_TEXT = 500
MAX_EVIDENCE_PATH = 500
MAX_EVIDENCE_LOCATION = 200
MAX_EVIDENCE_DETAILS = 20
MAX_EVIDENCE_VALUE = 300

_RULE_TYPE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_EVIDENCE_FIELDS = (
    "pattern",
    "script",
    "operation",
    "error",
    "reason",
    "budget",
    "limit",
    "observed",
    "observedCounts",
    "fileSizeBytes",
    "sizeLimitBytes",
    "ecosystem",
    "package",
    "dependencyGroup",
    "requestedSpecification",
    "resolvedVersion",
    "sourceType",
    "sourceIdentifier",
    "metadata",
)


def explain_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    explained: list[dict[str, Any]] = []
    for finding in findings:
        item = dict(finding)
        item["explainability"] = build_finding_explainability(item)
        explained.append(item)
    return explained


def build_finding_explainability(finding: dict[str, Any]) -> dict[str, Any]:
    finding_type = _finding_type(finding)
    severity = _severity(finding.get("severity"))
    category = _category(finding_type)
    observation = _text(
        finding.get("explanation") or "The scanner recorded this finding.",
        MAX_EXPLANATION_TEXT,
    )
    manual_check = _text(
        finding.get("action") or _manual_check(finding_type),
        MAX_EXPLANATION_TEXT,
    )
    return {
        "schemaVersion": FINDING_EXPLAINABILITY_SCHEMA_VERSION,
        "rule": {
            "id": f"scanner.{finding_type}",
            "name": _rule_name(finding_type),
            "version": FINDING_RULE_VERSION,
        },
        "category": category,
        "evidence": _evidence(finding, finding_type),
        "observation": observation,
        "impact": _impact(finding_type, category),
        "severityReason": _severity_reason(severity, finding_type, category),
        "manualCheck": manual_check,
        "limitations": _limitations(category),
    }


def normalize_finding_explainability(
    value: Any,
    *,
    finding: dict[str, Any],
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    finding_path = finding.get("path") or finding.get("file_path") or ""
    if finding_path and not _path(finding_path):
        return None
    expected = build_finding_explainability(finding)
    if value != expected:
        return None
    return expected


def _evidence(finding: dict[str, Any], finding_type: str) -> dict[str, Any]:
    path = _path(finding.get("path") or finding.get("file_path"))
    evidence: dict[str, Any] = {
        "kind": _evidence_kind(finding_type),
        "path": path,
        "location": _evidence_location(finding, finding_type),
    }
    details: dict[str, Any] = {}
    for field in _EVIDENCE_FIELDS:
        bounded = _bounded_value(finding.get(field))
        if bounded not in (None, "", [], {}):
            details[field] = bounded
    suspicious = normalize_suspicious_text_evidence(finding.get("evidence"))
    if finding_type == "suspicious-text-pattern" and suspicious:
        evidence["location"] = f"line {suspicious['line']}"
        evidence["excerpt"] = suspicious["excerpt"]
        details.update({
            "pattern": suspicious["pattern"],
            "matchCount": suspicious["matchCount"],
            "additionalMatchesOmitted": suspicious["additionalMatchesOmitted"],
        })
    if details:
        evidence["details"] = dict(sorted(details.items())[:MAX_EVIDENCE_DETAILS])
    return evidence


def _finding_type(finding: dict[str, Any]) -> str:
    value = _text(finding.get("type") or finding.get("finding_type") or "unknown", 120).lower()
    return value if _RULE_TYPE.fullmatch(value) else "unknown"


def _rule_name(finding_type: str) -> str:
    return " ".join(part.capitalize() for part in finding_type.split("-"))


def _category(finding_type: str) -> str:
    if finding_type.startswith("dependency-"):
        return "dependency"
    if finding_type in {"package-lifecycle-script", "executable-or-script-file", "suspicious-text-pattern"}:
        return "code execution"
    if finding_type == "secret-looking-file":
        return "sensitive file"
    if finding_type in {"symlink-or-reparse-point", "hardlink"}:
        return "filesystem boundary"
    if finding_type in {
        "directory-traversal-error",
        "filesystem-entry-inspection-error",
        "oversized-file-skipped",
        "ignore-policy-read-error",
        "scan-resource-budget-exceeded",
    }:
        return "scan coverage"
    return "project metadata"


def _evidence_kind(finding_type: str) -> str:
    if finding_type == "suspicious-text-pattern":
        return "text-match"
    if finding_type == "package-lifecycle-script":
        return "manifest-field"
    if finding_type.startswith("dependency-"):
        return "dependency-metadata"
    if finding_type in {"symlink-or-reparse-point", "hardlink"}:
        return "filesystem-identity"
    if finding_type in {
        "directory-traversal-error",
        "filesystem-entry-inspection-error",
        "oversized-file-skipped",
        "ignore-policy-read-error",
        "scan-resource-budget-exceeded",
    }:
        return "coverage-limitation"
    return "path-classification"


def _evidence_location(finding: dict[str, Any], finding_type: str) -> str:
    if finding_type == "package-lifecycle-script" and finding.get("script"):
        return _text(f"scripts.{finding['script']}", MAX_EVIDENCE_LOCATION)
    if finding.get("operation"):
        return _text(finding["operation"], MAX_EVIDENCE_LOCATION)
    if finding.get("package"):
        return _text(finding["package"], MAX_EVIDENCE_LOCATION)
    path = _path(finding.get("path") or finding.get("file_path"))
    return PurePosixPath(path).name if path else "project scan"


def _impact(finding_type: str, category: str) -> str:
    if finding_type == "secret-looking-file":
        return "Conventional secret-bearing file names can contain credentials or private material that should not be exposed."
    if finding_type == "package-lifecycle-script":
        return "Package lifecycle scripts may execute implicitly during dependency installation or packaging."
    if finding_type == "suspicious-text-pattern":
        return "The matched construct can fetch content, launch processes, decode data, or evaluate code depending on its surrounding logic."
    if finding_type == "executable-or-script-file":
        return "Executable files and scripts can run commands or load code on the local machine."
    if category == "filesystem boundary":
        return "Unsafe filesystem identity can cross the selected project boundary or make inspected content differ from the referenced content."
    if category == "scan coverage":
        return "Missing inspection evidence prevents Glacial from making a complete claim about the affected path or remaining project content."
    if "integrity" in finding_type:
        return "Missing, malformed, or changed integrity evidence weakens confidence that resolved dependency bytes match the expected artifact."
    if "source" in finding_type or finding_type in {"dependency-vcs-source", "dependency-local-source"}:
        return "Non-default or changed dependency sources alter where installable code is obtained and what identity can be verified offline."
    if category == "dependency":
        return "Dependency metadata controls which third-party code may be selected or installed and whether the resolved inventory is reproducible."
    if finding_type == "lockfile":
        return "Lockfiles select concrete dependency versions and can carry meaningful supply-chain changes."
    return "This persisted scanner observation may affect how safely the project can be reviewed before running tools or code."


def _severity_reason(severity: str, finding_type: str, category: str) -> str:
    if severity == "high":
        if category == "scan coverage" or finding_type.endswith("parse-error"):
            return "High severity is assigned because critical inspection evidence is unavailable and the scanner must fail closed."
        return "High severity is assigned because the observation can involve execution, sensitive material, unsafe boundaries, or unverifiable artifact identity before use."
    if severity == "medium":
        return "Medium severity is assigned because the observation creates meaningful uncertainty, non-default behavior, or incomplete evidence requiring manual review."
    if severity == "low":
        return "Low severity is assigned because the observation is review context or drift without direct evidence of harmful behavior."
    return "The persisted severity is unrecognized, so this explanation does not treat it as reassuring."


def _manual_check(finding_type: str) -> str:
    return {
        "secret-looking-file": "Confirm the file is intentionally present and does not contain material that could be exposed by sharing or tooling.",
        "package-lifecycle-script": "Inspect the exact lifecycle field and every command it can invoke before installing dependencies.",
        "executable-or-script-file": "Inspect the file provenance and commands before executing or loading it.",
        "suspicious-text-pattern": "Inspect the bounded match in its full source context and trace any inputs, commands, or data it reaches.",
        "lockfile": "Review the lockfile diff and expected dependency versions before installation.",
        "symlink-or-reparse-point": "Inspect the link target without allowing Glacial to follow it outside the selected project.",
        "hardlink": "Inspect every known path referencing the same file identity before trusting its contents.",
    }.get(
        finding_type,
        "Inspect the recorded path and bounded evidence manually before running, installing, sharing, or trusting the affected project content.",
    )


def _limitations(category: str) -> str:
    if category == "sensitive file":
        return "Glacial classified the path by name and did not open the file; it does not know whether secrets are present."
    if category == "dependency":
        return "Glacial used local metadata only; it did not install packages, contact registries, inspect installed code, or determine package reputation or intent."
    if category == "filesystem boundary":
        return "Glacial did not follow the unsafe filesystem entry and cannot determine the target content or intent."
    if category == "scan coverage":
        return "The scan is incomplete for the recorded reason; Glacial does not know what uninspected content contains."
    return "Glacial did not execute project code and cannot determine intent or runtime behavior; this is scanner evidence, not proof of vulnerability or malicious behavior."


def _severity(value: Any) -> str:
    severity = _text(value or "high", 20).lower()
    return severity if severity in {"none", "low", "medium", "high"} else "unknown"


def _path(value: Any) -> str:
    path = str(value or "").replace("\\", "/")[:MAX_EVIDENCE_PATH]
    while path.startswith("./"):
        path = path[2:]
    if path.startswith("/") or re.match(r"^[A-Za-z]:", path) or ".." in path.split("/") or "\x00" in path:
        return ""
    return "/".join(part for part in path.split("/") if part not in ("", "."))


def _text(value: Any, limit: int) -> str:
    clean = "".join(
        character if ord(character) >= 32 else " "
        for character in str(value or "")
    )
    return " ".join(clean.split())[:limit]


def _bounded_value(value: Any, depth: int = 0) -> Any:
    if value is None or depth > 2:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return _text(value, MAX_EVIDENCE_VALUE)
    if isinstance(value, list):
        return [
            item
            for item in (_bounded_value(raw, depth + 1) for raw in value[:10])
            if item not in (None, "", [], {})
        ]
    if isinstance(value, dict):
        result = {
            str(key)[:80]: _bounded_value(item, depth + 1)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))[:12]
        }
        return {key: item for key, item in result.items() if item not in (None, "", [], {})}
    return None
