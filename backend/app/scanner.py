from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .dependency_trust import MAX_DEPENDENCY_BYTES, analyze_dependencies, is_dependency_metadata
from .safety import has_multiple_hardlinks, is_reparse_point_or_symlink


RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}
MANIFESTS = {"package.json", "requirements.txt", "pyproject.toml", "pipfile"}
LIFECYCLE_SCRIPTS = {
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepack",
    "postpack",
    "prepublish",
}
LOCKFILES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "uv.lock",
    "requirements.lock.txt",
    "pipfile.lock",
}
SECRET_FILE_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_ed25519",
}
SECRET_FILE_SUFFIXES = {".pem", ".key"}
EXECUTABLE_EXTENSIONS = {
    ".bat": ("medium", "Batch script found. Review before running because it can execute commands on Windows."),
    ".cmd": ("medium", "Command script found. Review before running because it can execute commands on Windows."),
    ".ps1": ("high", "PowerShell script found. Review carefully before running."),
    ".sh": ("medium", "Shell script found. Review before running in a Unix-like shell."),
    ".exe": ("high", "Windows executable found. Do not run it unless you trust its origin."),
    ".dll": ("high", "Windows library file found. Review its origin before loading or executing related software."),
}
SKIP_DIRS = {".git", "node_modules", "dist", "build", ".venv", "venv", "__pycache__"}
IGNORE_FILE_NAME = ".codexforgeignore"
MAX_TEXT_BYTES = 1024 * 1024

PATTERNS = {
    "Invoke-Expression": ("high", "PowerShell dynamic execution pattern found."),
    "iex": ("high", "PowerShell shorthand for Invoke-Expression found."),
    "curl": ("medium", "Network download command reference found."),
    "wget": ("medium", "Network download command reference found."),
    "Start-Process": ("high", "PowerShell process launch pattern found."),
    "encodedcommand": ("high", "Encoded PowerShell command pattern found."),
    "fromBase64String": ("high", "Base64 decoding pattern found."),
    "child_process": ("high", "Node.js process execution API reference found."),
    "eval(": ("high", "Dynamic code evaluation pattern found."),
}


def scan_project(project_path: Path, previous_dependency_trust: dict[str, Any] | None = None) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    manifests: list[str] = []
    lockfiles: list[str] = []
    lifecycle_scripts: list[dict[str, str]] = []
    secret_files: list[str] = []
    ignored_files: list[str] = []
    reviewed_files: list[str] = []
    issue_counts = {
        "traversalFailureCount": 0,
        "fileInspectionFailureCount": 0,
        "oversizedFileCount": 0,
        "unsafePathCount": 0,
        "dependencyAnalysisFailureCount": 0,
    }
    dependency_inputs: list[tuple[Path, str]] = []
    generic_failed_dependency_paths: set[str] = set()
    ignore_patterns, ignore_finding, ignore_issue = _load_ignore_patterns(project_path)
    reported_linked_paths: set[str] = set()
    failed_inspection_paths: set[str] = set()
    reported_traversal_failures: set[str] = set()
    if ignore_finding:
        findings.append(ignore_finding)
        reported_linked_paths.add(ignore_finding["path"])
        issue_counts[ignore_issue] += 1
        if ignore_issue == "fileInspectionFailureCount":
            failed_inspection_paths.add(ignore_finding["path"])

    def record_traversal_error(error: OSError) -> None:
        relative_path = _error_path(error, project_path)
        if relative_path in reported_traversal_failures:
            return
        reported_traversal_failures.add(relative_path)
        findings.append(
            _inspection_finding(
                relative_path,
                "directory-traversal-error",
                "medium",
                "Directory contents could not be enumerated, so this part of the project was not inspected.",
                "Review filesystem permissions and inspect this directory manually before trusting the scan.",
                operation="traverse-directory",
                error=_sanitized_error(error),
            )
        )
        issue_counts["traversalFailureCount"] += 1

    for current_root, dirs, files in os.walk(project_path, followlinks=False, onerror=record_traversal_error):
        root_path = Path(current_root)
        safe_dirs = []
        for dirname in dirs:
            directory_path = root_path / dirname
            relative_path = _relative_path(directory_path, project_path)
            if is_reparse_point_or_symlink(directory_path):
                if relative_path not in reported_linked_paths:
                    findings.append(_linked_path_finding(relative_path))
                    reported_linked_paths.add(relative_path)
                    issue_counts["unsafePathCount"] += 1
                continue
            if dirname.lower() in SKIP_DIRS:
                continue
            safe_dirs.append(dirname)
        dirs[:] = safe_dirs

        for filename in sorted(files):
            file_path = root_path / filename
            relative_path = _relative_path(file_path, project_path)

            if is_reparse_point_or_symlink(file_path):
                if relative_path not in reported_linked_paths:
                    findings.append(_linked_path_finding(relative_path))
                    reported_linked_paths.add(relative_path)
                    issue_counts["unsafePathCount"] += 1
                continue

            unsafe_finding = _unsafe_file_finding(file_path, relative_path)
            if unsafe_finding:
                if relative_path not in reported_linked_paths:
                    findings.append(unsafe_finding)
                    reported_linked_paths.add(relative_path)
                    issue_counts[
                        "unsafePathCount"
                        if unsafe_finding["type"] == "hardlink"
                        else "fileInspectionFailureCount"
                    ] += 1
                continue

            if relative_path in ignore_patterns:
                ignored_files.append(relative_path)
                continue
            if relative_path in failed_inspection_paths:
                continue

            lower_name = filename.lower()
            suffix = file_path.suffix.lower()
            is_secret_file = _is_secret_file(lower_name, suffix)
            dependency_metadata = is_dependency_metadata(relative_path)

            if lower_name in MANIFESTS or _is_requirements_manifest(relative_path):
                manifests.append(relative_path)

            if lower_name in LOCKFILES:
                lockfiles.append(relative_path)

            if dependency_metadata:
                dependency_inputs.append((file_path, relative_path))

            if is_secret_file:
                secret_files.append(relative_path)
                findings.append(
                    _finding(
                        relative_path,
                        "secret-looking-file",
                        "high",
                        "Secret-looking file found. Review before sharing or running tools.",
                    )
                )

            if suffix in EXECUTABLE_EXTENSIONS:
                severity, explanation = EXECUTABLE_EXTENSIONS[suffix]
                findings.append(_finding(relative_path, "executable-or-script-file", severity, explanation))

            if lower_name in LOCKFILES:
                findings.append(
                    _finding(
                        relative_path,
                        "lockfile",
                        "low",
                        "Dependency lockfile found. Review dependency changes before installing.",
                    )
                )

            if is_secret_file:
                # Secret-looking files are intentionally classified by name only and
                # are never opened. That classification completes their intended review.
                reviewed_files.append(relative_path)
                continue

            content_findings, package_scripts, issue = _inspect_file_content(
                file_path,
                relative_path,
                is_package_json=lower_name == "package.json",
                max_bytes=MAX_DEPENDENCY_BYTES if dependency_metadata else MAX_TEXT_BYTES,
            )
            findings.extend(content_findings)
            lifecycle_scripts.extend(package_scripts)
            if issue:
                issue_counts[issue] += 1
                if dependency_metadata:
                    generic_failed_dependency_paths.add(relative_path)
            else:
                reviewed_files.append(relative_path)

    dependency_trust = analyze_dependencies(
        project_path,
        dependency_inputs,
        previous=previous_dependency_trust,
    )
    dependency_findings = dependency_trust.pop("findings", [])
    dependency_parse_paths = {
        finding.get("path", "")
        for finding in dependency_findings
        if finding.get("type") == "dependency-manifest-parse-error"
    }
    findings = [
        finding for finding in findings
        if not (finding.get("type") == "package-json-read-error" and finding.get("path") in dependency_parse_paths)
    ]
    findings.extend(dependency_findings)
    dependency_input_paths = {relative for _, relative in dependency_inputs}
    dependency_analyzed_paths = set(dependency_trust.get("analyzedFiles", []))
    dependency_failed_paths = (
        set(dependency_trust.get("failedFiles", []))
        | (dependency_input_paths - dependency_analyzed_paths)
    )
    reviewed_files = [path for path in reviewed_files if path not in dependency_failed_paths]
    dependency_gap_count = max(0, int(dependency_trust.get("completenessGapCount", 0)))
    already_counted = len(dependency_failed_paths.intersection(generic_failed_dependency_paths))
    issue_counts["dependencyAnalysisFailureCount"] = max(0, dependency_gap_count - already_counted)

    issue_count = sum(issue_counts.values())

    return {
        "overall_risk": _overall_risk(findings, manifests, lockfiles, lifecycle_scripts, secret_files),
        "findings": findings,
        "manifests": sorted(manifests),
        "lockfiles": sorted(lockfiles),
        "lifecycleScripts": sorted(lifecycle_scripts, key=lambda script: (script["path"], script["script"])),
        "secretFiles": sorted(secret_files),
        "ignoredFiles": sorted(ignored_files),
        "reviewedFiles": sorted(reviewed_files),
        "reviewedFileCount": len(reviewed_files),
        "zone": _infer_zone(project_path),
        "dependencyTrust": dependency_trust,
        "scanCompleteness": {
            "complete": issue_count == 0,
            **issue_counts,
            "issueCount": issue_count,
        },
    }


def _inspect_file_content(
    file_path: Path,
    relative_path: str,
    *,
    is_package_json: bool,
    max_bytes: int = MAX_TEXT_BYTES,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], str | None]:
    try:
        file_size = file_path.stat().st_size
    except OSError as error:
        return [_inspection_finding(
            relative_path,
            "filesystem-entry-inspection-error",
            "medium",
            "File metadata could not be inspected, so this file was not reviewed.",
            "Review filesystem permissions and inspect this file manually before trusting the scan.",
            operation="inspect-file-metadata",
            error=_sanitized_error(error),
        )], [], "fileInspectionFailureCount"

    if file_size > max_bytes:
        return [_inspection_finding(
            relative_path,
            "oversized-file-skipped",
            "low",
            "File content was not inspected because it exceeds the configured content-inspection size limit.",
            "Review this file manually or reduce its size before relying on scan coverage.",
            fileSizeBytes=file_size,
            sizeLimitBytes=max_bytes,
            reason="content-size-limit",
        )], [], "oversizedFileCount"

    try:
        with file_path.open("rb") as file_handle:
            content = file_handle.read(max_bytes + 1)
    except OSError as error:
        return [_inspection_finding(
            relative_path,
            "filesystem-entry-inspection-error",
            "medium",
            "File content could not be read, so this file was not reviewed.",
            "Review filesystem permissions and inspect this file manually before trusting the scan.",
            operation="read-file-content",
            error=_sanitized_error(error),
        )], [], "fileInspectionFailureCount"

    if len(content) > max_bytes:
        return [_inspection_finding(
            relative_path,
            "oversized-file-skipped",
            "low",
            "File content was not inspected because it exceeds the configured content-inspection size limit.",
            "Review this file manually or reduce its size before relying on scan coverage.",
            fileSizeBytes=max(file_size, len(content)),
            sizeLimitBytes=max_bytes,
            reason="content-size-limit",
        )], [], "oversizedFileCount"

    text = content.decode("utf-8", errors="ignore")
    findings: list[dict[str, Any]] = _scan_text_patterns(text, relative_path)
    lifecycle_scripts: list[dict[str, str]] = []
    if not is_package_json:
        return findings, lifecycle_scripts, None

    try:
        data = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        findings.append(_finding(
            relative_path,
            "package-json-read-error",
            "medium",
            "package.json could not be parsed. Review it manually before installing dependencies.",
        ))
        return findings, lifecycle_scripts, None

    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return findings, lifecycle_scripts, None
    for script_name in sorted(LIFECYCLE_SCRIPTS.intersection(scripts.keys())):
        lifecycle_scripts.append({"path": relative_path, "script": script_name})
        findings.append(_finding(
            relative_path,
            "package-lifecycle-script",
            "high",
            f"package.json defines a '{script_name}' lifecycle script. Review it before installing dependencies.",
        ))
    return findings, lifecycle_scripts, None


def _scan_text_patterns(text: str, relative_path: str) -> list[dict[str, Any]]:
    lower_text = text.lower()
    findings = []
    for pattern, (severity, explanation) in PATTERNS.items():
        needle = pattern.lower()
        if needle in lower_text:
            findings.append(_finding(relative_path, "suspicious-text-pattern", severity, f"{explanation} Pattern: {pattern}"))
    return findings


def _load_ignore_patterns(
    project_path: Path,
) -> tuple[set[str], dict[str, Any] | None, str]:
    ignore_path = project_path / IGNORE_FILE_NAME
    if is_reparse_point_or_symlink(ignore_path):
        return set(), _linked_path_finding(IGNORE_FILE_NAME), "unsafePathCount"

    unsafe_finding = _unsafe_file_finding(ignore_path, IGNORE_FILE_NAME)
    if unsafe_finding:
        issue = "unsafePathCount" if unsafe_finding["type"] == "hardlink" else "fileInspectionFailureCount"
        return set(), unsafe_finding, issue

    try:
        lines = ignore_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return set(), None, "fileInspectionFailureCount"
    except OSError as error:
        return set(), _inspection_finding(
            IGNORE_FILE_NAME,
            "filesystem-entry-inspection-error",
            "medium",
            ".codexforgeignore could not be read, so its ignore rules were not applied.",
            "Review the ignore file and filesystem permissions before trusting scan coverage.",
            operation="read-ignore-file",
            error=_sanitized_error(error),
        ), "fileInspectionFailureCount"

    patterns = set()
    for line in lines:
        pattern = line.strip()
        if not pattern or pattern.startswith("#"):
            continue
        patterns.add(pattern.replace("\\", "/"))
    return patterns, None, "fileInspectionFailureCount"


def _relative_path(file_path: Path, project_path: Path) -> str:
    return file_path.relative_to(project_path).as_posix()


def _finding(path: str, finding_type: str, severity: str, explanation: str, **metadata: Any) -> dict[str, Any]:
    return {
        "path": path,
        "type": finding_type,
        "severity": severity,
        "explanation": explanation,
        **metadata,
    }


def _inspection_finding(
    path: str,
    finding_type: str,
    severity: str,
    explanation: str,
    action: str,
    **metadata: Any,
) -> dict[str, Any]:
    return _finding(path, finding_type, severity, explanation, action=action, **metadata)


def _linked_path_finding(path: str) -> dict[str, str]:
    return _finding(
        path,
        "symlink-or-reparse-point",
        "high",
        "Linked filesystem entry was not scanned because it may lead outside the selected project.",
    )


def _unsafe_file_finding(
    file_path: Path,
    relative_path: str,
) -> dict[str, str] | None:
    try:
        if has_multiple_hardlinks(file_path):
            return _finding(
                relative_path,
                "hardlink",
                "high",
                "Hardlinked file was not scanned because another path may reference the same content.",
            )
    except OSError as error:
        return _inspection_finding(
            relative_path,
            "filesystem-entry-inspection-error",
            "high",
            "Filesystem entry was not scanned because its link status could not be inspected safely.",
            "Inspect the file and its link status manually before trusting the scan.",
            operation="inspect-link-status",
            error=_sanitized_error(error),
        )

    return None


def _error_path(error: OSError, project_path: Path) -> str:
    filename = getattr(error, "filename", None)
    if not filename:
        return "."
    try:
        candidate = Path(filename)
        if not candidate.is_absolute():
            return candidate.as_posix()
        return candidate.relative_to(project_path).as_posix()
    except (TypeError, ValueError):
        return Path(str(filename)).name or "."


def _sanitized_error(error: OSError) -> str:
    error_number = getattr(error, "errno", None)
    description = os.strerror(error_number) if isinstance(error_number, int) else "Filesystem operation failed."
    return " ".join(description.split())[:200]

def _overall_risk(
    findings: list[dict[str, str]],
    manifests: list[str],
    lockfiles: list[str],
    lifecycle_scripts: list[dict[str, str]],
    secret_files: list[str],
) -> str:
    if secret_files or lifecycle_scripts or _has_severity(findings, "high"):
        return "high"
    if manifests and not lockfiles:
        return "medium"
    if _has_severity(findings, "medium"):
        return "medium"
    if lockfiles:
        return "low"
    if not findings and not manifests and not lockfiles:
        return "none"

    highest = max((RISK_ORDER.get(finding["severity"], 0) for finding in findings), default=0)
    for name, value in RISK_ORDER.items():
        if value == highest:
            return name
    return "none"


def _has_severity(findings: list[dict[str, str]], severity: str) -> bool:
    return any(finding["severity"] == severity for finding in findings)


def _is_secret_file(lower_name: str, suffix: str) -> bool:
    return lower_name in SECRET_FILE_NAMES or suffix in SECRET_FILE_SUFFIXES


def _is_requirements_manifest(relative_path: str) -> bool:
    path = Path(relative_path)
    lower_name = path.name.lower()
    lower_parts = [part.lower() for part in path.parts]
    return (
        lower_name == "requirements.txt"
        or (lower_name.startswith("requirements-") and lower_name.endswith(".txt"))
        or ("requirements" in lower_parts[:-1] and lower_name.endswith(".txt"))
    )


def _infer_zone(project_path: Path) -> str:
    zones = {"trusted": "Trusted", "untrusted": "Untrusted", "quarantine": "Quarantine"}
    for part in project_path.parts:
        zone = zones.get(part.lower())
        if zone:
            return zone
    return "Unknown"
