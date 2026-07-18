from __future__ import annotations

import os
from pathlib import Path
from typing import Any, NamedTuple

from .dependency_trust import (
    MAX_DEPENDENCY_BYTES,
    analyze_dependencies,
    decode_json_object,
    is_dependency_metadata,
)
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
IGNORE_FILE_NAME = ".glacialignore"
MAX_TEXT_BYTES = 1024 * 1024
# These defaults leave ample room for large source repositories while bounding
# attacker-controlled allocation and traversal work. Generated/vendor trees are
# already excluded by SKIP_DIRS, and dependency analysis retains its own tighter caps.
MAX_IGNORE_BYTES = 256 * 1024
MAX_IGNORE_PATTERNS = 10_000
MAX_SCAN_DIRECTORIES = 50_000
MAX_SCAN_FILES = 100_000
MAX_SCAN_FILESYSTEM_ENTRIES = 150_000
MAX_SCAN_INSPECTED_BYTES = 512 * 1024 * 1024
MAX_SCAN_FINDINGS = 10_000
MAX_SCAN_RESULT_RECORDS = 100_000

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


class _ContentInspection(NamedTuple):
    findings: list[dict[str, Any]]
    lifecycle_scripts: list[dict[str, str]]
    issue: str | None
    inspected_bytes: int
    aggregate_bytes_observed: int | None = None


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
        "policyExcludedFileCount": 0,
        "resourceBudgetExceededCount": 0,
    }
    dependency_inputs: list[tuple[Path, str]] = []
    generic_failed_dependency_paths: set[str] = set()
    reported_linked_paths: set[str] = set()
    failed_inspection_paths: set[str] = set()
    reported_traversal_failures: set[str] = set()
    exceeded_budgets: set[str] = set()
    stop_traversal = False
    work_counts = {
        "directoriesEncountered": 1,
        "filesEncountered": 0,
        "filesystemEntriesEncountered": 0,
        "inspectedBytes": 0,
        "resultRecords": 0,
    }

    def record_resource_budget(
        budget: str,
        limit: int,
        observed: int,
        path: str,
    ) -> None:
        nonlocal stop_traversal
        if budget in exceeded_budgets:
            stop_traversal = True
            return
        exceeded_budgets.add(budget)
        stop_traversal = True
        issue_counts["resourceBudgetExceededCount"] += 1
        findings.append(_resource_budget_finding(budget, limit, observed, path, work_counts))

    def append_finding(finding: dict[str, Any]) -> bool:
        if len(findings) >= MAX_SCAN_FINDINGS:
            record_resource_budget(
                "findings",
                MAX_SCAN_FINDINGS,
                len(findings) + 1,
                str(finding.get("path") or "."),
            )
            return False
        findings.append(finding)
        return True

    def append_result_record(records: list[Any], value: Any, path: str) -> bool:
        observed = work_counts["resultRecords"] + 1
        if observed > MAX_SCAN_RESULT_RECORDS:
            record_resource_budget(
                "result-records",
                MAX_SCAN_RESULT_RECORDS,
                observed,
                path,
            )
            return False
        records.append(value)
        work_counts["resultRecords"] = observed
        return True

    ignore_patterns, ignore_finding, ignore_issue = _load_ignore_patterns(project_path)
    if ignore_finding:
        append_finding(ignore_finding)
        reported_linked_paths.add(ignore_finding["path"])
        issue_counts[ignore_issue] += 1
        if ignore_issue == "resourceBudgetExceededCount":
            exceeded_budgets.add(str(ignore_finding.get("budget") or "ignore-policy"))
        if ignore_issue in {"fileInspectionFailureCount", "resourceBudgetExceededCount"}:
            failed_inspection_paths.add(ignore_finding["path"])

    def record_traversal_error(error: OSError) -> None:
        relative_path = _error_path(error, project_path)
        if relative_path in reported_traversal_failures:
            return
        reported_traversal_failures.add(relative_path)
        append_finding(
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

    if work_counts["directoriesEncountered"] > MAX_SCAN_DIRECTORIES:
        record_resource_budget(
            "directories",
            MAX_SCAN_DIRECTORIES,
            work_counts["directoriesEncountered"],
            ".",
        )

    pending_directories = [project_path]
    while pending_directories and not stop_traversal:
        root_path = pending_directories.pop()
        directory_names: list[str] = []
        file_names: list[str] = []
        try:
            with os.scandir(root_path) as entries:
                for entry in entries:
                    observed_entries = work_counts["filesystemEntriesEncountered"] + 1
                    work_counts["filesystemEntriesEncountered"] = observed_entries
                    if observed_entries > MAX_SCAN_FILESYSTEM_ENTRIES:
                        record_resource_budget(
                            "filesystem-entries",
                            MAX_SCAN_FILESYSTEM_ENTRIES,
                            observed_entries,
                            _relative_path(root_path / entry.name, project_path),
                        )
                        break
                    try:
                        is_directory = entry.is_dir(follow_symlinks=False)
                    except OSError as error:
                        record_traversal_error(error)
                        if stop_traversal:
                            break
                        continue
                    if is_directory:
                        observed = work_counts["directoriesEncountered"] + 1
                        if observed > MAX_SCAN_DIRECTORIES:
                            work_counts["directoriesEncountered"] = observed
                            record_resource_budget(
                                "directories",
                                MAX_SCAN_DIRECTORIES,
                                observed,
                                _relative_path(root_path / entry.name, project_path),
                            )
                            break
                        work_counts["directoriesEncountered"] = observed
                        directory_names.append(entry.name)
                    else:
                        observed = work_counts["filesEncountered"] + 1
                        if observed > MAX_SCAN_FILES:
                            work_counts["filesEncountered"] = observed
                            record_resource_budget(
                                "files",
                                MAX_SCAN_FILES,
                                observed,
                                _relative_path(root_path / entry.name, project_path),
                            )
                            break
                        work_counts["filesEncountered"] = observed
                        file_names.append(entry.name)
        except OSError as error:
            record_traversal_error(error)
            continue

        if stop_traversal:
            break

        safe_dirs: list[str] = []
        for dirname in sorted(directory_names):
            directory_path = root_path / dirname
            relative_path = _relative_path(directory_path, project_path)
            if is_reparse_point_or_symlink(directory_path):
                if relative_path not in reported_linked_paths:
                    if not append_finding(_linked_path_finding(relative_path)):
                        break
                    reported_linked_paths.add(relative_path)
                    issue_counts["unsafePathCount"] += 1
                continue
            if dirname.lower() in SKIP_DIRS:
                continue
            safe_dirs.append(dirname)
        if stop_traversal:
            break
        pending_directories.extend(root_path / dirname for dirname in reversed(safe_dirs))

        for filename in sorted(file_names):
            file_path = root_path / filename
            relative_path = _relative_path(file_path, project_path)

            if is_reparse_point_or_symlink(file_path):
                if relative_path not in reported_linked_paths:
                    if not append_finding(_linked_path_finding(relative_path)):
                        break
                    reported_linked_paths.add(relative_path)
                    issue_counts["unsafePathCount"] += 1
                continue

            unsafe_finding = _unsafe_file_finding(file_path, relative_path)
            if unsafe_finding:
                if relative_path not in reported_linked_paths:
                    if not append_finding(unsafe_finding):
                        break
                    reported_linked_paths.add(relative_path)
                    issue_counts[
                        "unsafePathCount"
                        if unsafe_finding["type"] == "hardlink"
                        else "fileInspectionFailureCount"
                    ] += 1
                continue

            if relative_path in ignore_patterns:
                if not append_result_record(ignored_files, relative_path, relative_path):
                    break
                issue_counts["policyExcludedFileCount"] += 1
                continue
            if relative_path in failed_inspection_paths:
                continue

            lower_name = filename.lower()
            suffix = file_path.suffix.lower()
            is_secret_file = _is_secret_file(lower_name, suffix)
            dependency_metadata = is_dependency_metadata(relative_path)

            if lower_name in MANIFESTS or _is_requirements_manifest(relative_path):
                if not append_result_record(manifests, relative_path, relative_path):
                    break

            if lower_name in LOCKFILES:
                if not append_result_record(lockfiles, relative_path, relative_path):
                    break

            if dependency_metadata:
                dependency_inputs.append((file_path, relative_path))

            if is_secret_file:
                if not append_result_record(secret_files, relative_path, relative_path):
                    break
                if not append_finding(
                    _finding(
                        relative_path,
                        "secret-looking-file",
                        "high",
                        "Secret-looking file found. Review before sharing or running tools.",
                    )
                ):
                    break

            if suffix in EXECUTABLE_EXTENSIONS:
                severity, explanation = EXECUTABLE_EXTENSIONS[suffix]
                if not append_finding(_finding(relative_path, "executable-or-script-file", severity, explanation)):
                    break

            if lower_name in LOCKFILES:
                if not append_finding(
                    _finding(
                        relative_path,
                        "lockfile",
                        "low",
                        "Dependency lockfile found. Review dependency changes before installing.",
                    )
                ):
                    break

            if is_secret_file:
                # Secret-looking files are intentionally classified by name only and
                # are never opened. That classification completes their intended review.
                if not append_result_record(reviewed_files, relative_path, relative_path):
                    break
                continue

            inspection = _inspect_file_content(
                file_path,
                relative_path,
                is_package_json=lower_name == "package.json",
                max_bytes=MAX_DEPENDENCY_BYTES if dependency_metadata else MAX_TEXT_BYTES,
                aggregate_bytes_remaining=MAX_SCAN_INSPECTED_BYTES - work_counts["inspectedBytes"],
            )
            if inspection.aggregate_bytes_observed is not None:
                record_resource_budget(
                    "inspected-bytes",
                    MAX_SCAN_INSPECTED_BYTES,
                    work_counts["inspectedBytes"] + inspection.aggregate_bytes_observed,
                    relative_path,
                )
                break
            work_counts["inspectedBytes"] += inspection.inspected_bytes
            for finding in inspection.findings:
                if not append_finding(finding):
                    break
            if stop_traversal:
                break
            for package_script in inspection.lifecycle_scripts:
                if not append_result_record(lifecycle_scripts, package_script, relative_path):
                    break
            if stop_traversal:
                break
            if inspection.issue:
                issue_counts[inspection.issue] += 1
                if dependency_metadata:
                    generic_failed_dependency_paths.add(relative_path)
            else:
                if not append_result_record(reviewed_files, relative_path, relative_path):
                    break

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
    for dependency_finding in dependency_findings:
        if not append_finding(dependency_finding):
            break
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
    aggregate_bytes_remaining: int = MAX_SCAN_INSPECTED_BYTES,
) -> _ContentInspection:
    try:
        file_size = file_path.stat().st_size
    except OSError as error:
        return _ContentInspection([_inspection_finding(
            relative_path,
            "filesystem-entry-inspection-error",
            "medium",
            "File metadata could not be inspected, so this file was not reviewed.",
            "Review filesystem permissions and inspect this file manually before trusting the scan.",
            operation="inspect-file-metadata",
            error=_sanitized_error(error),
        )], [], "fileInspectionFailureCount", 0)

    if file_size > max_bytes:
        return _ContentInspection([_inspection_finding(
            relative_path,
            "oversized-file-skipped",
            "low",
            "File content was not inspected because it exceeds the configured content-inspection size limit.",
            "Review this file manually or reduce its size before relying on scan coverage.",
            fileSizeBytes=file_size,
            sizeLimitBytes=max_bytes,
            reason="content-size-limit",
        )], [], "oversizedFileCount", 0)

    if file_size > aggregate_bytes_remaining:
        return _ContentInspection([], [], None, 0, file_size)

    try:
        with file_path.open("rb") as file_handle:
            content = file_handle.read(min(max_bytes + 1, aggregate_bytes_remaining + 1))
    except OSError as error:
        return _ContentInspection([_inspection_finding(
            relative_path,
            "filesystem-entry-inspection-error",
            "medium",
            "File content could not be read, so this file was not reviewed.",
            "Review filesystem permissions and inspect this file manually before trusting the scan.",
            operation="read-file-content",
            error=_sanitized_error(error),
        )], [], "fileInspectionFailureCount", 0)

    if len(content) > aggregate_bytes_remaining:
        return _ContentInspection([], [], None, 0, len(content))

    if len(content) > max_bytes:
        return _ContentInspection([_inspection_finding(
            relative_path,
            "oversized-file-skipped",
            "low",
            "File content was not inspected because it exceeds the configured content-inspection size limit.",
            "Review this file manually or reduce its size before relying on scan coverage.",
            fileSizeBytes=max(file_size, len(content)),
            sizeLimitBytes=max_bytes,
            reason="content-size-limit",
        )], [], "oversizedFileCount", len(content))

    text = content.decode("utf-8", errors="ignore")
    findings: list[dict[str, Any]] = _scan_text_patterns(text, relative_path)
    lifecycle_scripts: list[dict[str, str]] = []
    if not is_package_json:
        return _ContentInspection(findings, lifecycle_scripts, None, len(content))

    data, parse_issue = decode_json_object(content)
    if parse_issue is not None:
        findings.append(_inspection_finding(
            relative_path,
            "package-json-read-error",
            "medium",
            "package.json could not be safely parsed as a JSON object, so its lifecycle scripts were not inspected.",
            "Correct or regenerate package.json and rescan before installing dependencies.",
            operation="parse-package-json",
            reason=parse_issue,
        ))
        return _ContentInspection(
            findings,
            lifecycle_scripts,
            "fileInspectionFailureCount",
            len(content),
        )

    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return _ContentInspection(findings, lifecycle_scripts, None, len(content))
    for script_name in sorted(LIFECYCLE_SCRIPTS.intersection(scripts.keys())):
        lifecycle_scripts.append({"path": relative_path, "script": script_name})
        findings.append(_finding(
            relative_path,
            "package-lifecycle-script",
            "high",
            f"package.json defines a '{script_name}' lifecycle script. Review it before installing dependencies.",
            script=script_name,
        ))
    return _ContentInspection(findings, lifecycle_scripts, None, len(content))


def _scan_text_patterns(text: str, relative_path: str) -> list[dict[str, Any]]:
    lower_text = text.lower()
    findings = []
    for pattern, (severity, explanation) in PATTERNS.items():
        needle = pattern.lower()
        if needle in lower_text:
            findings.append(_finding(
                relative_path,
                "suspicious-text-pattern",
                severity,
                f"{explanation} Pattern: {pattern}",
                pattern=pattern,
            ))
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
        file_size = ignore_path.stat().st_size
        if file_size > MAX_IGNORE_BYTES:
            return set(), _resource_budget_finding(
                "ignore-bytes",
                MAX_IGNORE_BYTES,
                file_size,
                IGNORE_FILE_NAME,
            ), "resourceBudgetExceededCount"
        with ignore_path.open("rb") as ignore_file:
            content = ignore_file.read(MAX_IGNORE_BYTES + 1)
    except FileNotFoundError:
        return set(), None, "fileInspectionFailureCount"
    except OSError as error:
        return set(), _inspection_finding(
            IGNORE_FILE_NAME,
            "filesystem-entry-inspection-error",
            "medium",
            ".glacialignore could not be read, so its ignore rules were not applied.",
            "Review the ignore file and filesystem permissions before trusting scan coverage.",
            operation="read-ignore-file",
            error=_sanitized_error(error),
        ), "fileInspectionFailureCount"

    if len(content) > MAX_IGNORE_BYTES:
        return set(), _resource_budget_finding(
            "ignore-bytes",
            MAX_IGNORE_BYTES,
            len(content),
            IGNORE_FILE_NAME,
        ), "resourceBudgetExceededCount"
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return set(), _inspection_finding(
            IGNORE_FILE_NAME,
            "ignore-policy-read-error",
            "medium",
            ".glacialignore is not valid UTF-8, so its ignore rules were not applied.",
            "Correct or remove the ignore policy and rescan before trusting scan coverage.",
            operation="parse-ignore-policy",
            reason="invalid-utf8",
        ), "fileInspectionFailureCount"

    patterns = set()
    for line in lines:
        pattern = line.strip()
        if not pattern or pattern.startswith("#"):
            continue
        normalized = pattern.replace("\\", "/")
        if normalized in patterns:
            continue
        if len(patterns) >= MAX_IGNORE_PATTERNS:
            return set(), _resource_budget_finding(
                "ignore-patterns",
                MAX_IGNORE_PATTERNS,
                len(patterns) + 1,
                IGNORE_FILE_NAME,
            ), "resourceBudgetExceededCount"
        patterns.add(normalized)
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


def _resource_budget_finding(
    budget: str,
    limit: int,
    observed: int,
    path: str,
    observed_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "budget": budget,
        "limit": limit,
        "observed": observed,
        "reason": "scan-resource-budget-exceeded",
    }
    if observed_counts:
        metadata["observedCounts"] = dict(observed_counts)
    return _inspection_finding(
        path,
        "scan-resource-budget-exceeded",
        "medium",
        f"Scanner resource budget '{budget}' was exceeded (limit {limit}, observed {observed}), so additional repository coverage was stopped or rejected.",
        "Review the retained evidence and reduce or manually inspect the unscanned repository content before rescanning.",
        operation="enforce-scan-resource-budget",
        **metadata,
    )


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
