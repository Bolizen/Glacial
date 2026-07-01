from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}
MANIFESTS = {"package.json", "requirements.txt", "pyproject.toml"}
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
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "uv.lock",
    "requirements.lock.txt",
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


def scan_project(project_path: Path) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    manifests: list[str] = []
    lockfiles: list[str] = []
    lifecycle_scripts: list[dict[str, str]] = []
    secret_files: list[str] = []
    ignored_files: list[str] = []
    reviewed_files: list[str] = []
    ignore_patterns = _load_ignore_patterns(project_path)

    for current_root, dirs, files in os.walk(project_path):
        dirs[:] = [
            name
            for name in dirs
            if name.lower() not in SKIP_DIRS and not _is_reparse_point_or_symlink(Path(current_root) / name)
        ]
        root_path = Path(current_root)

        for filename in files:
            file_path = root_path / filename
            relative_path = _relative_path(file_path, project_path)
            if relative_path in ignore_patterns:
                ignored_files.append(relative_path)
                continue

            reviewed_files.append(relative_path)
            lower_name = filename.lower()
            suffix = file_path.suffix.lower()
            is_secret_file = _is_secret_file(lower_name, suffix)

            if lower_name in MANIFESTS:
                manifests.append(relative_path)

            if lower_name in LOCKFILES:
                lockfiles.append(relative_path)

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

            if lower_name == "package.json":
                package_findings, package_lifecycle_scripts = _scan_package_json(file_path, relative_path)
                findings.extend(package_findings)
                lifecycle_scripts.extend(package_lifecycle_scripts)

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

            if not is_secret_file:
                findings.extend(_scan_text_patterns(file_path, relative_path))

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
    }


def _scan_package_json(file_path: Path, relative_path: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return [
            _finding(
                relative_path,
                "package-json-read-error",
                "medium",
                "package.json could not be parsed. Review it manually before installing dependencies.",
            )
        ], []

    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return [], []

    findings: list[dict[str, str]] = []
    lifecycle_scripts: list[dict[str, str]] = []
    for script_name in sorted(LIFECYCLE_SCRIPTS.intersection(scripts.keys())):
        lifecycle_scripts.append({"path": relative_path, "script": script_name})
        findings.append(
            _finding(
                relative_path,
                "package-lifecycle-script",
                "high",
                f"package.json defines a '{script_name}' lifecycle script. Review it before installing dependencies.",
            )
        )
    return findings, lifecycle_scripts


def _scan_text_patterns(file_path: Path, relative_path: str) -> list[dict[str, str]]:
    try:
        if file_path.stat().st_size > MAX_TEXT_BYTES:
            return []
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    lower_text = text.lower()
    findings = []
    for pattern, (severity, explanation) in PATTERNS.items():
        needle = pattern.lower()
        if needle in lower_text:
            findings.append(_finding(relative_path, "suspicious-text-pattern", severity, f"{explanation} Pattern: {pattern}"))
    return findings


def _load_ignore_patterns(project_path: Path) -> set[str]:
    ignore_path = project_path / IGNORE_FILE_NAME
    try:
        lines = ignore_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return set()

    patterns = set()
    for line in lines:
        pattern = line.strip()
        if not pattern or pattern.startswith("#"):
            continue
        patterns.add(pattern.replace("\\", "/"))
    return patterns


def _relative_path(file_path: Path, project_path: Path) -> str:
    return file_path.relative_to(project_path).as_posix()


def _finding(path: str, finding_type: str, severity: str, explanation: str) -> dict[str, str]:
    return {
        "path": path,
        "type": finding_type,
        "severity": severity,
        "explanation": explanation,
    }


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


def _infer_zone(project_path: Path) -> str:
    zones = {"trusted": "Trusted", "untrusted": "Untrusted", "quarantine": "Quarantine"}
    for part in project_path.parts:
        zone = zones.get(part.lower())
        if zone:
            return zone
    return "Unknown"


def _is_reparse_point_or_symlink(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        return bool(path.stat(follow_symlinks=False).st_file_attributes & 0x400)
    except (AttributeError, OSError):
        return False
