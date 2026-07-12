from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

try:
    import tomllib
except ImportError:  # pragma: no cover - supported runtimes provide tomllib
    tomllib = None

from .safety import has_multiple_hardlinks, is_reparse_point_or_symlink


SCHEMA_VERSION = 1
MAX_DEPENDENCY_BYTES = 5 * 1024 * 1024
MAX_ENTRIES = 2000
MAX_CHANGES = 300
MAX_FINDINGS = 500
MAX_DEPENDENCY_FILES = 500
MAX_REQUIREMENTS_DEPTH = 100
SUPPORTED_INTEGRITY_ALGORITHMS = {"sha256", "sha384", "sha512"}
NODE_MANIFESTS = {"package.json"}
NODE_LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json"}
PYTHON_MANIFESTS = {"pyproject.toml", "pipfile"}
PYTHON_LOCKFILES = {"poetry.lock", "pipfile.lock"}
DEPENDENCY_GROUPS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)
PIPENV_GROUPS = (("packages", "pipenv", False), ("dev-packages", "pipenv-dev", True))
PIPENV_LOCK_GROUPS = (("default", "pipenv", False), ("develop", "pipenv-dev", True))


def is_dependency_metadata(relative_path: str) -> bool:
    path = Path(relative_path)
    lower_name = path.name.lower()
    lower_parts = [part.lower() for part in path.parts]
    return (
        lower_name in NODE_MANIFESTS
        or lower_name in NODE_LOCKFILES
        or lower_name in PYTHON_MANIFESTS
        or lower_name in PYTHON_LOCKFILES
        or _is_requirements_path(lower_name, lower_parts)
    )


def analyze_dependencies(
    project_path: Path,
    inputs: list[tuple[Path, str]],
    *,
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    state = _AnalysisState(project_path)
    input_map = {relative: path for path, relative in inputs if is_dependency_metadata(relative)}
    ordered_inputs = sorted(input_map.items())
    if len(ordered_inputs) > MAX_DEPENDENCY_FILES:
        state.record_file_limit(
            len(ordered_inputs) - MAX_DEPENDENCY_FILES,
            "dependency-input-file-limit",
            "Supported dependency metadata exceeded the safe file-count limit.",
        )
        input_map = dict(ordered_inputs[:MAX_DEPENDENCY_FILES])
    for relative in sorted(input_map):
        path = input_map[relative]
        lower_name = path.name.lower()
        if lower_name == "package.json":
            state.parse_node_manifest(path, relative)
        elif lower_name in NODE_LOCKFILES:
            state.parse_node_lock(path, relative)
        elif _is_requirements_path(lower_name, [part.lower() for part in Path(relative).parts]):
            state.parse_requirements(path, relative)
        elif lower_name == "pyproject.toml":
            state.parse_pyproject(path, relative)
        elif lower_name == "poetry.lock":
            state.parse_poetry_lock(path, relative)
        elif lower_name == "pipfile":
            state.parse_pipfile(path, relative)
        elif lower_name == "pipfile.lock":
            state.parse_pipfile_lock(path, relative)

    state.finish_consistency_checks()
    normalized_entries = state.normalized_entries()

    current_status = _analysis_status(input_map, state)
    comparison, change_findings = _compare_snapshots(
        previous,
        normalized_entries,
        state.manifests,
        state.lockfiles,
        current_status,
    )
    state.findings.extend(change_findings)

    findings = sorted(_dedupe_findings(state.findings), key=_finding_sort_key)
    if len(findings) > MAX_FINDINGS:
        findings = findings[:MAX_FINDINGS]
        state.add_limitation("dependency-finding-limit", "Dependency findings exceeded the safe persistence limit.")

    counts = _inventory_counts(normalized_entries)
    consistency_count = sum(1 for finding in findings if finding["type"] in CONSISTENCY_FINDING_TYPES)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "status": _analysis_status(input_map, state),
        "ecosystems": sorted(state.ecosystems),
        "manifests": sorted(state.manifests),
        "lockfiles": sorted(state.lockfiles),
        "packageManagers": sorted(state.package_managers),
        "directDependencyCount": counts["direct"],
        "lockedDependencyCount": counts["locked"],
        "integrityCoverage": {
            "total": counts["integrityTotal"],
            "present": counts["integrityPresent"],
            "missing": counts["integrityTotal"] - counts["integrityPresent"],
        },
        "sourceCounts": counts["sources"],
        "unusualSourceCount": counts["unusualSources"],
        "installScriptIndicatorCount": counts["installScripts"],
        "consistencyIssueCount": consistency_count,
        "changeCount": comparison["changeCount"],
        "highestFindingSeverity": _highest_severity(findings),
        "entries": normalized_entries,
        "comparison": comparison,
        "limitations": sorted(state.limitations, key=lambda item: (item.get("path", ""), item["reason"])),
        "analyzedFiles": sorted(state.analyzed_files),
        "failedFiles": sorted(state.failed_files),
        "completenessGapCount": state.completeness_gap_count(),
        "findings": findings,
        "offlineOnly": True,
    }


def _analysis_status(input_map: dict[str, Path], state: "_AnalysisState") -> str:
    if not input_map:
        return "unsupported"
    if state.malformed:
        return "malformed"
    if state.limitations or state.failed_files:
        return "incomplete"
    return "complete"


def _inventory_counts(entries: list[dict[str, Any]]) -> dict[str, Any]:
    sources: Counter[str] = Counter()
    direct: set[tuple[str, str]] = set()
    locked: set[tuple[str, str, str, str, str]] = set()
    integrity: dict[tuple[str, str, str, str, str], bool] = {}
    install_scripts = 0
    for entry in entries:
        sources[entry.get("sourceType", "unknown")] += 1
        if entry.get("direct") is True:
            direct.add((entry.get("ecosystem", ""), entry.get("name", "")))
        if entry.get("lockedVersion"):
            key = _locked_key(entry)
            locked.add(key)
            if entry.get("sourceType") in {"registry", "url"}:
                integrity[key] = entry.get("integrityPresent") is True
        if entry.get("installScriptIndicator") is True:
            install_scripts += 1
    return {
        "direct": len(direct),
        "locked": len(locked),
        "integrityTotal": len(integrity),
        "integrityPresent": sum(integrity.values()),
        "sources": {key: sources[key] for key in sorted(sources)},
        "unusualSources": sum(sources[name] for name in ("local", "vcs", "url", "unknown")),
        "installScripts": install_scripts,
    }


CONSISTENCY_FINDING_TYPES = {
    "dependency-manifest-parse-error",
    "dependency-lockfile-parse-error",
    "dependency-missing-from-lock",
    "dependency-unexpected-lock-entry",
    "dependency-specification-mismatch",
    "dependency-lockfile-version-unsupported",
}


class _AnalysisState:
    def __init__(self, project_path: Path) -> None:
        self.project_path = project_path
        self.ecosystems: set[str] = set()
        self.manifests: set[str] = set()
        self.lockfiles: set[str] = set()
        self.package_managers: set[str] = set()
        self.direct_entries: list[dict[str, Any]] = []
        self.locked_entries: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self.limitations: list[dict[str, str]] = []
        self.analyzed_files: set[str] = set()
        self.failed_files: set[str] = set()
        self.malformed = False
        self.node_manifest_groups: dict[str, dict[str, str]] = {}
        self.node_lock_root_groups: dict[str, dict[str, str]] = {}
        self.node_lock_version: int | None = None
        self.node_declared_manager = ""
        self.poetry_manifest_paths: set[str] = set()
        self._requirements_seen: set[str] = set()
        self._requirements_stack: list[str] = []
        self._skipped_file_count = 0
        self._finding_keys: set[tuple[str, ...]] = set()

    def record_file_limit(self, count: int, reason: str, explanation: str) -> None:
        self._skipped_file_count += count
        self.add_limitation(reason, explanation)
        self.add_finding(
            "dependency-analysis-incomplete", "medium",
            "Some dependency metadata was not analyzed because a safe file-count limit was reached.",
            "Reduce or manually review unusually numerous dependency metadata files.",
        )

    def completeness_gap_count(self) -> int:
        counted_reasons = {"dependency-input-file-limit", "requirements-file-limit", "requirements-depth-limit"}
        global_limitations = sum(
            1 for item in self.limitations
            if not item.get("path") and item.get("reason") not in counted_reasons
        )
        return len(self.failed_files) + self._skipped_file_count + global_limitations

    def _analysis_gap(
        self, relative: str, reason: str, limitation: str, explanation: str, action: str,
    ) -> None:
        if relative:
            self.failed_files.add(relative)
        self.add_limitation(reason, limitation, relative)
        self.add_finding(
            "dependency-analysis-incomplete", "medium", explanation, action,
            path=relative,
        )

    def _append_entry(self, entry: dict[str, Any], *, locked: bool) -> bool:
        if len(self.direct_entries) + len(self.locked_entries) >= MAX_ENTRIES:
            path = str(entry.get("manifestPath") or entry.get("lockfilePath") or "")
            if path:
                self.failed_files.add(path)
            if not any(item.get("reason") == "dependency-entry-limit" for item in self.limitations):
                self.add_limitation("dependency-entry-limit", "Dependency inventory exceeded the safe in-memory analysis limit.", path)
                self.add_finding(
                    "dependency-analysis-incomplete", "medium",
                    "Dependency inventory exceeded the safe analysis limit, so additional entries were not retained.",
                    "Review unusually large dependency metadata manually before relying on this analysis.",
                )
            return False
        (self.locked_entries if locked else self.direct_entries).append(entry)
        return True

    def _mark_analyzed(self, relative: str) -> None:
        if relative not in self.failed_files:
            self.analyzed_files.add(relative)

    def _read_object(
        self, path: Path, relative: str, kind: str, finding_type: str, parser: Any,
    ) -> dict[str, Any] | None:
        content = self.read_bytes(path, relative, kind)
        return parser(content, self, relative, finding_type) if content is not None else None

    def read_bytes(self, path: Path, relative: str, kind: str) -> bytes | None:
        try:
            if is_reparse_point_or_symlink(path) or has_multiple_hardlinks(path):
                self.failed_files.add(relative)
                self.add_limitation("unsafe-dependency-metadata", "Dependency metadata was not read because its filesystem identity is unsafe.", relative)
                return None
            size = path.stat().st_size
            if size > MAX_DEPENDENCY_BYTES:
                self.failed_files.add(relative)
                self.add_limitation("dependency-metadata-size-limit", "Dependency metadata exceeded the specialized size limit.", relative)
                self.add_finding(
                    "dependency-analysis-incomplete",
                    "medium",
                    "Dependency metadata was too large to analyze safely.",
                    "Review this dependency file manually or reduce its size before relying on dependency analysis.",
                    path=relative,
                    metadata={"sizeLimitBytes": MAX_DEPENDENCY_BYTES, "inputKind": kind},
                )
                return None
            with path.open("rb") as handle:
                content = handle.read(MAX_DEPENDENCY_BYTES + 1)
            if len(content) > MAX_DEPENDENCY_BYTES:
                self.failed_files.add(relative)
                self.add_limitation("dependency-metadata-size-limit", "Dependency metadata grew beyond the specialized size limit while being read.", relative)
                return None
            return content
        except OSError:
            self.failed_files.add(relative)
            self.add_limitation("dependency-metadata-read-error", "Dependency metadata could not be read safely.", relative)
            self.add_finding(
                "dependency-analysis-incomplete",
                "medium",
                "Dependency metadata could not be read, so offline dependency analysis is incomplete.",
                "Inspect the file and filesystem permissions manually.",
                path=relative,
                metadata={"inputKind": kind},
            )
            return None

    def parse_node_manifest(self, path: Path, relative: str) -> None:
        self.ecosystems.add("node")
        self.manifests.add(relative)
        data = self._read_object(path, relative, "manifest", "dependency-manifest-parse-error", _json_object)
        if data is None:
            return
        package_manager = data.get("packageManager")
        if isinstance(package_manager, str) and package_manager.strip():
            self.node_declared_manager = _package_manager_name(package_manager)
            if self.node_declared_manager:
                self.package_managers.add(self.node_declared_manager)
        groups = self._parse_node_dependency_groups(data, relative)
        self._parse_node_bundling(data, relative)
        self._parse_node_overrides(data, relative)
        for field in ("workspaces", "resolutions"):
            if data.get(field) not in (None, [], {}):
                self._analysis_gap(
                    relative, f"node-{field}-not-resolved",
                    f"package.json field '{field}' was detected but is not resolved by offline dependency analysis.",
                    f"The Node '{field}' configuration was inventoried but not fully interpreted.",
                    f"Review the '{field}' configuration and related lockfile changes manually.",
                )
        self.node_manifest_groups = groups
        self._mark_analyzed(relative)

    def _parse_node_dependency_groups(self, data: dict[str, Any], relative: str) -> dict[str, dict[str, str]]:
        groups: dict[str, dict[str, str]] = {}
        for group in DEPENDENCY_GROUPS:
            raw = data.get(group, {})
            if raw is None:
                raw = {}
            if not isinstance(raw, dict):
                self._metadata_structure_error(
                    relative, "dependency-manifest-parse-error", "high",
                    f"package.json field '{group}' is not an object, so dependency identity is unreliable.",
                    "Correct the manifest structure before installing dependencies.", "node", {"field": group},
                )
                continue
            group_entries: dict[str, str] = {}
            for raw_name, raw_spec in sorted(raw.items(), key=lambda item: str(item[0]).lower()):
                if not isinstance(raw_name, str) or not isinstance(raw_spec, str):
                    self._metadata_structure_error(
                        relative, "dependency-manifest-parse-error", "high",
                        f"A dependency declaration in '{group}' has an invalid name or specification.",
                        "Correct the dependency declaration before installing dependencies.", "node", {"field": group},
                    )
                    continue
                name = _normalize_node_name(raw_name)
                spec = _sanitize_spec(raw_spec)
                group_entries[name] = spec
                source_type, source_host = _classify_node_spec(raw_spec)
                entry = _entry(
                    "node", name, group, direct=True,
                    requestedSpecification=spec,
                    sourceType=source_type,
                    sourceIdentifier=source_host,
                    dev=group == "devDependencies",
                    optional=group == "optionalDependencies",
                    peer=group == "peerDependencies",
                    manifestPath=relative,
                )
                if not self._append_entry(entry, locked=False):
                    continue
                self._source_findings(entry, relative)
            groups[group] = group_entries
        return groups

    def _parse_node_bundling(self, data: dict[str, Any], relative: str) -> None:
        bundled = data.get("bundledDependencies", data.get("bundleDependencies", []))
        if bundled is True:
            self.add_finding(
                "dependency-bundled-dependency", "low",
                "The project declares that its direct dependencies are bundled with the package.",
                "Confirm bundled dependencies are intentional and covered by the project's review process.",
                path=relative, ecosystem="node", metadata={"bundlesAllDirectDependencies": True},
            )
        elif bundled in (None, False, []):
            pass
        elif not isinstance(bundled, list):
            self._metadata_structure_error(
                relative, "dependency-manifest-parse-error", "medium",
                "Bundled dependency metadata is not a list.",
                "Review the bundled dependency declaration.", "node",
            )
        else:
            for raw_name in bundled:
                if not isinstance(raw_name, str):
                    self.malformed = True
                    self.failed_files.add(relative)
                    continue
                name = _normalize_node_name(raw_name)
                self.add_finding(
                    "dependency-bundled-dependency", "low",
                    "The project declares a bundled dependency that may be distributed with the package.",
                    "Confirm the bundled dependency is intentional and covered by the project's review process.",
                    path=relative, ecosystem="node", package=name,
                )

    def _parse_node_overrides(self, data: dict[str, Any], relative: str) -> None:
        overrides = data.get("overrides")
        if overrides not in (None, {}) and not isinstance(overrides, dict):
            self._metadata_structure_error(
                relative, "dependency-manifest-parse-error", "medium",
                "package.json field 'overrides' is not an object.",
                "Correct the override declaration and rescan.", "node", {"field": "overrides"},
            )
        elif isinstance(overrides, dict) and overrides:
            self.add_finding(
                "dependency-override-declaration", "low",
                "The manifest overrides one or more transitive dependency resolutions.",
                "Review the override declarations and confirm the resulting lockfile changes are intended.",
                path=relative, ecosystem="node", metadata={"overrideCount": len(overrides)},
            )

    def parse_node_lock(self, path: Path, relative: str) -> None:
        self.ecosystems.add("node")
        self.lockfiles.add(relative)
        self.package_managers.add("npm")
        data = self._read_object(path, relative, "lockfile", "dependency-lockfile-parse-error", _json_object)
        if data is None:
            return
        version = data.get("lockfileVersion", 1)
        if not isinstance(version, int) or version not in {1, 2, 3}:
            self.add_limitation("unsupported-lockfile-version", "npm lockfile version is unsupported.", relative)
            self.add_finding(
                "dependency-lockfile-version-unsupported", "medium",
                "The npm lockfile version is unsupported for reliable offline analysis.",
                "Regenerate the lockfile with a supported npm version or review it manually.",
                path=relative, ecosystem="node",
                metadata={"lockfileVersion": version if isinstance(version, (str, int, bool)) else "unsupported"},
            )
            self.failed_files.add(relative)
            return
        self.node_lock_version = version
        if version == 1:
            self.failed_files.add(relative)
            self.add_limitation(
                "npm-v1-root-evidence-limited",
                "npm lockfile version 1 lacks the root packages metadata used for complete group and install-state verification.",
                relative,
            )
        if version in {2, 3} and isinstance(data.get("packages"), dict):
            packages = data["packages"]
            root = packages.get("")
            if isinstance(root, dict):
                self.node_lock_root_groups = {
                    group: _string_map(root.get(group)) for group in DEPENDENCY_GROUPS
                }
            else:
                self.failed_files.add(relative)
                self.add_limitation(
                    "npm-root-package-unavailable",
                    "The npm packages map has no usable root-package record, so root consistency could not be verified.",
                    relative,
                )
            for package_path, package in sorted(packages.items(), key=lambda item: str(item[0]).lower()):
                if not package_path:
                    continue
                if not isinstance(package, dict):
                    self._node_lock_structure_error(relative, "An npm packages entry is not an object.")
                    continue
                name = _node_name_from_lock_path(str(package_path), package)
                if not name:
                    self._node_lock_structure_error(relative, "An npm packages entry has no usable package identity.")
                    continue
                is_direct = name in {item for group in self.node_lock_root_groups.values() for item in group} and _is_root_node_package_path(str(package_path), name)
                self._add_node_locked_entry(name, package, relative, version, direct=is_direct)
        elif isinstance(data.get("dependencies"), dict):
            if version in {2, 3}:
                self.failed_files.add(relative)
                self.add_limitation(
                    "npm-packages-map-unavailable",
                    "This npm lockfile lacks the packages map needed for complete root and install-state analysis.",
                    relative,
                )
            self._walk_node_v1(data["dependencies"], relative)
        else:
            self._metadata_structure_error(
                relative, "dependency-lockfile-parse-error", "high",
                "The npm lockfile does not contain a supported dependency structure.",
                "Regenerate or manually inspect the lockfile before installing dependencies.", "node",
            )
            return
        self._mark_analyzed(relative)

    def _walk_node_v1(self, dependencies: dict[str, Any], relative: str) -> None:
        pending = [(dependencies, 0)]
        while pending:
            current, depth = pending.pop()
            for raw_name, package in sorted(current.items(), key=lambda item: str(item[0]).lower(), reverse=True):
                if not isinstance(package, dict):
                    self._node_lock_structure_error(relative, "An npm dependencies entry is not an object.")
                    continue
                self._add_node_locked_entry(_normalize_node_name(str(raw_name)), package, relative, 1, direct=depth == 0)
                nested = package.get("dependencies")
                if isinstance(nested, dict):
                    pending.append((nested, depth + 1))
                elif nested is not None:
                    self._node_lock_structure_error(relative, "A nested npm dependencies field is not an object.")

    def _add_node_locked_entry(self, name: str, package: dict[str, Any], relative: str, lock_version: int, *, direct: bool) -> None:
        version = package.get("version") if isinstance(package.get("version"), str) else ""
        if not version and package.get("link") is not True:
            self._node_lock_structure_error(relative, "An npm lock entry has no usable version.")
            return
        resolved = package.get("resolved") if isinstance(package.get("resolved"), str) else ""
        source_type, source_host = _classify_resolved_source(resolved, version, link=package.get("link") is True)
        integrity = package.get("integrity") if isinstance(package.get("integrity"), str) else ""
        group = _node_direct_group(name, self.node_lock_root_groups) if direct else "transitive"
        entry = _entry(
            "node", name, group, direct=direct,
            lockedVersion=_safe_text(version, 200),
            sourceType=source_type,
            sourceIdentifier=source_host,
            integrity=_safe_text(integrity, 300),
            integrityPresent=bool(integrity),
            installScriptIndicator=package.get("hasInstallScript") is True,
            dev=package.get("dev") is True,
            optional=package.get("optional") is True,
            peer=package.get("peer") is True,
            lockfilePath=relative,
        )
        if not self._append_entry(entry, locked=True):
            return
        self._source_findings(entry, relative)
        if package.get("hasInstallScript") is True:
            self.add_finding(
                "dependency-install-script-indicator", "low",
                "The lockfile records an install-script indicator for this dependency.",
                "Review locally available package metadata before allowing installation scripts to run.",
                path=relative, ecosystem="node", package=name, group=group,
                metadata={"resolvedVersion": version} if version else {},
            )

        if integrity:
            integrity_status = _integrity_status(integrity)
            if integrity_status != "valid":
                self.add_finding(
                    "dependency-integrity-malformed", "medium",
                    f"The recorded dependency integrity value is {integrity_status}.",
                    "Regenerate the lockfile from a trusted source and review the integrity value.",
                    path=relative, ecosystem="node", package=name, group=group,
                    metadata={"integrityStatus": integrity_status},
                )
        elif lock_version >= 2 and source_type in {"registry", "url"} and not package.get("link"):
            self.add_finding(
                "dependency-integrity-missing", "medium",
                "A locked remote dependency has no recorded integrity value.",
                "Regenerate the lockfile and confirm the registry supplies integrity metadata.",
                path=relative, ecosystem="node", package=name, group=group,
                metadata={"resolvedVersion": version} if version else {},
            )

    def _node_lock_structure_error(self, relative: str, explanation: str) -> None:
        self._metadata_structure_error(
            relative, "dependency-lockfile-parse-error", "high", explanation,
            "Regenerate or manually inspect the npm lockfile before installing dependencies.", "node",
        )

    def parse_requirements(self, path: Path, relative: str) -> None:
        self.ecosystems.add("python")
        self.manifests.add(relative)
        self.package_managers.add("pip")
        self._parse_requirements_file(path, relative)

    def _parse_requirements_file(self, path: Path, relative: str) -> None:
        if relative in self._requirements_stack:
            self.failed_files.add(relative)
            self.add_limitation("requirements-include-cycle", "A recursive requirements include cycle was detected.", relative)
            self.add_finding(
                "dependency-analysis-incomplete", "medium",
                "A recursive requirements include cycle prevented complete dependency analysis.",
                "Remove the include cycle and rescan.", path=relative, ecosystem="python",
            )
            return
        if relative in self._requirements_seen:
            return
        if len(self._requirements_stack) >= MAX_REQUIREMENTS_DEPTH:
            if self._requirements_stack:
                self.failed_files.add(self._requirements_stack[-1])
            self.record_file_limit(
                1, "requirements-depth-limit",
                "A requirements include chain exceeded the safe recursion-depth limit.",
            )
            return
        if len(self._requirements_seen) >= MAX_DEPENDENCY_FILES:
            if self._requirements_stack:
                self.failed_files.add(self._requirements_stack[-1])
            self.record_file_limit(
                1, "requirements-file-limit",
                "Requirements includes exceeded the safe file-count limit.",
            )
            return
        self._requirements_seen.add(relative)
        self._requirements_stack.append(relative)
        content = self.read_bytes(path, relative, "manifest")
        if content is None:
            self._requirements_stack.pop()
            return
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            self._requirements_error(relative, 0, "Requirements metadata is not valid UTF-8.")
            self._requirements_stack.pop()
            return
        for line_number, raw_line, dangling_continuation in _logical_requirement_lines(text):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if dangling_continuation or _unsupported_requirement_option(line):
                self.failed_files.add(relative)
                self.add_limitation(
                    "unsupported-requirements-construct",
                    "A requirements continuation or option could not be interpreted reliably offline.",
                    relative,
                )
                self.add_finding(
                    "dependency-analysis-incomplete", "medium",
                    "A requirements construct is unsupported, so dependency analysis is incomplete.",
                    "Review the requirements options and continuations manually.",
                    path=relative, ecosystem="python", metadata={"line": line_number},
                )
                continue
            include = _requirements_include(line)
            if include:
                included = self._safe_include(path.parent, include, relative)
                if included:
                    included_path, included_relative = included
                    self.manifests.add(included_relative)
                    self._parse_requirements_file(included_path, included_relative)
                continue
            parsed = _parse_requirement_line(line)
            if parsed is None:
                self._requirements_error(relative, line_number, "A requirements line could not be interpreted safely.")
                continue
            entry = _entry(
                "python", parsed["name"], "requirements", direct=True,
                requestedSpecification=parsed["spec"],
                sourceType=parsed["sourceType"],
                sourceIdentifier=parsed.get("sourceIdentifier", ""),
                integrity=parsed.get("integrity", ""),
                integrityPresent=parsed.get("integrityPresent", False),
                optional=False, dev=False, peer=False,
                manifestPath=relative,
            )
            if not self._append_entry(entry, locked=False):
                continue
            self._source_findings(entry, relative)
            if parsed["pinning"] in {"unpinned", "range"} and parsed["sourceType"] == "registry":
                self.add_finding(
                    "dependency-unpinned", "low",
                    "A direct Python dependency is not pinned to one exact version.",
                    "Review the allowed version range and use a lockfile or hashes for reproducible installation.",
                    path=relative, ecosystem="python", package=parsed["name"], group="requirements",
                    requested=parsed["spec"], metadata={"pinning": parsed["pinning"]},
                )
            if parsed.get("integrityMalformed"):
                self.add_finding(
                    "dependency-integrity-malformed", "medium",
                    "A requirements hash declaration is malformed or uses an unsupported algorithm.",
                    "Correct the hash declaration and verify it against a trusted artifact.",
                    path=relative, ecosystem="python", package=parsed["name"], group="requirements",
                )
            if parsed["pinning"] == "exact" and parsed["sourceType"] == "registry":
                self._append_entry(_entry(
                    "python", parsed["name"], "requirements", direct=True,
                    lockedVersion=parsed["lockedVersion"],
                    sourceType="registry",
                    integrity=parsed.get("integrity", ""),
                    integrityPresent=parsed.get("integrityPresent", False),
                    lockfilePath=relative,
                ), locked=True)
        self._requirements_stack.pop()
        self._mark_analyzed(relative)

    def _safe_include(self, parent: Path, include: str, source_relative: str) -> tuple[Path, str] | None:
        include = include.strip().strip('"\'')
        candidate = Path(include)
        if candidate.is_absolute() or ".." in candidate.parts:
            self.add_limitation("unsafe-requirements-include", "A requirements include escaped the selected project.", source_relative)
            self.add_finding(
                "dependency-analysis-incomplete", "medium",
                "A requirements include was rejected because it was outside the selected project.",
                "Use a relative include that remains inside the project and rescan.",
                path=source_relative, ecosystem="python",
            )
            self.failed_files.add(source_relative)
            return None
        target = parent / candidate
        try:
            relative = target.relative_to(self.project_path).as_posix()
        except ValueError:
            self.failed_files.add(source_relative)
            self.add_limitation("unsafe-requirements-include", "A requirements include escaped the selected project.", source_relative)
            self.add_finding(
                "dependency-analysis-incomplete", "medium",
                "A requirements include could not be contained within the selected project.",
                "Use a relative include that remains inside the project and rescan.",
                path=source_relative, ecosystem="python",
            )
            return None
        try:
            current = self.project_path
            for part in Path(relative).parts:
                current /= part
                if is_reparse_point_or_symlink(current):
                    raise OSError("unsafe linked include")
            if not target.is_file() or has_multiple_hardlinks(target):
                raise OSError("missing or unsafe include")
        except OSError:
            self.failed_files.add(relative)
            self.add_limitation("requirements-include-unavailable", "A requirements include was missing or unsafe.", relative)
            self.add_finding(
                "dependency-analysis-incomplete", "medium",
                "An included requirements file was missing or could not be inspected safely.",
                "Restore a regular in-project include file and rescan.",
                path=relative, ecosystem="python",
            )
            return None
        return target, relative

    def _requirements_error(self, relative: str, line: int, explanation: str) -> None:
        self._metadata_structure_error(
            relative, "dependency-manifest-parse-error", "medium", explanation,
            "Correct the requirements metadata and rescan.", "python", {"line": line} if line else {},
        )

    def parse_pyproject(self, path: Path, relative: str) -> None:
        self.ecosystems.add("python")
        self.manifests.add(relative)
        data = self._read_object(path, relative, "manifest", "dependency-manifest-parse-error", _toml_object)
        if data is None:
            return
        build_requires = data.get("build-system", {}).get("requires") if isinstance(data.get("build-system"), dict) else None
        if build_requires:
            self._analysis_gap(
                relative, "pyproject-build-requires-unsupported",
                "pyproject build-system requirements are not included in normalized dependency analysis.",
                "Build-system requirements were detected but not analyzed as project dependencies.",
                "Review build-system requirements manually before invoking a build frontend.",
            )
        if data.get("dependency-groups"):
            self._analysis_gap(
                relative, "pyproject-dependency-groups-unsupported",
                "pyproject dependency-groups are not supported by normalized dependency analysis.",
                "Dependency groups were detected but could not be interpreted reliably.",
                "Review dependency groups manually and use a supported lockfile where possible.",
            )
        if data.get("project") is not None and not isinstance(data.get("project"), dict):
            self._python_structure_error(relative, "The pyproject project table is not an object.")
        project = data.get("project") if isinstance(data.get("project"), dict) else {}
        dependencies = project.get("dependencies", [])
        if not isinstance(dependencies, list):
            self._python_structure_error(relative, "The PEP 621 dependencies field is not a list.")
            dependencies = []
        for spec in dependencies:
            self._add_python_manifest_spec(spec, "project", relative)
        optional = project.get("optional-dependencies")
        if optional is not None and not isinstance(optional, dict):
            self._python_structure_error(relative, "The PEP 621 optional-dependencies field is not an object.")
        elif isinstance(optional, dict):
            for group, specs in sorted(optional.items()):
                if isinstance(specs, list):
                    for spec in specs:
                        self._add_python_manifest_spec(spec, f"optional:{group}", relative, optional=True)
                else:
                    self._python_structure_error(relative, "A PEP 621 optional dependency group is not a list.")
        poetry = _nested_dict(data, "tool", "poetry")
        if poetry:
            self.poetry_manifest_paths.add(relative)
            self.package_managers.add("poetry")
            self._add_poetry_group(poetry.get("dependencies"), "poetry", relative)
            self._add_poetry_group(poetry.get("dev-dependencies"), "poetry-dev", relative, dev=True)
            groups = poetry.get("group")
            if isinstance(groups, dict):
                for group_name, group_data in sorted(groups.items()):
                    if isinstance(group_data, dict):
                        self._add_poetry_group(group_data.get("dependencies"), f"poetry:{group_name}", relative, dev=group_name == "dev")
        self._mark_analyzed(relative)

    def _add_python_manifest_spec(self, raw_spec: Any, group: str, relative: str, optional: bool = False) -> None:
        if not isinstance(raw_spec, str):
            self._requirements_error(relative, 0, "A pyproject dependency entry is not a string.")
            return
        parsed = _parse_requirement_line(raw_spec)
        if parsed is None:
            self._requirements_error(relative, 0, "A pyproject dependency entry could not be interpreted.")
            return
        entry = _entry(
            "python", parsed["name"], group, direct=True,
            requestedSpecification=parsed["spec"], sourceType=parsed["sourceType"],
            sourceIdentifier=parsed.get("sourceIdentifier", ""), optional=optional,
            dev=group.endswith("dev"), peer=False, manifestPath=relative,
        )
        if not self._append_entry(entry, locked=False):
            return
        self._source_findings(entry, relative)
        if parsed["pinning"] in {"unpinned", "range"} and parsed["sourceType"] == "registry":
            self.add_finding(
                "dependency-unpinned", "low",
                "A direct Python dependency is not pinned to one exact version.",
                "Review the allowed range and use a compatible lockfile.",
                path=relative, ecosystem="python", package=parsed["name"], group=group,
                requested=parsed["spec"], metadata={"pinning": parsed["pinning"]},
            )

    def _add_poetry_group(self, raw: Any, group: str, relative: str, dev: bool = False) -> None:
        if raw is not None and not isinstance(raw, dict):
            self._python_structure_error(relative, "A Poetry dependency group is not an object.")
            return
        if not isinstance(raw, dict):
            return
        for raw_name, value in sorted(raw.items(), key=lambda item: str(item[0]).lower()):
            if str(raw_name).lower() == "python":
                continue
            name = _normalize_python_name(str(raw_name))
            spec, source_type, source_identifier = _poetry_spec(value)
            if source_type == "unknown" and not isinstance(value, dict):
                self._python_structure_error(relative, "A Poetry dependency declaration has an unsupported structure.")
                continue
            if isinstance(value, dict) and source_type == "registry" and not spec:
                self._python_structure_error(relative, "A Poetry dependency declaration has no usable version or source.")
                continue
            if source_type == "unknown":
                self._unresolved_named_source(relative)
            entry = _entry(
                "python", name, group, direct=True,
                requestedSpecification=spec, sourceType=source_type,
                sourceIdentifier=source_identifier, optional=isinstance(value, dict) and value.get("optional") is True,
                dev=dev, peer=False, manifestPath=relative,
            )
            if not self._append_entry(entry, locked=False):
                continue
            self._source_findings(entry, relative)

    def parse_poetry_lock(self, path: Path, relative: str) -> None:
        self.ecosystems.add("python")
        self.lockfiles.add(relative)
        self.package_managers.add("poetry")
        data = self._read_object(path, relative, "lockfile", "dependency-lockfile-parse-error", _toml_object)
        if data is None:
            return
        packages = data.get("package")
        if not isinstance(packages, list):
            self.malformed = True
            self.add_finding(
                "dependency-lockfile-parse-error", "medium",
                "poetry.lock does not contain a package list.",
                "Regenerate the Poetry lockfile and review dependency changes.",
                path=relative, ecosystem="python",
            )
            self.failed_files.add(relative)
            return
        for package in packages:
            if not isinstance(package, dict) or not isinstance(package.get("name"), str) or not isinstance(package.get("version"), str) or not package.get("version"):
                self._python_structure_error(relative, "A Poetry lock entry has no usable package name or version.", lockfile=True)
                continue
            name = _normalize_python_name(package["name"])
            version = _safe_text(package.get("version"), 200)
            source = package.get("source") if isinstance(package.get("source"), dict) else {}
            source_type, identifier = _classify_poetry_source(source)
            if package.get("files") is not None and not isinstance(package.get("files"), list):
                self._python_structure_error(relative, "A Poetry lock entry has an invalid files list.", lockfile=True)
            files = package.get("files") if isinstance(package.get("files"), list) else []
            if any(not isinstance(item, dict) or not isinstance(item.get("hash"), str) for item in files):
                self._python_structure_error(relative, "A Poetry lock file record has no usable hash.", lockfile=True)
            hashes = sorted(_safe_text(item.get("hash"), 300) for item in files if isinstance(item, dict) and item.get("hash"))
            self._record_python_hash_issues(hashes, relative, name, "transitive")
            integrity = hashes[0] if hashes else ""
            entry = _entry(
                "python", name, "transitive", direct=False,
                lockedVersion=version, sourceType=source_type, sourceIdentifier=identifier,
                integrity=integrity, integrityPresent=bool(hashes), lockfilePath=relative,
                optional=package.get("optional") is True,
                dev=str(package.get("category", "")).lower() == "dev", peer=False,
            )
            if not self._append_entry(entry, locked=True):
                continue
            self._source_findings(entry, relative)
        self._mark_analyzed(relative)

    def parse_pipfile(self, path: Path, relative: str) -> None:
        self.ecosystems.add("python")
        self.manifests.add(relative)
        self.package_managers.add("pipenv")
        data = self._read_object(path, relative, "manifest", "dependency-manifest-parse-error", _toml_object)
        if data is None:
            return
        for section, group, dev in PIPENV_GROUPS:
            packages = data.get(section)
            if packages is not None and not isinstance(packages, dict):
                self._python_structure_error(relative, f"Pipfile section '{section}' is not an object.")
                continue
            if not isinstance(packages, dict):
                continue
            for raw_name, raw_value in sorted(packages.items(), key=lambda item: str(item[0]).lower()):
                name = _normalize_python_name(str(raw_name))
                spec, source_type, identifier = _pipfile_spec(raw_value)
                if source_type == "unknown":
                    if isinstance(raw_value, dict):
                        self._unresolved_named_source(relative)
                    else:
                        self._python_structure_error(relative, "A Pipfile dependency declaration has an unsupported structure.")
                        continue
                if isinstance(raw_value, dict) and source_type == "registry" and not spec:
                    self._python_structure_error(relative, "A Pipfile dependency declaration has no usable version or source.")
                    continue
                entry = _entry(
                    "python", name, group, direct=True,
                    requestedSpecification=spec, sourceType=source_type,
                    sourceIdentifier=identifier, dev=dev, optional=False, peer=False,
                    manifestPath=relative,
                )
                if not self._append_entry(entry, locked=False):
                    continue
                self._source_findings(entry, relative)
        self._mark_analyzed(relative)

    def parse_pipfile_lock(self, path: Path, relative: str) -> None:
        self.ecosystems.add("python")
        self.lockfiles.add(relative)
        self.package_managers.add("pipenv")
        data = self._read_object(path, relative, "lockfile", "dependency-lockfile-parse-error", _json_object)
        if data is None:
            return
        for section, group, dev in PIPENV_LOCK_GROUPS:
            packages = data.get(section)
            if packages is not None and not isinstance(packages, dict):
                self._python_structure_error(relative, f"Pipfile.lock section '{section}' is not an object.", lockfile=True)
                continue
            if not isinstance(packages, dict):
                continue
            for raw_name, package in sorted(packages.items(), key=lambda item: str(item[0]).lower()):
                if not isinstance(package, dict) or not isinstance(package.get("version"), str) or not package.get("version"):
                    self._python_structure_error(relative, "A Pipfile.lock entry has no usable version.", lockfile=True)
                    continue
                name = _normalize_python_name(str(raw_name))
                version = str(package.get("version", "")).removeprefix("==")
                source_type, identifier = _pipfile_spec(package)[1:]
                if source_type == "unknown":
                    self._unresolved_named_source(relative)
                if package.get("hashes") is not None and not isinstance(package.get("hashes"), list):
                    self._python_structure_error(relative, "A Pipfile.lock entry has an invalid hashes list.", lockfile=True)
                hashes = package.get("hashes") if isinstance(package.get("hashes"), list) else []
                if any(not isinstance(value, str) for value in hashes):
                    self._python_structure_error(relative, "A Pipfile.lock hash is not a string.", lockfile=True)
                normalized_hashes = [_safe_text(value, 300) for value in hashes if isinstance(value, str)]
                self._record_python_hash_issues(normalized_hashes, relative, name, group)
                integrity = normalized_hashes[0] if normalized_hashes else ""
                self._append_entry(_entry(
                    "python", name, group, direct=True,
                    lockedVersion=_safe_text(version, 200), sourceType=source_type,
                    sourceIdentifier=identifier, integrity=integrity,
                    integrityPresent=bool(hashes), dev=dev, optional=False, peer=False,
                    lockfilePath=relative,
                ), locked=True)
        self._mark_analyzed(relative)

    def _python_structure_error(self, relative: str, explanation: str, *, lockfile: bool = False) -> None:
        self._metadata_structure_error(
            relative,
            "dependency-lockfile-parse-error" if lockfile else "dependency-manifest-parse-error",
            "medium", explanation,
            "Correct or regenerate the dependency metadata and rescan.", "python",
        )

    def _metadata_structure_error(
        self,
        relative: str,
        finding_type: str,
        severity: str,
        explanation: str,
        action: str,
        ecosystem: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.malformed = True
        self.failed_files.add(relative)
        self.add_finding(
            finding_type, severity, explanation, action,
            path=relative, ecosystem=ecosystem, metadata=metadata,
        )

    def _record_python_hash_issues(self, hashes: list[str], relative: str, name: str, group: str) -> None:
        if hashes and any(_integrity_status(value) != "valid" for value in hashes):
            self.add_finding(
                "dependency-integrity-malformed", "medium",
                "A Python lock entry contains a malformed hash or unsupported hash algorithm.",
                "Regenerate the lock metadata and verify the artifact hashes.",
                path=relative, ecosystem="python", package=name, group=group,
            )

    def _unresolved_named_source(self, relative: str) -> None:
        self.failed_files.add(relative)
        self.add_limitation(
            "named-python-source-unresolved",
            "A named Python package source could not be mapped to a safe host from this metadata alone.",
            relative,
        )

    def finish_consistency_checks(self) -> None:
        self._finish_node_consistency_checks()
        self._finish_python_consistency_checks()

    def _finish_node_consistency_checks(self) -> None:
        node_manifests = sorted(path for path in self.manifests if Path(path).name.lower() == "package.json")
        node_locks = sorted(path for path in self.lockfiles if Path(path).name.lower() in NODE_LOCKFILES)
        manifests_with_dependencies = {
            entry.get("manifestPath", "") for entry in self.direct_entries
            if entry.get("ecosystem") == "node"
        }
        for manifest in sorted(manifests_with_dependencies):
            if not _has_sibling(manifest, node_locks, NODE_LOCKFILES):
                self._analysis_gap(
                    manifest, "node-lockfile-unavailable",
                    "A Node manifest declares dependencies without a supported sibling npm lockfile.",
                    "Resolved Node dependency identity and integrity are unavailable offline.",
                    "Create or review the intended package-manager lockfile before installation.",
                )
        for lockfile in node_locks:
            if not _has_sibling(lockfile, node_manifests, NODE_MANIFESTS):
                self._analysis_gap(
                    lockfile, "node-manifest-unavailable",
                    "An npm lockfile has no sibling package.json manifest.",
                    "The npm lockfile could not be compared with its root manifest.",
                    "Restore or review the corresponding package.json before installation.",
                )
        if self.node_declared_manager and self.node_declared_manager != "npm" and node_manifests:
            self._analysis_gap(
                node_manifests[0], "unsupported-node-package-manager",
                "The declared Node package manager is not supported for lockfile normalization.",
                "The declared Node package manager cannot be fully verified by the npm-focused analyzer.",
                "Review the declared package manager and its lockfile manually.",
            )
        single_node_context = (
            len(node_manifests) == 1
            and len(node_locks) == 1
            and Path(node_manifests[0]).parent == Path(node_locks[0]).parent
        )
        if node_manifests and node_locks and not single_node_context:
            self.add_limitation(
                "multiple-node-metadata-contexts",
                "Multiple or non-sibling Node metadata contexts were inventoried, but cross-file consistency comparison was withheld.",
            )
        if single_node_context and self.node_declared_manager and self.node_lock_version and self.node_declared_manager != "npm":
            self.add_finding(
                "dependency-specification-mismatch", "medium",
                "The declared Node package manager does not match the npm lockfile format found in the project.",
                "Confirm the intended package manager and regenerate the matching lockfile.",
                ecosystem="node", path=next(iter(self.lockfiles), "package-lock.json"),
                metadata={"declaredPackageManager": self.node_declared_manager, "lockfilePackageManager": "npm"},
            )
        if single_node_context and self.node_manifest_groups and self.node_lock_version:
            self._node_cross_group_conflicts(self.node_manifest_groups, next(iter(self.manifests), "package.json"), "manifest")
            self._node_cross_group_conflicts(self.node_lock_root_groups, next(iter(self.lockfiles), "package-lock.json"), "lockfile root")
            manifest_names = {name for group in self.node_manifest_groups.values() for name in group}
            locked_names = {entry["name"] for entry in self.locked_entries if entry["ecosystem"] == "node"}
            for name in sorted(manifest_names - locked_names):
                group = _node_direct_group(name, self.node_manifest_groups)
                self.add_finding(
                    "dependency-missing-from-lock", "medium",
                    "A direct Node dependency declared in package.json is absent from the npm lockfile.",
                    "Regenerate the lockfile and review the resolved dependency before installing.",
                    ecosystem="node", package=name, group=group,
                    path=next(iter(self.manifests), "package.json"),
                )
            root_names = {name for group in self.node_lock_root_groups.values() for name in group}
            for name in sorted(root_names - manifest_names):
                self.add_finding(
                    "dependency-unexpected-lock-entry", "medium",
                    "The npm lockfile root declares a dependency absent from package.json.",
                    "Regenerate the lockfile or confirm why the root declaration differs.",
                    ecosystem="node", package=name,
                    path=next(iter(self.lockfiles), "package-lock.json"),
                )
            for group, manifest in self.node_manifest_groups.items():
                lock_group = self.node_lock_root_groups.get(group, {})
                for name in sorted(set(manifest).intersection(lock_group)):
                    if _specs_reliably_comparable(manifest[name], lock_group[name]) and manifest[name] != lock_group[name]:
                        self.add_finding(
                            "dependency-specification-mismatch", "medium",
                            "The requested dependency specification differs between package.json and the lockfile root metadata.",
                            "Regenerate the lockfile and review the requested specification.",
                            ecosystem="node", package=name, group=group,
                            requested=manifest[name], path=next(iter(self.lockfiles), "package-lock.json"),
                            metadata={"lockRequestedSpecification": lock_group[name]},
                        )
    def _finish_python_consistency_checks(self) -> None:
        python_direct_entries = [
            entry for entry in self.direct_entries
            if entry["ecosystem"] == "python" and not _requirements_self_lock(entry)
        ]
        pipfiles = sorted(path for path in self.manifests if Path(path).name.lower() == "pipfile")
        pipfile_locks = sorted(path for path in self.lockfiles if Path(path).name.lower() == "pipfile.lock")
        poetry_locks = sorted(path for path in self.lockfiles if Path(path).name.lower() == "poetry.lock")
        for manifest in pipfiles:
            if any(entry.get("manifestPath") == manifest for entry in python_direct_entries) and not _has_sibling(manifest, pipfile_locks, {"pipfile.lock"}):
                self._analysis_gap(
                    manifest, "pipfile-lock-unavailable",
                    "Pipfile declares dependencies without a sibling Pipfile.lock.",
                    "Resolved Pipenv dependency identity and hashes are unavailable offline.",
                    "Generate or review Pipfile.lock before installing dependencies.",
                )
        for lockfile in pipfile_locks:
            if not _has_sibling(lockfile, pipfiles, {"pipfile"}):
                self._analysis_gap(
                    lockfile, "pipfile-manifest-unavailable",
                    "Pipfile.lock has no sibling Pipfile.",
                    "The Pipenv lockfile could not be compared with its manifest.",
                    "Restore or review the corresponding Pipfile before installation.",
                )
        for manifest in sorted(self.poetry_manifest_paths):
            if not _has_sibling(manifest, poetry_locks, {"poetry.lock"}):
                self._analysis_gap(
                    manifest, "poetry-lock-unavailable",
                    "A Poetry manifest has no sibling poetry.lock.",
                    "Resolved Poetry dependency identity and hashes are unavailable offline.",
                    "Generate or review poetry.lock before installing dependencies.",
                )
        for lockfile in poetry_locks:
            if not _has_sibling(lockfile, self.poetry_manifest_paths, {"pyproject.toml"}):
                self._analysis_gap(
                    lockfile, "poetry-manifest-unavailable",
                    "poetry.lock has no sibling Poetry pyproject.toml manifest.",
                    "The Poetry lockfile could not be compared with its manifest.",
                    "Restore or review the corresponding pyproject.toml before installation.",
                )
        for direct in sorted(python_direct_entries, key=_entry_sort_key):
            compatible_locks = [
                entry for entry in self.locked_entries
                if entry["ecosystem"] == "python" and _lock_matches_direct(direct, entry)
            ]
            if _corresponding_lock_present(direct, self.lockfiles) and not compatible_locks:
                self.add_finding(
                    "dependency-missing-from-lock", "medium",
                    "A direct Python dependency is absent from the corresponding lockfile.",
                    "Regenerate the lockfile and review the resolved package before installing.",
                    ecosystem="python", package=direct["name"], group=direct["group"], path=direct.get("manifestPath", ""),
                )
            expected = _exact_requested_version(direct.get("requestedSpecification", ""))
            locked = compatible_locks[0] if compatible_locks else None
            if expected and locked and locked.get("lockedVersion") and expected != locked["lockedVersion"]:
                self.add_finding(
                    "dependency-specification-mismatch", "medium",
                    "The exact Python dependency request differs from the locally recorded locked version.",
                    "Regenerate the lockfile and review the resolved version.",
                    ecosystem="python", package=direct["name"], group=direct["group"],
                    path=direct.get("manifestPath", ""), requested=direct.get("requestedSpecification", ""),
                    resolved=locked["lockedVersion"],
                )

        for locked in sorted(
            (entry for entry in self.locked_entries if Path(entry.get("lockfilePath", "")).name.lower() == "pipfile.lock"),
            key=_entry_sort_key,
        ):
            if not any(_lock_matches_direct(direct, locked) for direct in python_direct_entries):
                self.add_finding(
                    "dependency-unexpected-lock-entry", "medium",
                    "A direct Pipenv lock entry is absent from Pipfile.",
                    "Regenerate Pipfile.lock or confirm why the direct lock entry remains.",
                    ecosystem="python", package=locked["name"], group=locked["group"],
                    path=locked.get("lockfilePath", ""),
                )

        python_locked = [
            entry for entry in self.locked_entries
            if entry["ecosystem"] == "python" and entry.get("sourceType") in {"registry", "url"}
        ]
        hash_locked_files = {
            entry.get("lockfilePath", "") for entry in python_locked if entry.get("integrityPresent") is True
        }
        for entry in python_locked:
            if entry.get("lockfilePath", "") in hash_locked_files and entry.get("integrityPresent") is not True:
                self.add_finding(
                    "dependency-integrity-missing", "medium",
                    "A locked Python dependency has no hash although this lock input records hashes for other packages.",
                    "Regenerate the lock metadata and verify hashes for all remote artifacts.",
                    ecosystem="python", package=entry["name"], group=entry["group"],
                    path=entry.get("lockfilePath", ""), resolved=entry.get("lockedVersion", ""),
                )

    def _node_cross_group_conflicts(self, groups: dict[str, dict[str, str]], path: str, location: str) -> None:
        declarations: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for group, values in groups.items():
            for name, specification in values.items():
                declarations[name].append((group, specification))
        for name, values in sorted(declarations.items()):
            if len(values) > 1 and len({specification for _, specification in values}) > 1:
                self.add_finding(
                    "dependency-specification-mismatch", "medium",
                    f"The Node {location} declares the same dependency in multiple groups with contradictory specifications.",
                    "Keep one intentional declaration or align the dependency specifications.",
                    ecosystem="node", package=name, path=path,
                    metadata={"groups": sorted(group for group, _ in values)},
                )

    def normalized_entries(self) -> list[dict[str, Any]]:
        locked_by_name: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for entry in self.locked_entries:
            locked_by_name[(entry["ecosystem"], entry["name"])].append(entry)
        entries: list[dict[str, Any]] = []
        matched_locked: set[int] = set()
        for direct in self.direct_entries:
            candidates = [
                entry for entry in locked_by_name.get((direct["ecosystem"], direct["name"]), [])
                if (
                    (direct["ecosystem"] == "python" and _lock_matches_direct(direct, entry))
                    or (direct["ecosystem"] == "node" and _node_lock_matches_direct(direct, entry))
                    or direct["ecosystem"] not in {"node", "python"}
                )
            ]
            candidates.sort(key=_entry_sort_key)
            locked = candidates[0] if candidates else None
            merged = dict(direct)
            if locked:
                matched_locked.add(id(locked))
                for key in ("lockedVersion", "integrity", "integrityPresent", "installScriptIndicator", "lockfilePath"):
                    if key in locked:
                        merged[key] = locked[key]
                if merged.get("sourceType") == "registry" and locked.get("sourceType"):
                    merged["sourceType"] = locked["sourceType"]
                    if locked.get("sourceIdentifier"):
                        merged["sourceIdentifier"] = locked["sourceIdentifier"]
            entries.append(_compact(merged))
        for locked in self.locked_entries:
            if id(locked) not in matched_locked:
                entries.append(_compact(locked))
        return sorted(entries, key=_entry_sort_key)

    def _source_findings(self, entry: dict[str, Any], path: str) -> None:
        source_type = entry.get("sourceType", "unknown")
        source_identifier = entry.get("sourceIdentifier", "")
        common = {
            "path": path,
            "ecosystem": entry["ecosystem"],
            "package": entry["name"],
            "group": entry["group"],
            "requested": entry.get("requestedSpecification", ""),
            "source_type": source_type,
            "source": source_identifier,
        }
        if entry.get("insecureHttp"):
            self.add_finding(
                "dependency-insecure-http-source", "high",
                "A dependency uses a plaintext HTTP source.",
                "Use an authenticated HTTPS registry or verify and pin the remote artifact.", **common,
            )
        elif source_type == "local":
            self.add_finding(
                "dependency-local-source", "medium",
                "A dependency resolves from a local file or linked path.",
                "Verify the local source and ensure it remains inside the intended project boundary.", **common,
            )
        elif source_type == "vcs":
            self.add_finding(
                "dependency-vcs-source", "medium",
                "A dependency is obtained directly from version control.",
                "Review the repository host and pin an immutable revision where possible.", **common,
            )
        elif source_type == "url":
            finding_type = "dependency-nonregistry-source"
            severity = "medium"
            explanation = "A dependency uses a direct remote URL or archive source."
            self.add_finding(
                finding_type, severity, explanation,
                "Use an authenticated HTTPS registry or verify and pin the remote artifact.", **common,
            )
        elif source_type == "unknown":
            self.add_finding(
                "dependency-nonregistry-source", "low",
                "A dependency uses a named or otherwise unresolved package source that may be legitimate.",
                "Confirm the named source configuration and host before installing.", **common,
            )
        if source_type in {"url", "vcs"} and (not source_identifier or source_identifier.endswith(":malformed")):
            self.failed_files.add(path)
            self.add_limitation("malformed-dependency-source", "A remote dependency source had no safely interpretable host.", path)
            self.add_finding(
                "dependency-analysis-incomplete", "medium",
                "A remote dependency source could not be interpreted reliably.",
                "Correct the dependency source and rescan.", **common,
            )
        if source_identifier and entry["ecosystem"] == "node" and source_type in {"registry", "url"} and source_identifier != "registry.npmjs.org":
            self.add_finding(
                "dependency-resolved-host-anomaly", "low",
                "A dependency resolves from a non-default registry or remote host; custom registries may be legitimate.",
                "Confirm that this host is expected for the project.", **common,
            )

    def add_limitation(self, reason: str, explanation: str, path: str = "") -> None:
        item = {"reason": reason, "explanation": _safe_text(explanation, 300)}
        if path:
            item["path"] = _safe_relative_path(path)
        if item not in self.limitations:
            self.limitations.append(item)

    def add_finding(
        self,
        finding_type: str,
        severity: str,
        explanation: str,
        action: str,
        *,
        path: str = "",
        ecosystem: str = "",
        package: str = "",
        group: str = "",
        requested: str = "",
        resolved: str = "",
        source_type: str = "",
        source: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        finding: dict[str, Any] = {
            "type": finding_type,
            "severity": severity,
            "explanation": _safe_text(explanation, 500),
            "action": _safe_text(action, 500),
        }
        optional = {
            "path": _safe_relative_path(path),
            "ecosystem": ecosystem,
            "package": package,
            "dependencyGroup": group,
            "requestedSpecification": _sanitize_spec(requested),
            "resolvedVersion": _safe_text(resolved, 200),
            "sourceType": source_type,
            "sourceIdentifier": _safe_text(source, 200),
            "metadata": _compact(metadata or {}),
        }
        finding.update({key: value for key, value in optional.items() if value not in ("", {}, [])})
        identity = _finding_identity(finding)
        if identity in self._finding_keys:
            return
        self._finding_keys.add(identity)
        self.findings.append(finding)


def _json_object(content: bytes, state: _AnalysisState, relative: str, finding_type: str) -> dict[str, Any] | None:
    try:
        data = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        state.malformed = True
        state.failed_files.add(relative)
        state.add_finding(
            finding_type, "high" if finding_type.endswith("manifest-parse-error") else "medium",
            "Dependency JSON metadata is malformed and could not be analyzed reliably.",
            "Correct or regenerate the dependency metadata and rescan.", path=relative,
        )
        return None
    if not isinstance(data, dict):
        state.malformed = True
        state.failed_files.add(relative)
        state.add_finding(
            finding_type, "medium", "Dependency JSON metadata is not an object.",
            "Correct or regenerate the dependency metadata and rescan.", path=relative,
        )
        return None
    return data


def _toml_object(content: bytes, state: _AnalysisState, relative: str, finding_type: str) -> dict[str, Any] | None:
    if tomllib is None:
        state.failed_files.add(relative)
        state.add_limitation("toml-parser-unavailable", "This Python runtime cannot parse TOML dependency metadata.", relative)
        return None
    try:
        data = tomllib.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        state.malformed = True
        state.failed_files.add(relative)
        state.add_finding(
            finding_type, "medium", "Dependency TOML metadata is malformed and could not be analyzed reliably.",
            "Correct or regenerate the dependency metadata and rescan.", path=relative, ecosystem="python",
        )
        return None
    return data


def _logical_requirement_lines(text: str) -> list[tuple[int, str, bool]]:
    logical: list[tuple[int, str, bool]] = []
    buffer = ""
    start_line = 0
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if not buffer:
            start_line = line_number
        stripped = raw_line.rstrip()
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        logical.append((start_line, buffer + raw_line, False))
        buffer = ""
    if buffer:
        logical.append((start_line, buffer.rstrip(), True))
    return logical


def _unsupported_requirement_option(line: str) -> bool:
    if line.startswith(("-e ", "--editable ", "-r ", "--requirement ", "--requirement=")):
        return False
    if line.startswith("-"):
        return True
    without_hashes = re.sub(r"\s+--hash(?:=|\s+)[^\s]+", "", line)
    return re.search(r"\s--[A-Za-z]", without_hashes) is not None


def _split_requirement_marker(line: str) -> tuple[str, str]:
    if "://" not in line and ";" in line:
        requirement, marker = line.split(";", 1)
        return requirement.strip(), _safe_text(marker, 300)
    match = re.match(r"^(.*?)\s+;\s*(.+)$", line)
    return (match.group(1).strip(), _safe_text(match.group(2), 300)) if match else (line, "")


def _with_marker(spec: str, marker: str) -> str:
    return f"{spec}; {marker}" if marker else spec


def _parse_requirement_line(line: str) -> dict[str, Any] | None:
    line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
    editable = False
    if line.startswith(("-e ", "--editable ")):
        editable = True
        line = line.split(None, 1)[1].strip()
    hash_values = re.findall(r"--hash(?:=|\s+)([^\s]+)", line)
    line = re.sub(r"\s+--hash(?:=|\s+)[^\s]+", "", line).strip()
    line, marker = _split_requirement_marker(line)
    if line.startswith(("git+", "hg+", "svn+", "bzr+")):
        name = _name_from_egg(line) or "unnamed-vcs-dependency"
        return _requirement_result(name, _with_marker(line, marker), "vcs", "unpinned", hash_values, editable=editable)
    direct_match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]+\])?)\s*@\s*(.+)$", line)
    if direct_match:
        name = _normalize_python_name(direct_match.group(1).split("[", 1)[0])
        target = direct_match.group(2).strip()
        source_type, identifier = _classify_python_source(target, editable)
        if source_type == "registry":
            return None
        return _requirement_result(name, _with_marker(target, marker), source_type, "unpinned", hash_values, identifier, editable)
    if line.startswith(("http://", "https://")):
        name = _archive_name(line) or "unnamed-url-dependency"
        source_type, identifier = _classify_python_source(line, editable)
        return _requirement_result(name, _with_marker(line, marker), source_type, "unpinned", hash_values, identifier, editable)
    if line.startswith((".", "/", "\\")) or line.lower().endswith((".whl", ".zip", ".tar.gz")):
        name = _archive_name(line) or "unnamed-local-dependency"
        return _requirement_result(name, _with_marker(line, marker), "local", "unpinned", hash_values, "local path", editable)
    match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*([^;]*)(?:;.*)?$", line)
    if not match:
        return None
    name = _normalize_python_name(match.group(1))
    spec = match.group(2).strip()
    if editable:
        return None
    exact_match = re.fullmatch(r"==\s*([^,*\s]+)", spec)
    pinning = "exact" if exact_match and "*" not in exact_match.group(1) else "unpinned" if not spec else "range"
    result = _requirement_result(name, _with_marker(spec, marker), "registry", pinning, hash_values, editable=editable)
    if exact_match:
        result["lockedVersion"] = _safe_text(exact_match.group(1), 200)
    return result


def _requirement_result(
    name: str,
    spec: str,
    source_type: str,
    pinning: str,
    hashes: list[str],
    identifier: str = "",
    editable: bool = False,
) -> dict[str, Any]:
    valid_hashes = [value for value in hashes if _integrity_status(value) == "valid"]
    return {
        "name": _normalize_python_name(name),
        "spec": _sanitize_spec(spec),
        "sourceType": "local" if editable and source_type == "registry" else source_type,
        "sourceIdentifier": identifier,
        "pinning": pinning,
        "integrity": valid_hashes[0] if valid_hashes else "",
        "integrityPresent": bool(hashes),
        "integrityMalformed": bool(hashes) and len(valid_hashes) != len(hashes),
    }


def _compare_snapshots(
    previous: dict[str, Any] | None,
    current_entries: list[dict[str, Any]],
    manifests: set[str],
    lockfiles: set[str],
    current_status: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(previous, dict):
        return _empty_comparison("unavailable", "No previous dependency analysis is available."), []
    if previous.get("schemaVersion") != SCHEMA_VERSION or not isinstance(previous.get("entries"), list):
        return _empty_comparison("incompatible", "The previous dependency analysis schema is unavailable or incompatible."), []
    previous_entries = [entry for entry in previous["entries"] if isinstance(entry, dict)]
    current_direct = {_direct_key(entry): entry for entry in current_entries if entry.get("direct") is True}
    previous_direct = {_direct_key(entry): entry for entry in previous_entries if entry.get("direct") is True}
    changes: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    previous_status = previous.get("status") if isinstance(previous.get("status"), str) else "unknown"
    if previous_status != current_status:
        changes.append({
            "changeType": "analysis-status-changed",
            "previousValue": _safe_text(previous_status, 40),
            "currentValue": current_status,
        })

    # Partial inventories must not manufacture removals. Package-level comparison is
    # reliable only when both snapshots completed their intended local inspection.
    if previous_status == "complete" and current_status == "complete":
        for key in sorted(set(current_direct) - set(previous_direct)):
            entry = current_direct[key]
            changes.append(_change("added", entry))
            findings.append(_change_finding("dependency-added", "low", entry, "A direct dependency was added since the previous compatible scan.", "Review why this dependency was added before installing it."))
        for key in sorted(set(previous_direct) - set(current_direct)):
            changes.append(_change("removed", previous_direct[key]))
        for key in sorted(set(current_direct).intersection(previous_direct)):
            current = current_direct[key]
            old = previous_direct[key]
            if current.get("requestedSpecification", "") != old.get("requestedSpecification", ""):
                changes.append(_change("specification-changed", current, previous=_sanitize_spec(old.get("requestedSpecification", ""))))
            if current.get("lockedVersion", "") != old.get("lockedVersion", ""):
                changes.append(_change("version-changed", current, previous=old.get("lockedVersion", "")))
                findings.append(_change_finding("dependency-version-changed", "low", current, "A resolved dependency version changed since the previous scan.", "Review the version change and corresponding release information locally where available."))
            if (current.get("sourceType", ""), current.get("sourceIdentifier", "")) != (old.get("sourceType", ""), old.get("sourceIdentifier", "")):
                previous_source = _safe_text(old.get("sourceType", ""), 40)
                previous_identifier = _sanitize_source_identifier(old.get("sourceIdentifier", ""))
                changes.append(_change("source-changed", current, previous=f"{previous_source}:{previous_identifier}"))
                severity = "high" if current.get("sourceType") == "url" and current.get("sourceIdentifier", "").startswith("http:") else "medium"
                findings.append(_change_finding("dependency-source-changed", severity, current, "A dependency source changed since the previous scan.", "Verify that the new source and host are expected before installing."))
            if (
                current.get("lockedVersion") == old.get("lockedVersion")
                and current.get("sourceType") == old.get("sourceType")
                and current.get("sourceIdentifier") == old.get("sourceIdentifier")
                and current.get("integrity")
                and old.get("integrity")
                and _integrity_status(current["integrity"]) == "valid"
                and _integrity_status(old["integrity"]) == "valid"
                and current.get("integrity") != old.get("integrity")
            ):
                changes.append(_change("integrity-changed", current))
                findings.append(_change_finding("dependency-integrity-changed", "high", current, "Integrity changed while package, version, and source remained equivalent.", "Stop and verify the lockfile change against a trusted artifact source before installing."))

        current_locked = {_locked_key(entry): entry for entry in current_entries if entry.get("lockedVersion") and entry.get("direct") is not True}
        previous_locked = {_locked_key(entry): entry for entry in previous_entries if entry.get("lockedVersion") and entry.get("direct") is not True}
        for key in sorted(set(current_locked) - set(previous_locked)):
            changes.append(_change("locked-added", current_locked[key]))
        for key in sorted(set(previous_locked) - set(current_locked)):
            changes.append(_change("locked-removed", previous_locked[key]))
    previous_manifests = set(item for item in previous.get("manifests", []) if isinstance(item, str))
    previous_lockfiles = set(item for item in previous.get("lockfiles", []) if isinstance(item, str))
    file_changes = {
        "manifestsAdded": sorted(manifests - previous_manifests),
        "manifestsRemoved": sorted(previous_manifests - manifests),
        "lockfilesAdded": sorted(lockfiles - previous_lockfiles),
        "lockfilesRemoved": sorted(previous_lockfiles - lockfiles),
    }
    changes = sorted(changes, key=lambda item: (item["changeType"], item.get("ecosystem", ""), item.get("name", ""), item.get("group", "")))
    total_change_count = len(changes) + sum(len(value) for value in file_changes.values())
    truncated = len(changes) > MAX_CHANGES
    changes = changes[:MAX_CHANGES]
    return {
        "baselineStatus": "available",
        "changeCount": total_change_count,
        "changes": changes,
        "fileChanges": file_changes,
        "truncated": truncated,
    }, findings


def _empty_comparison(status: str, explanation: str) -> dict[str, Any]:
    return {
        "baselineStatus": status,
        "changeCount": 0,
        "changes": [],
        "fileChanges": {"manifestsAdded": [], "manifestsRemoved": [], "lockfilesAdded": [], "lockfilesRemoved": []},
        "explanation": explanation,
        "truncated": False,
    }


def _change(change_type: str, entry: dict[str, Any], previous: str = "") -> dict[str, Any]:
    result = {
        "changeType": change_type,
        "ecosystem": entry.get("ecosystem", ""),
        "name": entry.get("name", ""),
        "group": entry.get("group", ""),
    }
    for key in ("requestedSpecification", "lockedVersion", "sourceType", "sourceIdentifier"):
        if entry.get(key):
            result[key] = entry[key]
    if previous:
        result["previousValue"] = _safe_text(previous, 300)
    return result


def _change_finding(finding_type: str, severity: str, entry: dict[str, Any], explanation: str, action: str) -> dict[str, Any]:
    finding = {
        "type": finding_type,
        "severity": severity,
        "explanation": explanation,
        "action": action,
        "ecosystem": entry.get("ecosystem", ""),
        "package": entry.get("name", ""),
        "dependencyGroup": entry.get("group", ""),
    }
    if entry.get("manifestPath") or entry.get("lockfilePath"):
        finding["path"] = entry.get("manifestPath") or entry.get("lockfilePath")
    return _compact(finding)


def _entry(ecosystem: str, name: str, group: str, *, direct: bool, **values: Any) -> dict[str, Any]:
    result = {
        "ecosystem": ecosystem,
        "name": name,
        "group": group,
        "sourceType": values.pop("sourceType", "unknown") or "unknown",
        "direct": direct,
        "optional": values.pop("optional", False) is True,
        "dev": values.pop("dev", False) is True,
        "peer": values.pop("peer", False) is True,
        "installScriptIndicator": values.pop("installScriptIndicator", False) is True,
    }
    result.update({key: value for key, value in values.items() if value not in (None, "", [], {})})
    if str(result.get("sourceIdentifier", "")).startswith("http:"):
        result["insecureHttp"] = True
    return _compact(result)


def _classify_node_spec(spec: str) -> tuple[str, str]:
    lower = spec.strip().lower()
    if lower.startswith("npm:"):
        return "registry", "npm alias"
    if lower.startswith("workspace:"):
        return "local", "workspace"
    if lower.startswith(("file:", "link:")) or lower.startswith(("./", "../", "/")):
        return "local", "local path"
    if lower.startswith(("git+", "git://", "github:", "gitlab:", "bitbucket:")) or re.match(r"^[^@\s]+@[^:\s]+:", spec):
        return "vcs", _safe_url_host(spec)
    if lower.startswith(("http://", "https://")):
        return "url", _safe_url_host(spec, include_scheme=True)
    if not spec.strip():
        return "unknown", ""
    return "registry", ""


def _classify_resolved_source(resolved: str, version: str, *, link: bool) -> tuple[str, str]:
    if link:
        return "local", "linked package"
    if resolved.startswith(("git+", "git://")):
        return "vcs", _safe_url_host(resolved)
    if resolved.startswith("http://"):
        return "url", _safe_url_host(resolved, include_scheme=True)
    if resolved.startswith("https://"):
        return "registry", _safe_url_host(resolved)
    if version.startswith(("file:", "link:")):
        return "local", "local path"
    return "registry", ""


def _classify_python_source(value: str, editable: bool = False) -> tuple[str, str]:
    lower = value.lower()
    if editable or lower.startswith(("file:", ".", "/", "\\")) or re.match(r"^[a-z]:[\\/]", lower):
        return "local", "local path"
    if lower.startswith(("git+", "hg+", "svn+", "bzr+")):
        return "vcs", _safe_url_host(value)
    if lower.startswith(("http://", "https://")):
        return "url", _safe_url_host(value, include_scheme=lower.startswith("http://"))
    return "registry", ""


def _classify_poetry_source(source: dict[str, Any]) -> tuple[str, str]:
    source_type = str(source.get("type", "")).lower()
    url = str(source.get("url", ""))
    if source_type in {"git", "hg", "svn"}:
        return "vcs", _safe_url_host(url)
    if source_type in {"directory", "file"}:
        return "local", "local path"
    if source_type == "legacy" and url:
        return "registry", _safe_url_host(url)
    if url:
        return "url", _safe_url_host(url, include_scheme=url.startswith("http://"))
    return "registry", ""


def _poetry_spec(value: Any) -> tuple[str, str, str]:
    if isinstance(value, str):
        return _safe_text(value, 300), "registry", ""
    if not isinstance(value, dict):
        return "", "unknown", ""
    for key, source_type in (("git", "vcs"), ("url", "url"), ("path", "local")):
        if isinstance(value.get(key), str):
            raw = value[key]
            identifier = "local path" if source_type == "local" else _safe_url_host(raw, include_scheme=raw.startswith("http://"))
            return _sanitize_spec(raw), source_type, identifier
    version = value.get("version")
    if isinstance(value.get("source"), str) and value["source"].strip():
        return _safe_text(version, 300), "unknown", "named source"
    return _safe_text(version, 300), "registry", ""


def _pipfile_spec(value: Any) -> tuple[str, str, str]:
    if isinstance(value, str):
        source_type, identifier = _classify_python_source(value)
        return _sanitize_spec(value), source_type, identifier
    if not isinstance(value, dict):
        return "", "unknown", ""
    for key, source_type in (("git", "vcs"), ("path", "local"), ("file", "local")):
        if isinstance(value.get(key), str):
            raw = value[key]
            identifier = "local path" if source_type == "local" else _safe_url_host(raw)
            return _sanitize_spec(raw), source_type, identifier
    version = value.get("version", "")
    if isinstance(value.get("index"), str) and value["index"].strip():
        return _safe_text(version, 300), "unknown", "named source"
    return _safe_text(version, 300), "registry", ""


def _sanitize_spec(value: Any) -> str:
    text = _safe_text(value, 500)
    if not text:
        return ""
    scp_match = re.match(r"^(?:[^@\s]+@)([^:\s]+):(.+)$", text)
    if scp_match:
        host = scp_match.group(1).lower()
        path = re.split(r"[?#]", scp_match.group(2), maxsplit=1)[0].lstrip("/")
        return _safe_text(f"vcs:{host}/{path}", 500)
    if "://" in text:
        return _sanitize_url(text)
    lower = text.lower()
    if lower.startswith(("file:", "link:")):
        prefix, local = text.split(":", 1)
        return f"{prefix.lower()}:{_sanitize_local_spec(local)}"
    if re.match(r"^[A-Za-z]:[\\/]", text) or text.startswith(("/", "\\", "../", "..\\")):
        return "local path"
    return text


def _sanitize_local_spec(value: str) -> str:
    normalized = value.replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", normalized) or normalized.startswith("/") or ".." in Path(normalized).parts:
        return "local path"
    return _safe_text(normalized, 300) or "local path"


def _sanitize_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname or ""
        if not hostname:
            return _safe_text(parsed.scheme, 20)
        port = f":{parsed.port}" if parsed.port else ""
        path = re.sub(r"/{2,}", "/", parsed.path or "")
        return urlunsplit((parsed.scheme.lower(), f"{hostname.lower()}{port}", path, "", ""))
    except (TypeError, ValueError):
        return "malformed remote source"


def _safe_url_host(value: str, *, include_scheme: bool = False) -> str:
    candidate = value
    for prefix in ("git+", "hg+", "svn+", "bzr+"):
        if candidate.startswith(prefix):
            candidate = candidate[len(prefix):]
    try:
        parsed = urlsplit(candidate)
        host = (parsed.hostname or "").lower()
        if host:
            if include_scheme:
                return f"{parsed.scheme.lower()}:{host}"
            return host
        if include_scheme and parsed.scheme.lower() in {"http", "https"}:
            return f"{parsed.scheme.lower()}:malformed"
    except ValueError:
        pass
    match = re.match(r"^(?:[^@\s]+@)?([^:\s]+):", candidate)
    return match.group(1).lower() if match else ""


def _sanitize_source_identifier(value: Any) -> str:
    text = _safe_text(value, 300)
    if not text:
        return ""
    if "://" in text or "@" in text or "?" in text or "#" in text:
        host = _safe_url_host(text, include_scheme=text.lower().startswith("http://"))
        return host or "redacted source"
    if re.match(r"^[A-Za-z]:[\\/]", text) or text.startswith(("/", "\\")):
        return "local path"
    return text


def _integrity_status(value: str) -> str:
    if not isinstance(value, str) or not value:
        return "missing"
    statuses = [_integrity_token_status(token) for token in value.split()]
    if not statuses:
        return "missing"
    if "malformed" in statuses:
        return "malformed"
    if "unsupported algorithm" in statuses:
        return "unsupported algorithm"
    return "valid"


def _integrity_token_status(value: str) -> str:
    parts = value.split("-", 1) if "-" in value else value.split(":", 1)
    if len(parts) != 2 or not parts[1].strip():
        return "malformed"
    algorithm = parts[0].lower()
    if algorithm not in SUPPORTED_INTEGRITY_ALGORITHMS:
        return "unsupported algorithm"
    payload = parts[1].strip()
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", payload):
        return "malformed"
    return "valid"


def _requirements_include(line: str) -> str:
    match = re.match(r"^(?:-r|--requirement)(?:=|\s+)(.+)$", line)
    return match.group(1).strip() if match else ""


def _is_requirements_path(lower_name: str, lower_parts: list[str]) -> bool:
    return (
        lower_name == "requirements.txt"
        or (lower_name.startswith("requirements-") and lower_name.endswith(".txt"))
        or ("requirements" in lower_parts[:-1] and lower_name.endswith(".txt"))
    )


def _node_name_from_lock_path(path: str, package: dict[str, Any]) -> str:
    marker = "node_modules/"
    if marker in path:
        tail = path.rsplit(marker, 1)[1].strip("/")
        parts = tail.split("/")
        return _normalize_node_name("/".join(parts[:2]) if parts[0].startswith("@") and len(parts) > 1 else parts[0])
    return _normalize_node_name(package["name"]) if isinstance(package.get("name"), str) else ""


def _is_root_node_package_path(path: str, name: str) -> bool:
    normalized = path.replace("\\", "/").strip("/").lower()
    return normalized == f"node_modules/{name.lower()}"


def _node_direct_group(name: str, groups: dict[str, dict[str, str]]) -> str:
    for group in DEPENDENCY_GROUPS:
        if name in groups.get(group, {}):
            return group
    return "dependencies"


def _string_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {
        _normalize_node_name(str(name)): _sanitize_spec(spec)
        for name, spec in value.items()
        if isinstance(name, str) and isinstance(spec, str)
    }


def _specs_reliably_comparable(left: str, right: str) -> bool:
    ambiguous = ("workspace:", "file:", "link:", "npm:", "git+", "http://", "https://")
    return not left.startswith(ambiguous) and not right.startswith(ambiguous)


def _normalize_node_name(name: str) -> str:
    return name.strip().lower()[:214]


def _normalize_python_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())[:214]


def _name_from_egg(value: str) -> str:
    match = re.search(r"[#&]egg=([A-Za-z0-9._-]+)", value)
    return _normalize_python_name(match.group(1)) if match else ""


def _archive_name(value: str) -> str:
    sanitized = _sanitize_url(value) if "://" in value else value
    name = Path(urlsplit(sanitized).path).name
    name = re.sub(r"(?:\.tar\.gz|\.whl|\.zip)$", "", name, flags=re.IGNORECASE)
    match = re.match(r"([A-Za-z0-9._-]+?)(?:-\d|$)", name)
    return _normalize_python_name(match.group(1)) if match else ""


def _nested_dict(value: dict[str, Any], *keys: str) -> dict[str, Any]:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict):
            return {}
        current = current.get(key)
    return current if isinstance(current, dict) else {}


def _requirements_self_lock(entry: dict[str, Any]) -> bool:
    return entry.get("group") == "requirements" and entry.get("requestedSpecification", "").startswith("==")


def _lock_matches_direct(direct: dict[str, Any], locked: dict[str, Any]) -> bool:
    if direct.get("name") != locked.get("name"):
        return False
    manifest = Path(str(direct.get("manifestPath", "")))
    lockfile = Path(str(locked.get("lockfilePath", "")))
    if manifest.parent != lockfile.parent:
        return False
    manifest_name = manifest.name.lower()
    lock_name = lockfile.name.lower()
    if _is_requirements_path(manifest_name, [part.lower() for part in manifest.parts]):
        return manifest.as_posix().lower() == lockfile.as_posix().lower()
    if manifest_name == "pipfile":
        return lock_name == "pipfile.lock"
    if manifest_name == "pyproject.toml":
        return lock_name == "poetry.lock"
    return False


def _node_lock_matches_direct(direct: dict[str, Any], locked: dict[str, Any]) -> bool:
    if direct.get("name") != locked.get("name"):
        return False
    manifest = Path(str(direct.get("manifestPath", "")))
    lockfile = Path(str(locked.get("lockfilePath", "")))
    return (
        manifest.name.lower() == "package.json"
        and lockfile.name.lower() in NODE_LOCKFILES
        and manifest.parent == lockfile.parent
    )


def _has_sibling(path: str, candidates: Any, names: set[str]) -> bool:
    parent = Path(path).parent
    return any(Path(candidate).parent == parent and Path(candidate).name.lower() in names for candidate in candidates)


def _corresponding_lock_present(direct: dict[str, Any], lockfiles: set[str]) -> bool:
    return any(
        _lock_matches_direct(direct, {"name": direct.get("name"), "lockfilePath": path})
        for path in lockfiles
    )


def _package_manager_name(value: str) -> str:
    name = value.strip().rsplit("@", 1)[0].strip().lower()
    return _safe_text(name, 60) if re.fullmatch(r"[a-z0-9._-]+", name) else ""


def _exact_requested_version(value: str) -> str:
    text = value.strip()
    if text.startswith("==") and not any(marker in text for marker in (",", ";", "*")):
        return text[2:].strip()
    if re.fullmatch(r"\d+(?:\.\d+)*(?:[-+][A-Za-z0-9._-]+)?", text):
        return text
    return ""


def _direct_key(entry: dict[str, Any]) -> tuple[str, str, str]:
    return (str(entry.get("ecosystem", "")), str(entry.get("name", "")), str(entry.get("group", "")))


def _locked_key(entry: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(entry.get("ecosystem", "")),
        str(entry.get("name", "")),
        str(entry.get("lockedVersion", "")),
        str(entry.get("sourceType", "")),
        str(entry.get("sourceIdentifier", "")),
    )


def _entry_sort_key(entry: dict[str, Any]) -> tuple[Any, ...]:
    return (
        entry.get("ecosystem", ""),
        entry.get("name", ""),
        0 if entry.get("direct") else 1,
        entry.get("group", ""),
        entry.get("lockedVersion", ""),
        entry.get("sourceType", ""),
    )


def _finding_sort_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    order = {"high": 0, "medium": 1, "low": 2, "none": 3}
    return (
        order.get(finding.get("severity", "low"), 4),
        finding.get("type", ""),
        finding.get("ecosystem", ""),
        finding.get("package", ""),
        finding.get("path", ""),
    )


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, ...]] = set()
    result: list[dict[str, Any]] = []
    for finding in findings:
        key = _finding_identity(finding)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result


def _finding_identity(finding: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(finding.get(field, "")) for field in (
        "type", "severity", "path", "ecosystem", "package", "dependencyGroup", "sourceIdentifier",
    ))


def _highest_severity(findings: list[dict[str, Any]]) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    return max((finding.get("severity", "low") for finding in findings), key=lambda value: order.get(value, 0), default="none")


def _safe_relative_path(value: str) -> str:
    text = str(value or "").replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", text) or text.startswith("/") or ".." in Path(text).parts:
        return Path(text).name
    return _safe_text(text, 500)


def _safe_text(value: Any, limit: int) -> str:
    if not isinstance(value, (str, int, float, bool)):
        return ""
    return " ".join(str(value).split())[:limit]


def _compact(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _compact(item) for key, item in value.items() if item is not None and item != ""}
    if isinstance(value, list):
        return [_compact(item) for item in value if item is not None]
    if isinstance(value, tuple):
        return [_compact(item) for item in value]
    if isinstance(value, (str, int, float, bool)):
        return value
    return _safe_text(value, 200)
