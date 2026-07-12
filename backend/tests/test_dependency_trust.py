from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from app import database, dependency_trust, main, scanner
from app.scanner import scan_project
from app.schemas import ProjectPathRequest


class DependencyTrustScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(self.temporary_directory.cleanup)
        self.project = Path(self.temporary_directory.name) / "project"
        self.project.mkdir()

    def write_json(self, name: str, value: object) -> None:
        (self.project / name).write_text(json.dumps(value), encoding="utf-8")

    def test_node_lock_v3_normalizes_sources_integrity_scripts_and_consistency(self) -> None:
        self.write_json("package.json", {
            "packageManager": "npm@10.0.0",
            "dependencies": {"alpha": "^1.0.0", "alias": "npm:alpha@^1", "local": "file:vendor/local", "workspace": "workspace:*", "linked": "link:vendor/linked"},
            "devDependencies": {"tool": "https://downloads.example/tool.tgz?token=secret"},
            "bundledDependencies": ["alpha"],
            "overrides": {"alpha": "1.2.0"},
        })
        self.write_json("package-lock.json", {
            "name": "fixture",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "dependencies": {"alpha": "^1.0.0", "alias": "npm:alpha@^1", "local": "file:vendor/local", "workspace": "workspace:*", "linked": "link:vendor/linked"},
                    "devDependencies": {"tool": "https://downloads.example/tool.tgz?token=secret"},
                },
                "node_modules/alpha": {"version": "1.2.0", "resolved": "https://registry.npmjs.org/alpha/-/alpha-1.2.0.tgz", "integrity": "sha512-YWJj"},
                "node_modules/alias": {"name": "alias", "version": "1.2.0", "resolved": "https://registry.npmjs.org/alpha/-/alpha-1.2.0.tgz", "integrity": "sha512-YWJj"},
                "node_modules/local": {"version": "file:vendor/local", "link": True},
                "node_modules/workspace": {"version": "workspace:*", "link": True},
                "node_modules/linked": {"version": "link:vendor/linked", "link": True},
                "node_modules/tool": {"version": "2.0.0", "resolved": "https://downloads.example/tool.tgz?token=secret", "integrity": "sha512-YWJj", "hasInstallScript": True, "dev": True},
            },
        })

        result = scan_project(self.project)
        trust = result["dependencyTrust"]

        self.assertEqual(trust["status"], "complete")
        self.assertEqual(trust["ecosystems"], ["node"])
        self.assertEqual(trust["directDependencyCount"], 6)
        self.assertEqual(trust["lockedDependencyCount"], 6)
        self.assertEqual(trust["integrityCoverage"], {"total": 3, "present": 3, "missing": 0})
        self.assertEqual(trust["installScriptIndicatorCount"], 1)
        self.assertTrue(any(entry["sourceType"] == "local" for entry in trust["entries"]))
        self.assertTrue(any(finding["type"] == "dependency-install-script-indicator" for finding in result["findings"]))
        self.assertTrue(any(finding["type"] == "dependency-bundled-dependency" for finding in result["findings"]))
        self.assertTrue(any(finding["type"] == "dependency-override-declaration" for finding in result["findings"]))
        serialized = json.dumps(trust, sort_keys=True)
        self.assertNotIn("token=secret", serialized)
        self.assertNotIn(str(self.project), serialized)

    def test_node_v1_and_v2_are_supported_without_false_high_for_multiple_versions(self) -> None:
        self.write_json("package.json", {"dependencies": {"alpha": "^1"}})
        self.write_json("package-lock.json", {
            "lockfileVersion": 1,
            "dependencies": {
                "alpha": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz",
                    "integrity": "sha512-YWJj",
                    "dependencies": {"alpha": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/alpha/-/alpha-2.0.0.tgz", "integrity": "sha512-ZGVm"}},
                }
            },
        })
        first = scan_project(self.project)["dependencyTrust"]
        self.assertEqual(first["status"], "incomplete")
        self.assertTrue(any(item["reason"] == "npm-v1-root-evidence-limited" for item in first["limitations"]))
        self.assertEqual(sum(entry["name"] == "alpha" for entry in first["entries"]), 2)
        direct_alpha = next(entry for entry in first["entries"] if entry["name"] == "alpha" and entry["direct"])
        self.assertEqual(direct_alpha["lockedVersion"], "1.0.0")
        self.assertFalse(any(finding["severity"] == "high" for finding in scan_project(self.project)["findings"] if finding["type"].startswith("dependency-")))

        self.write_json("package-lock.json", {
            "lockfileVersion": 2,
            "packages": {
                "": {"dependencies": {"alpha": "^1"}},
                "node_modules/alpha": {"version": "1.1.0", "resolved": "https://registry.npmjs.org/alpha/-/alpha-1.1.0.tgz", "integrity": "sha512-YWJj"},
            },
        })
        second = scan_project(self.project)["dependencyTrust"]
        self.assertEqual(second["status"], "complete")
        self.assertEqual(second["lockedDependencyCount"], 1)

    def test_node_alias_identity_privacy_and_malformed_packages_are_conservative(self) -> None:
        self.write_json("package.json", {
            "dependencies": {
                "alias-name": "npm:actual-name@1.0.0",
                "private-vcs": "developer@github.com:org/private.git?token=hidden#main",
                "@scope/tool": "1.0.0",
            },
        })
        self.write_json("package-lock.json", {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"alias-name": "npm:actual-name@1.0.0", "private-vcs": "developer@github.com:org/private.git?token=hidden#main", "@scope/tool": "1.0.0"}},
                "node_modules/alias-name": {"name": "actual-name", "version": "1.0.0", "resolved": "https://registry.npmjs.org/actual-name/-/actual-name-1.0.0.tgz", "integrity": "sha512-AAAA"},
                "node_modules/private-vcs": {"version": "1.0.0", "resolved": "git+https://github.com/org/private.git"},
                "node_modules/@scope/tool": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/@scope/tool/-/tool-1.0.0.tgz", "integrity": "sha512-BBBB"},
            },
        })

        result = scan_project(self.project)
        alias = next(entry for entry in result["dependencyTrust"]["entries"] if entry["name"] == "alias-name")
        self.assertEqual(alias["lockedVersion"], "1.0.0")
        self.assertFalse(any(finding["type"] == "dependency-missing-from-lock" and finding.get("package") == "alias-name" for finding in result["findings"]))
        serialized = json.dumps(result["dependencyTrust"])
        self.assertNotIn("developer@", serialized)
        self.assertNotIn("token=hidden", serialized)

        lock = json.loads((self.project / "package-lock.json").read_text(encoding="utf-8"))
        lock["packages"]["node_modules/broken"] = "not-an-object"
        self.write_json("package-lock.json", lock)
        malformed = scan_project(self.project)
        self.assertEqual(malformed["dependencyTrust"]["status"], "malformed")
        self.assertNotIn("package-lock.json", malformed["reviewedFiles"])

        self.write_json("package-lock.json", {"lockfileVersion": 3, "packages": {"node_modules/alias-name": {"version": "1.0.0"}}})
        rootless = scan_project(self.project)
        self.assertEqual(rootless["dependencyTrust"]["status"], "incomplete")
        self.assertTrue(any(item["reason"] == "npm-root-package-unavailable" for item in rootless["dependencyTrust"]["limitations"]))

    def test_node_malformed_unsupported_missing_and_source_findings(self) -> None:
        self.write_json("package.json", {"dependencies": {"missing": "^1", "gitdep": "git+https://user:secret@github.com/org/repo.git?token=x", "plain": "http://example.test/plain.tgz"}})
        self.write_json("package-lock.json", {"lockfileVersion": 9, "packages": {}})
        result = scan_project(self.project)
        types = {finding["type"] for finding in result["findings"]}
        self.assertIn("dependency-lockfile-version-unsupported", types)
        self.assertIn("dependency-vcs-source", types)
        self.assertIn("dependency-insecure-http-source", types)
        self.assertFalse(result["scanCompleteness"]["complete"])
        self.assertGreater(result["scanCompleteness"]["dependencyAnalysisFailureCount"], 0)

        (self.project / "package-lock.json").write_text("{", encoding="utf-8")
        malformed = scan_project(self.project)
        self.assertEqual(malformed["dependencyTrust"]["status"], "malformed")
        self.assertNotIn("package-lock.json", malformed["reviewedFiles"])
        self.assertTrue(any(finding["type"] == "dependency-lockfile-parse-error" for finding in malformed["findings"]))

    def test_node_consistency_integrity_and_baseline_changes(self) -> None:
        self.write_json("package.json", {"dependencies": {"alpha": "1.0.0", "missing": "2.0.0"}})
        self.write_json("package-lock.json", {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"alpha": "1.0.0", "extra": "1.0.0"}},
                "node_modules/alpha": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz", "integrity": "sha512-AAAA"},
                "node_modules/extra": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/extra/-/extra-1.0.0.tgz"},
                "node_modules/transitive": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/transitive/-/transitive-1.0.0.tgz", "integrity": "sha512-CCCC"},
            },
        })
        first = scan_project(self.project)
        first_types = {finding["type"] for finding in first["findings"]}
        self.assertIn("dependency-missing-from-lock", first_types)
        self.assertIn("dependency-unexpected-lock-entry", first_types)
        self.assertIn("dependency-integrity-missing", first_types)

        lock = json.loads((self.project / "package-lock.json").read_text(encoding="utf-8"))
        lock["packages"]["node_modules/alpha"]["integrity"] = "sha512-BBBB"
        lock["packages"]["node_modules/transitive"]["version"] = "2.0.0"
        self.write_json("package-lock.json", lock)
        second = scan_project(self.project, previous_dependency_trust=first["dependencyTrust"])
        changed = next(finding for finding in second["findings"] if finding["type"] == "dependency-integrity-changed")
        self.assertEqual(changed["severity"], "high")
        self.assertEqual(second["dependencyTrust"]["comparison"]["baselineStatus"], "available")
        change_types = {change["changeType"] for change in second["dependencyTrust"]["comparison"]["changes"]}
        self.assertIn("locked-added", change_types)
        self.assertIn("locked-removed", change_types)

    def test_python_requirements_sources_hashes_includes_and_cycles(self) -> None:
        requirements = self.project / "requirements"
        requirements.mkdir()
        (requirements / "extra.txt").write_text("urllib3==2.2.0\n", encoding="utf-8")
        (self.project / "requirements.txt").write_text(
            "requests==2.31.0 --hash=sha256:abc\n"
            "flask>=2\n"
            "demo @ git+https://user:secret@github.com/org/repo.git?token=x\n"
            "archive @ http://example.test/archive.whl?token=x\n"
            "local @ file:vendor/local\n"
            "-r requirements/extra.txt\n",
            encoding="utf-8",
        )
        result = scan_project(self.project)
        trust = result["dependencyTrust"]
        types = {finding["type"] for finding in result["findings"]}
        self.assertEqual(trust["ecosystems"], ["python"])
        self.assertIn("dependency-unpinned", types)
        self.assertIn("dependency-vcs-source", types)
        self.assertIn("dependency-insecure-http-source", types)
        self.assertIn("dependency-local-source", types)
        self.assertIn("requirements/extra.txt", trust["analyzedFiles"])
        serialized = json.dumps(trust)
        self.assertNotIn("user:secret", serialized)
        self.assertNotIn("token=x", serialized)

        (requirements / "extra.txt").write_text("-r cycle.txt\n", encoding="utf-8")
        (requirements / "cycle.txt").write_text("-r extra.txt\n", encoding="utf-8")
        cycled = scan_project(self.project)
        self.assertFalse(cycled["scanCompleteness"]["complete"])
        self.assertTrue(any(item["reason"] == "requirements-include-cycle" for item in cycled["dependencyTrust"]["limitations"]))

        (self.project / "requirements.txt").write_text("-r ../outside.txt\n", encoding="utf-8")
        unsafe = scan_project(self.project)
        self.assertTrue(any(item["reason"] == "unsafe-requirements-include" for item in unsafe["dependencyTrust"]["limitations"]))

    def test_requirements_continuations_markers_options_and_local_paths_are_conservative(self) -> None:
        continued_requirement = "requests==2.31.0 " + "\\" + "\n    --hash=sha256:abc\n"
        (self.project / "requirements.txt").write_text(
            continued_requirement
            + "demo[extra]>=1; python_version < '3.12'\n"
            "localpkg @ file:C:\\Users\\private-user\\artifact.whl\n"
            "--index-url https://user:secret@packages.example/simple?token=hidden\n",
            encoding="utf-8",
        )

        result = scan_project(self.project)
        trust = result["dependencyTrust"]

        self.assertEqual(trust["status"], "incomplete")
        requests = next(entry for entry in trust["entries"] if entry["name"] == "requests" and entry["direct"])
        self.assertTrue(requests["integrityPresent"])
        demo = next(entry for entry in trust["entries"] if entry["name"] == "demo")
        self.assertIn("python_version", demo["requestedSpecification"])
        local = next(entry for entry in trust["entries"] if entry["name"] == "localpkg")
        self.assertEqual(local["requestedSpecification"], "file:local path")
        serialized = json.dumps(result)
        self.assertNotIn("private-user", serialized)
        self.assertNotIn("user:secret", serialized)
        self.assertNotIn("token=hidden", serialized)
        self.assertTrue(any(item["reason"] == "unsupported-requirements-construct" for item in trust["limitations"]))

    def test_python_lock_matching_never_crosses_package_manager_or_directory(self) -> None:
        (self.project / "Pipfile").write_text("[packages]\nshared = \"==1.0.0\"\n", encoding="utf-8")
        self.write_json("Pipfile.lock", {"default": {"other": {"version": "==1.0.0", "hashes": ["sha256:abc"]}}, "develop": {}})
        (self.project / "pyproject.toml").write_text("[tool.poetry.dependencies]\npython = \"^3.11\"\nshared = \"2.0.0\"\n", encoding="utf-8")
        (self.project / "poetry.lock").write_text(
            "[[package]]\nname = \"shared\"\nversion = \"2.0.0\"\noptional = false\nfiles = [{file = \"shared.whl\", hash = \"sha256:def\"}]\n",
            encoding="utf-8",
        )

        result = scan_project(self.project)
        missing = [finding for finding in result["findings"] if finding["type"] == "dependency-missing-from-lock"]
        self.assertTrue(any(finding.get("package") == "shared" and finding.get("path") == "Pipfile" for finding in missing))
        pipfile_entry = next(entry for entry in result["dependencyTrust"]["entries"] if entry.get("manifestPath") == "Pipfile" and entry["name"] == "shared")
        self.assertNotIn("lockedVersion", pipfile_entry)

    def test_invalid_integrity_change_is_not_escalated_as_verified_identity_change(self) -> None:
        self.write_json("package.json", {"dependencies": {"alpha": "1.0.0"}})
        self.write_json("package-lock.json", {"lockfileVersion": 3, "packages": {"": {"dependencies": {"alpha": "1.0.0"}}, "node_modules/alpha": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz", "integrity": "bad-one"}}})
        first = scan_project(self.project)
        lock = json.loads((self.project / "package-lock.json").read_text(encoding="utf-8"))
        lock["packages"]["node_modules/alpha"]["integrity"] = "bad-two"
        self.write_json("package-lock.json", lock)

        second = scan_project(self.project, previous_dependency_trust=first["dependencyTrust"])

        self.assertFalse(any(finding["type"] == "dependency-integrity-changed" for finding in second["findings"]))
        self.assertTrue(any(finding["type"] == "dependency-integrity-malformed" for finding in second["findings"]))

    def test_multiple_node_contexts_do_not_cross_merge_lock_entries(self) -> None:
        self.write_json("package.json", {"dependencies": {"alpha": "1.0.0"}})
        self.write_json("package-lock.json", {"lockfileVersion": 3, "packages": {"": {"dependencies": {"alpha": "1.0.0"}}, "node_modules/alpha": {"version": "1.0.0", "integrity": "sha512-AAAA"}}})
        nested = self.project / "nested"
        nested.mkdir()
        (nested / "package.json").write_text(json.dumps({"dependencies": {"alpha": "2.0.0"}}), encoding="utf-8")
        (nested / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {"dependencies": {"alpha": "2.0.0"}}, "node_modules/alpha": {"version": "2.0.0", "integrity": "sha512-BBBB"}}}), encoding="utf-8")

        trust = scan_project(self.project)["dependencyTrust"]

        direct = [entry for entry in trust["entries"] if entry["name"] == "alpha" and entry["direct"]]
        self.assertEqual({(entry["manifestPath"], entry["lockedVersion"]) for entry in direct}, {("package.json", "1.0.0"), ("nested/package.json", "2.0.0")})
        self.assertEqual(trust["status"], "incomplete")
        self.assertTrue(any(item["reason"] == "multiple-node-metadata-contexts" for item in trust["limitations"]))

    def test_pyproject_poetry_and_pipenv_metadata(self) -> None:
        (self.project / "pyproject.toml").write_text(
            "[project]\ndependencies = [\"requests>=2\", \"click==8.1.7\"]\n"
            "[project.optional-dependencies]\ndev = [\"pytest>=8\"]\n"
            "[tool.poetry.dependencies]\npython = \"^3.11\"\npendulum = { git = \"https://github.com/org/repo.git\" }\n",
            encoding="utf-8",
        )
        (self.project / "poetry.lock").write_text(
            "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\noptional = false\nfiles = [{file = \"requests.whl\", hash = \"sha256:abc\"}]\n"
            "[[package]]\nname = \"click\"\nversion = \"8.1.7\"\noptional = false\nfiles = [{file = \"click.whl\", hash = \"sha256:def\"}]\n",
            encoding="utf-8",
        )
        (self.project / "Pipfile").write_text("[packages]\nflask = \"==3.0.0\"\n[dev-packages]\nruff = \"*\"\n", encoding="utf-8")
        self.write_json("Pipfile.lock", {"default": {"flask": {"version": "==3.0.0", "hashes": ["sha256:abc"]}}, "develop": {"ruff": {"version": "==0.5.0", "hashes": ["sha256:def"]}}})

        trust = scan_project(self.project)["dependencyTrust"]

        self.assertEqual(trust["status"], "complete")
        self.assertIn("poetry", trust["packageManagers"])
        self.assertIn("pipenv", trust["packageManagers"])
        self.assertTrue(any(entry["group"] == "optional:dev" for entry in trust["entries"]))
        self.assertTrue(any(entry["group"] == "pipenv-dev" for entry in trust["entries"]))

    def test_structurally_invalid_python_fields_cannot_render_complete(self) -> None:
        (self.project / "pyproject.toml").write_text("[project]\ndependencies = \"requests\"\n", encoding="utf-8")
        self.write_json("Pipfile.lock", {"default": [], "develop": {}})

        result = scan_project(self.project)

        self.assertEqual(result["dependencyTrust"]["status"], "malformed")
        self.assertNotIn("pyproject.toml", result["reviewedFiles"])
        self.assertNotIn("Pipfile.lock", result["reviewedFiles"])
        self.assertGreaterEqual(sum(finding["type"] in {"dependency-manifest-parse-error", "dependency-lockfile-parse-error"} for finding in result["findings"]), 2)

    def test_malformed_python_metadata_oversized_and_linked_inputs_are_not_reviewed(self) -> None:
        (self.project / "pyproject.toml").write_text("[project\n", encoding="utf-8")
        malformed = scan_project(self.project)
        self.assertEqual(malformed["dependencyTrust"]["status"], "malformed")
        self.assertNotIn("pyproject.toml", malformed["reviewedFiles"])

        (self.project / "pyproject.toml").write_text("[project]\ndependencies=[]\n" + ("#x" * 50), encoding="utf-8")
        valid = scan_project(self.project)
        with patch.object(scanner, "MAX_DEPENDENCY_BYTES", 32), patch.object(dependency_trust, "MAX_DEPENDENCY_BYTES", 32):
            oversized = scan_project(self.project, previous_dependency_trust=valid["dependencyTrust"])
        self.assertFalse(oversized["scanCompleteness"]["complete"])
        self.assertNotIn("pyproject.toml", oversized["reviewedFiles"])
        self.assertTrue(any(
            change["changeType"] == "analysis-status-changed"
            for change in oversized["dependencyTrust"]["comparison"]["changes"]
        ))

        with patch.object(scanner, "is_reparse_point_or_symlink", side_effect=lambda path: path.name == "pyproject.toml"):
            linked = scan_project(self.project)
        self.assertTrue(any(finding["type"] == "symlink-or-reparse-point" for finding in linked["findings"]))
        self.assertNotIn("pyproject.toml", linked["reviewedFiles"])

        with patch.object(scanner, "has_multiple_hardlinks", side_effect=lambda path: path.name == "pyproject.toml"):
            hardlinked = scan_project(self.project)
        self.assertTrue(any(finding["type"] == "hardlink" and finding["path"] == "pyproject.toml" for finding in hardlinked["findings"]))
        self.assertNotIn("pyproject.toml", hardlinked["reviewedFiles"])

    def test_dependency_read_failure_after_general_inspection_is_incomplete_and_not_reviewed(self) -> None:
        target = self.project / "requirements.txt"
        target.write_text("requests==2.31.0\n", encoding="utf-8")
        original_open = Path.open
        target_reads = 0

        def open_path(path: Path, *args: object, **kwargs: object):
            nonlocal target_reads
            if path == target and args and args[0] == "rb":
                target_reads += 1
                if target_reads == 2:
                    raise OSError(5, "simulated read failure")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", autospec=True, side_effect=open_path):
            result = scan_project(self.project)

        self.assertEqual(target_reads, 2)
        self.assertEqual(result["dependencyTrust"]["status"], "incomplete")
        self.assertNotIn("requirements.txt", result["reviewedFiles"])
        self.assertEqual(result["scanCompleteness"]["dependencyAnalysisFailureCount"], 1)
        self.assertTrue(any(finding["type"] == "dependency-analysis-incomplete" for finding in result["findings"]))

    def test_dependency_inventory_limit_marks_general_scan_incomplete(self) -> None:
        (self.project / "requirements.txt").write_text("alpha==1.0.0\nbeta==2.0.0\n", encoding="utf-8")

        with patch.object(dependency_trust, "MAX_ENTRIES", 1):
            result = scan_project(self.project)

        self.assertEqual(result["dependencyTrust"]["status"], "incomplete")
        self.assertEqual(result["dependencyTrust"]["completenessGapCount"], 1)
        self.assertFalse(result["scanCompleteness"]["complete"])
        self.assertEqual(result["scanCompleteness"]["dependencyAnalysisFailureCount"], 1)


class DependencyTrustPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(self.temporary_directory.cleanup)
        self.base = Path(self.temporary_directory.name)
        self.root = self.base / "workspace"
        self.project = self.root / "project"
        self.project.mkdir(parents=True)
        self.database_path = self.base / "codexforge.db"
        patches = [
            patch.object(database, "DB_PATH", self.database_path),
            patch.object(database, "get_connection", side_effect=self.connection),
            patch.object(main, "get_connection", side_effect=self.connection),
        ]
        for active in patches:
            active.start()
            self.addCleanup(active.stop)
        database.init_db()
        database.set_setting(database.WORKSPACE_ROOT_SETTING, str(self.root))
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO projects (path, name, description, project_type, created_at) VALUES (?, 'project', '', '', 'now')",
                (str(self.project),),
            )
        (self.project / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

    @contextmanager
    def connection(self):
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def test_current_history_comparison_and_legacy_round_trip(self) -> None:
        first = main.run_scan(ProjectPathRequest(project_path=str(self.project)))
        self.assertEqual(first["dependencyTrust"]["status"], "complete")
        self.assertEqual(first["dependencyTrust"]["comparison"]["baselineStatus"], "unavailable")

        (self.project / "requirements.txt").write_text("requests==2.32.0\nnewpkg>=1\n", encoding="utf-8")
        second = main.run_scan(ProjectPathRequest(project_path=str(self.project)))
        self.assertEqual(second["dependencyTrust"]["comparison"]["baselineStatus"], "available")
        self.assertGreater(second["dependencyTrust"]["changeCount"], 0)
        history = main.scan_history(str(self.project))["scans"]
        self.assertEqual(history[0]["dependencyTrust"], second["dependencyTrust"])

        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO scans (project_path, scan_date, overall_risk, findings_json) VALUES (?, 'legacy', 'none', '[]')",
                (str(self.project),),
            )
        legacy = next(scan for scan in main.scan_history(str(self.project))["scans"] if scan["scan_date"] == "legacy")
        self.assertIsNone(legacy["dependencyTrust"])

        (self.project / "requirements.txt").write_text("requests==2.33.0\nnewpkg>=1\n", encoding="utf-8")
        after_legacy = main.run_scan(ProjectPathRequest(project_path=str(self.project)))
        self.assertEqual(after_legacy["dependencyTrust"]["comparison"]["baselineStatus"], "available")
        version_change = next(
            change for change in after_legacy["dependencyTrust"]["comparison"]["changes"]
            if change["changeType"] == "version-changed" and change["name"] == "requests"
        )
        self.assertEqual(version_change["previousValue"], "2.32.0")

        project_payload = main.list_projects()["projects"][0]
        self.assertNotIn("entries", project_payload)

    def test_dependency_baseline_never_crosses_projects(self) -> None:
        main.run_scan(ProjectPathRequest(project_path=str(self.project)))
        other = self.root / "other"
        other.mkdir()
        (other / "requirements.txt").write_text("requests==9.9.9\n", encoding="utf-8")
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO projects (path, name, description, project_type, created_at) VALUES (?, 'other', '', '', 'now')",
                (str(other),),
            )

        result = main.run_scan(ProjectPathRequest(project_path=str(other)))

        self.assertEqual(result["dependencyTrust"]["comparison"]["baselineStatus"], "unavailable")
        self.assertEqual(result["dependencyTrust"]["changeCount"], 0)

    def test_sensitive_dependency_sources_remain_sanitized_through_history(self) -> None:
        (self.project / "requirements.txt").write_text(
            "privatepkg @ https://api-user:api-pass@packages.example/private.whl?token=history-secret#fragment\n",
            encoding="utf-8",
        )

        current = main.run_scan(ProjectPathRequest(project_path=str(self.project)))
        history = main.scan_history(str(self.project))["scans"]
        serialized = json.dumps({"current": current["dependencyTrust"], "history": history[0]["dependencyTrust"], "findings": history[0]["findings"]})

        for secret in ("api-user", "api-pass", "history-secret", "fragment"):
            self.assertNotIn(secret, serialized)
        self.assertIn("packages.example", serialized)


if __name__ == "__main__":
    unittest.main()
