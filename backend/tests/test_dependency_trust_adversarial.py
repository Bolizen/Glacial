from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from app import dependency_trust
from app.scanner import scan_project


class DependencyTrustAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(self.temporary_directory.cleanup)
        self.project = Path(self.temporary_directory.name) / "project"
        self.project.mkdir()

    def write_json(self, name: str, value: object) -> None:
        path = self.project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_missing_metadata_pairs_and_unsupported_pyproject_sections_are_incomplete(self) -> None:
        self.write_json("package.json", {"dependencies": {"alpha": "1.0.0"}})
        node = scan_project(self.project)
        self.assertEqual(node["dependencyTrust"]["status"], "incomplete")
        self.assertIn("package.json", node["dependencyTrust"]["failedFiles"])
        self.assertNotIn("package.json", node["reviewedFiles"])

        (self.project / "package.json").unlink()
        (self.project / "pyproject.toml").write_text(
            "[build-system]\nrequires = [\"setuptools>=70\"]\n"
            "[dependency-groups]\ndev = [\"pytest>=8\"]\n",
            encoding="utf-8",
        )
        python = scan_project(self.project)
        reasons = {item["reason"] for item in python["dependencyTrust"]["limitations"]}
        self.assertEqual(python["dependencyTrust"]["status"], "incomplete")
        self.assertIn("pyproject-build-requires-unsupported", reasons)
        self.assertIn("pyproject-dependency-groups-unsupported", reasons)
        self.assertNotIn("pyproject.toml", python["reviewedFiles"])

    def test_custom_registry_is_low_review_evidence_not_direct_url_risk(self) -> None:
        self.write_json("package.json", {"dependencies": {"alpha": "1.0.0"}})
        self.write_json("package-lock.json", {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"alpha": "1.0.0"}},
                "node_modules/alpha": {
                    "version": "1.0.0",
                    "resolved": "https://registry.corp.example/alpha/-/alpha-1.0.0.tgz",
                    "integrity": "sha512-AAAA",
                },
            },
        })

        result = scan_project(self.project)
        dependency_findings = [finding for finding in result["findings"] if finding["type"].startswith("dependency-")]

        self.assertEqual(result["dependencyTrust"]["status"], "complete")
        self.assertEqual({finding["type"] for finding in dependency_findings}, {"dependency-resolved-host-anomaly"})
        self.assertTrue(all(finding["severity"] == "low" for finding in dependency_findings))

    def test_sensitive_sources_are_absent_and_values_are_bounded(self) -> None:
        long_path = "a" * 2_000
        dependencies = {
            "encoded": "git+https://user%40mail:pa%3Ass@github.com/org/repo.git?token=QUERY_SECRET#FRAGMENT_SECRET",
            "scp": "private-user@github.com:org/repo.git?access=ACCESS_SECRET#main",
            "windows": "file:C:\\Users\\SensitiveUser\\private-package",
            "posix": "file:/home/SensitiveUser/private-package",
            "remote": f"https://url-user:url-pass@example.com/{long_path}?token=LONG_SECRET#fragment",
        }
        self.write_json("package.json", {"dependencies": dependencies})
        packages = {"": {"dependencies": dependencies}}
        for name in dependencies:
            packages[f"node_modules/{name}"] = {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
                "integrity": "sha512-AAAA",
            }
        self.write_json("package-lock.json", {"lockfileVersion": 3, "packages": packages})

        result = scan_project(self.project)
        serialized = json.dumps({"trust": result["dependencyTrust"], "findings": result["findings"]})

        for secret in ("user%40mail", "pa%3Ass", "QUERY_SECRET", "FRAGMENT_SECRET", "private-user", "ACCESS_SECRET", "SensitiveUser", "url-user", "url-pass", "LONG_SECRET"):
            self.assertNotIn(secret, serialized)
        self.assertNotIn(str(self.project), serialized)
        self.assertLessEqual(max(len(entry.get("requestedSpecification", "")) for entry in result["dependencyTrust"]["entries"]), 500)
        self.assertLessEqual(max(len(entry.get("sourceIdentifier", "")) for entry in result["dependencyTrust"]["entries"]), 200)

    def test_file_inventory_and_requirements_depth_are_bounded(self) -> None:
        requirements = self.project / "requirements"
        requirements.mkdir()
        for index in range(6):
            (requirements / f"req-{index}.txt").write_text(f"package-{index}==1.0.0\n", encoding="utf-8")

        with patch.object(dependency_trust, "MAX_DEPENDENCY_FILES", 3):
            limited = scan_project(self.project)

        self.assertEqual(limited["dependencyTrust"]["status"], "incomplete")
        self.assertEqual(len(limited["dependencyTrust"]["entries"]), 3)
        self.assertEqual(limited["dependencyTrust"]["completenessGapCount"], 3)
        self.assertEqual(sum(path.startswith("requirements/") for path in limited["reviewedFiles"]), 3)

        for path in requirements.iterdir():
            path.unlink()
        chain_length = 8
        (self.project / "requirements.txt").write_text("-r chain-0.txt\n", encoding="utf-8")
        for index in range(chain_length):
            target = "terminal==1.0.0\n" if index == chain_length - 1 else f"-r chain-{index + 1}.txt\n"
            (self.project / f"chain-{index}.txt").write_text(target, encoding="utf-8")

        with patch.object(dependency_trust, "MAX_REQUIREMENTS_DEPTH", 3):
            depth_limited = scan_project(self.project)

        self.assertEqual(depth_limited["dependencyTrust"]["status"], "incomplete")
        self.assertTrue(any(item["reason"] == "requirements-depth-limit" for item in depth_limited["dependencyTrust"]["limitations"]))
        self.assertFalse(depth_limited["scanCompleteness"]["complete"])

    def test_deep_json_and_repeated_unsupported_options_remain_bounded(self) -> None:
        depth = 1_200
        nested = '{"lockfileVersion":1,"dependencies":' + ('{"a":{"version":"1","dependencies":' * depth) + '{}' + ('}}' * depth) + '}'
        (self.project / "package-lock.json").write_text(nested, encoding="utf-8")
        started = time.monotonic()
        malformed = scan_project(self.project)
        self.assertLess(time.monotonic() - started, 5.0)
        self.assertNotEqual(malformed["dependencyTrust"]["status"], "complete")
        self.assertLessEqual(len(malformed["dependencyTrust"]["entries"]), dependency_trust.MAX_ENTRIES)

        (self.project / "package-lock.json").unlink()
        (self.project / "requirements.txt").write_text(
            "".join("--index-url https://user:secret@example.test/simple?token=hidden\n" for _ in range(2_000)),
            encoding="utf-8",
        )
        repeated = scan_project(self.project)
        dependency_gaps = [finding for finding in repeated["findings"] if finding["type"] == "dependency-analysis-incomplete"]
        self.assertEqual(len(dependency_gaps), 1)
        self.assertNotIn("user:secret", json.dumps(repeated))
        self.assertNotIn("token=hidden", json.dumps(repeated))

    def test_source_changes_are_review_evidence_and_incomplete_snapshots_do_not_remove(self) -> None:
        self.write_json("package.json", {"dependencies": {"alpha": "1.0.0", "beta": "1.0.0"}})
        self.write_json("package-lock.json", {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"alpha": "1.0.0", "beta": "1.0.0"}},
                "node_modules/alpha": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz", "integrity": "sha512-AAAA"},
                "node_modules/beta": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/beta/-/beta-1.0.0.tgz", "integrity": "sha512-BBBB"},
            },
        })
        first = scan_project(self.project)
        lock = json.loads((self.project / "package-lock.json").read_text(encoding="utf-8"))
        lock["packages"]["node_modules/alpha"]["resolved"] = "https://registry.corp.example/alpha/-/alpha-1.0.0.tgz"
        self.write_json("package-lock.json", lock)

        changed = scan_project(self.project, previous_dependency_trust=first["dependencyTrust"])
        source_finding = next(finding for finding in changed["findings"] if finding["type"] == "dependency-source-changed")
        self.assertEqual(source_finding["severity"], "medium")
        self.assertFalse(any(finding["severity"] == "high" for finding in changed["findings"] if finding["type"].startswith("dependency-")))

        (self.project / "package-lock.json").unlink()
        self.write_json("package.json", {"dependencies": {"alpha": "1.0.0"}})
        incomplete = scan_project(self.project, previous_dependency_trust=changed["dependencyTrust"])
        change_types = {change["changeType"] for change in incomplete["dependencyTrust"]["comparison"]["changes"]}
        self.assertEqual(incomplete["dependencyTrust"]["status"], "incomplete")
        self.assertNotIn("removed", change_types)
        self.assertNotIn("locked-removed", change_types)

    def test_empty_supported_manifest_and_absent_metadata_are_distinct(self) -> None:
        self.write_json("package.json", {})
        supported = scan_project(self.project)["dependencyTrust"]
        self.assertEqual(supported["status"], "complete")
        self.assertEqual(supported["directDependencyCount"], 0)

        (self.project / "package.json").unlink()
        unsupported = scan_project(self.project)["dependencyTrust"]
        self.assertEqual(unsupported["status"], "unsupported")


if __name__ == "__main__":
    unittest.main()
