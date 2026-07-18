from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import scanner
from app.scanner import scan_project


class ScannerLinkedPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            dir=Path(__file__).resolve().parent
        )
        self.base_path = Path(self.temporary_directory.name)
        self.project_path = self.base_path / "project"
        self.project_path.mkdir()
        self.addCleanup(self.temporary_directory.cleanup)

    def create_symlink(
        self,
        link: Path,
        target: Path,
        *,
        target_is_directory: bool = False,
    ) -> None:
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except OSError as exc:
            self.skipTest(f"Symlinks are unavailable: {exc}")

    def scan_with_linked_paths(self, *linked_paths: Path) -> dict[str, object]:
        linked = set(linked_paths)
        with patch(
            "app.scanner.is_reparse_point_or_symlink",
            side_effect=lambda path: path in linked,
        ):
            return scan_project(self.project_path)

    def assert_link_finding(self, result: dict[str, object], path: str) -> None:
        self.assertTrue(
            any(
                finding["type"] == "symlink-or-reparse-point"
                and finding["path"] == path
                for finding in result["findings"]
            )
        )

    def test_reported_linked_file_is_not_read_or_reviewed(self) -> None:
        linked_file = self.project_path / "linked.txt"
        linked_file.write_text("eval(untrusted_input)", encoding="utf-8")

        result = self.scan_with_linked_paths(linked_file)

        self.assert_link_finding(result, "linked.txt")
        self.assertNotIn("linked.txt", result["reviewedFiles"])
        self.assertNotIn("linked.txt", result["ignoredFiles"])
        self.assertFalse(
            any(
                finding["type"] == "suspicious-text-pattern"
                and finding["path"] == "linked.txt"
                for finding in result["findings"]
            )
        )

    def test_file_symlink_integration_is_not_read_or_reviewed(self) -> None:
        external_file = self.base_path / "external.txt"
        external_file.write_text("eval(untrusted_input)", encoding="utf-8")
        self.create_symlink(self.project_path / "linked.txt", external_file)

        result = scan_project(self.project_path)

        self.assert_link_finding(result, "linked.txt")
        self.assertNotIn("linked.txt", result["reviewedFiles"])
        self.assertNotIn("linked.txt", result["ignoredFiles"])
        self.assertFalse(
            any(
                finding["type"] == "suspicious-text-pattern"
                and finding["path"] == "linked.txt"
                for finding in result["findings"]
            )
        )

    def test_hardlinked_file_is_not_read_or_reviewed(self) -> None:
        external_file = self.base_path / "external-hardlink.txt"
        external_file.write_text("eval(untrusted_input)", encoding="utf-8")
        linked_file = self.project_path / "linked.txt"
        try:
            os.link(external_file, linked_file)
        except OSError as exc:
            self.skipTest(f"Hardlinks are unavailable: {exc}")

        result = scan_project(self.project_path)

        self.assertTrue(
            any(
                finding["type"] == "hardlink"
                and finding["path"] == "linked.txt"
                for finding in result["findings"]
            )
        )
        self.assertNotIn("linked.txt", result["reviewedFiles"])
        self.assertNotIn("linked.txt", result["ignoredFiles"])
        self.assertFalse(
            any(
                finding["type"] == "suspicious-text-pattern"
                and finding["path"] == "linked.txt"
                for finding in result["findings"]
            )
        )

    def test_ignored_linked_file_still_produces_a_finding(self) -> None:
        (self.project_path / ".glacialignore").write_text(
            "ignored-link.txt\n",
            encoding="utf-8",
        )
        linked_file = self.project_path / "ignored-link.txt"
        linked_file.write_text(
            "eval(untrusted_input)",
            encoding="utf-8",
        )

        result = self.scan_with_linked_paths(linked_file)

        self.assert_link_finding(result, "ignored-link.txt")
        self.assertNotIn("ignored-link.txt", result["reviewedFiles"])
        self.assertNotIn("ignored-link.txt", result["ignoredFiles"])

    def test_reported_linked_directory_is_not_traversed(self) -> None:
        linked_directory = self.project_path / "linked-directory"
        linked_directory.mkdir()
        (linked_directory / "payload.txt").write_text(
            "eval(untrusted_input)",
            encoding="utf-8",
        )

        result = self.scan_with_linked_paths(linked_directory)

        self.assert_link_finding(result, "linked-directory")
        self.assertFalse(
            any(
                path.startswith("linked-directory/")
                for path in result["reviewedFiles"]
            )
        )
        self.assertFalse(
            any(
                finding["path"].startswith("linked-directory/")
                for finding in result["findings"]
            )
        )

    def test_directory_symlink_integration_is_not_traversed(self) -> None:
        external_directory = self.base_path / "external-directory"
        external_directory.mkdir()
        (external_directory / "payload.txt").write_text(
            "eval(untrusted_input)",
            encoding="utf-8",
        )
        self.create_symlink(
            self.project_path / "linked-directory",
            external_directory,
            target_is_directory=True,
        )

        result = scan_project(self.project_path)

        self.assert_link_finding(result, "linked-directory")
        self.assertFalse(
            any(
                path.startswith("linked-directory/")
                for path in result["reviewedFiles"]
            )
        )
        self.assertFalse(
            any(
                finding["path"].startswith("linked-directory/")
                for finding in result["findings"]
            )
        )

    def test_linked_ignore_file_is_reported_and_not_used(self) -> None:
        linked_ignore = self.project_path / ".glacialignore"
        linked_ignore.write_text("payload.txt\n", encoding="utf-8")
        (self.project_path / "payload.txt").write_text(
            "eval(untrusted_input)",
            encoding="utf-8",
        )

        result = self.scan_with_linked_paths(linked_ignore)

        self.assert_link_finding(result, ".glacialignore")
        self.assertNotIn(".glacialignore", result["reviewedFiles"])
        self.assertNotIn("payload.txt", result["ignoredFiles"])
        self.assertIn("payload.txt", result["reviewedFiles"])

    def test_hardlinked_ignore_file_is_reported_and_not_used(self) -> None:
        external_ignore = self.base_path / "external-ignore"
        external_ignore.write_text("payload.txt\n", encoding="utf-8")
        try:
            os.link(external_ignore, self.project_path / ".glacialignore")
        except OSError as exc:
            self.skipTest(f"Hardlinks are unavailable: {exc}")
        (self.project_path / "payload.txt").write_text("eval(untrusted_input)", encoding="utf-8")

        result = scan_project(self.project_path)

        self.assertTrue(any(
            finding["type"] == "hardlink" and finding["path"] == ".glacialignore"
            for finding in result["findings"]
        ))
        self.assertNotIn("payload.txt", result["ignoredFiles"])
        self.assertIn("payload.txt", result["reviewedFiles"])


class ScannerCompletenessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.base_path = Path(self.temporary_directory.name)
        self.project_path = self.base_path / "project"
        self.project_path.mkdir()
        self.addCleanup(self.temporary_directory.cleanup)

    def assert_resource_budget(
        self,
        result: dict[str, object],
        budget: str,
        limit: int,
        observed: int,
    ) -> dict[str, object]:
        self.assertFalse(result["scanCompleteness"]["complete"])
        self.assertEqual(result["scanCompleteness"]["resourceBudgetExceededCount"], 1)
        finding = next(
            finding
            for finding in result["findings"]
            if finding["type"] == "scan-resource-budget-exceeded"
            and finding["budget"] == budget
        )
        self.assertEqual(finding["limit"], limit)
        self.assertEqual(finding["observed"], observed)
        return finding

    def assert_package_json_failure(self, result: dict[str, object], reason: str) -> None:
        self.assertFalse(result["scanCompleteness"]["complete"])
        self.assertEqual(result["scanCompleteness"]["fileInspectionFailureCount"], 1)
        self.assertEqual(result["scanCompleteness"]["dependencyAnalysisFailureCount"], 0)
        self.assertEqual(result["dependencyTrust"]["status"], "malformed")
        self.assertIn("package.json", result["dependencyTrust"]["failedFiles"])
        self.assertNotIn("package.json", result["reviewedFiles"])
        finding = next(
            finding
            for finding in result["findings"]
            if finding["type"] == "dependency-manifest-parse-error"
            and finding["path"] == "package.json"
        )
        self.assertEqual(finding["metadata"]["reason"], reason)

    def test_non_object_package_json_is_incomplete_and_scan_continues(self) -> None:
        (self.project_path / "zzz.ps1").write_text(
            "Invoke-Expression $payload",
            encoding="utf-8",
        )

        for name, content in {
            "null": "null",
            "array": "[]",
            "string": '"text"',
            "number": "7",
        }.items():
            with self.subTest(name=name):
                (self.project_path / "package.json").write_text(content, encoding="utf-8")

                result = scan_project(self.project_path)

                self.assert_package_json_failure(result, "top-level-json-not-object")
                self.assertEqual(result["lifecycleScripts"], [])
                self.assertIn("zzz.ps1", result["reviewedFiles"])
                self.assertTrue(any(
                    finding["type"] == "suspicious-text-pattern"
                    and finding["path"] == "zzz.ps1"
                    for finding in result["findings"]
                ))

    def test_malformed_package_json_syntax_is_explicitly_incomplete(self) -> None:
        (self.project_path / "package.json").write_text(
            '{"scripts":',
            encoding="utf-8",
        )

        result = scan_project(self.project_path)

        self.assert_package_json_failure(result, "invalid-json-syntax")

    def test_invalid_utf8_package_json_is_explicitly_incomplete(self) -> None:
        (self.project_path / "package.json").write_bytes(b"{\xff}")

        result = scan_project(self.project_path)

        self.assert_package_json_failure(result, "invalid-utf8")

    def test_deeply_nested_package_json_is_explicitly_incomplete(self) -> None:
        depth = 5_000
        content = '{"scripts":' + ('{"x":' * depth) + "null" + ("}" * depth) + "}"
        (self.project_path / "package.json").write_text(content, encoding="utf-8")

        result = scan_project(self.project_path)

        self.assert_package_json_failure(result, "excessive-json-nesting")

    def test_valid_package_json_preserves_dependency_and_lifecycle_inspection(self) -> None:
        (self.project_path / "package.json").write_text(
            '{"scripts":{"postinstall":"node setup.js"},"dependencies":{"alpha":"1.0.0"}}',
            encoding="utf-8",
        )
        (self.project_path / "package-lock.json").write_text(
            '{"lockfileVersion":3,"packages":{"":{"dependencies":{"alpha":"1.0.0"}},'
            '"node_modules/alpha":{"version":"1.0.0","resolved":'
            '"https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz","integrity":"sha512-AAAA"}}}',
            encoding="utf-8",
        )

        result = scan_project(self.project_path)

        self.assertTrue(result["scanCompleteness"]["complete"])
        self.assertEqual(result["dependencyTrust"]["status"], "complete")
        self.assertEqual(result["lifecycleScripts"], [{"path": "package.json", "script": "postinstall"}])
        self.assertTrue(any(
            entry["name"] == "alpha"
            and entry["requestedSpecification"] == "1.0.0"
            and entry["manifestPath"] == "package.json"
            for entry in result["dependencyTrust"]["entries"]
        ))
        self.assertIn("package.json", result["reviewedFiles"])

    def test_successful_scan_reports_complete(self) -> None:
        (self.project_path / "safe.txt").write_text("ordinary content", encoding="utf-8")

        result = scan_project(self.project_path)

        self.assertEqual(result["reviewedFiles"], ["safe.txt"])
        self.assertEqual(result["scanCompleteness"], {
            "complete": True,
            "traversalFailureCount": 0,
            "fileInspectionFailureCount": 0,
            "oversizedFileCount": 0,
            "unsafePathCount": 0,
            "dependencyAnalysisFailureCount": 0,
            "policyExcludedFileCount": 0,
            "resourceBudgetExceededCount": 0,
            "issueCount": 0,
        })

    def test_oversized_ignore_policy_is_rejected_before_content_allocation(self) -> None:
        ignore_file = self.project_path / ".glacialignore"
        ignored_target = self.project_path / "target.ps1"
        ignored_target.write_text("Invoke-Expression $payload", encoding="utf-8")
        with patch.object(scanner, "MAX_IGNORE_BYTES", 16):
            ignore_file.write_text("target.ps1\n" + ("x" * 32), encoding="utf-8")
            with patch.object(Path, "open", autospec=True, side_effect=AssertionError("oversized policy was opened")):
                patterns, finding, issue = scanner._load_ignore_patterns(self.project_path)

            self.assertEqual(patterns, set())
            self.assertEqual(issue, "resourceBudgetExceededCount")
            self.assertEqual(finding["budget"], "ignore-bytes")
            self.assertEqual(finding["limit"], 16)
            self.assertGreater(finding["observed"], 16)

            result = scan_project(self.project_path)

        self.assertEqual(result["ignoredFiles"], [])
        self.assertIn("target.ps1", result["reviewedFiles"])
        self.assertTrue(any(
            item["path"] == "target.ps1" and item["type"] == "suspicious-text-pattern"
            for item in result["findings"]
        ))
        self.assert_resource_budget(result, "ignore-bytes", 16, ignore_file.stat().st_size)

    def test_excessive_ignore_patterns_reject_the_entire_policy(self) -> None:
        (self.project_path / ".glacialignore").write_text(
            "target.ps1\nnoise-one.txt\nnoise-two.txt\n",
            encoding="utf-8",
        )
        (self.project_path / "target.ps1").write_text("Invoke-Expression $payload", encoding="utf-8")

        with patch.object(scanner, "MAX_IGNORE_PATTERNS", 2):
            result = scan_project(self.project_path)

        self.assertEqual(result["ignoredFiles"], [])
        self.assertIn("target.ps1", result["reviewedFiles"])
        self.assertTrue(any(item["path"] == "target.ps1" for item in result["findings"]))
        self.assert_resource_budget(result, "ignore-patterns", 2, 3)

    def test_file_budget_stops_traversal_and_preserves_prior_high_risk_evidence(self) -> None:
        flood = self.project_path / "flood"
        flood.mkdir()
        (self.project_path / "evidence.ps1").write_text("Invoke-Expression $payload", encoding="utf-8")
        for name in ("one.txt", "two.txt"):
            (flood / name).write_text("ordinary content", encoding="utf-8")

        with patch.object(scanner, "MAX_SCAN_FILES", 2):
            result = scan_project(self.project_path)

        self.assertIn("evidence.ps1", result["reviewedFiles"])
        self.assertTrue(any(
            item["path"] == "evidence.ps1" and item["severity"] == "high"
            for item in result["findings"]
        ))
        finding = self.assert_resource_budget(result, "files", 2, 3)
        self.assertEqual(finding["observedCounts"]["filesEncountered"], 3)

    def test_directory_budget_stops_traversal_and_preserves_prior_evidence(self) -> None:
        first = self.project_path / "first"
        second = first / "second"
        second.mkdir(parents=True)
        (self.project_path / "evidence.ps1").write_text("Invoke-Expression $payload", encoding="utf-8")

        with patch.object(scanner, "MAX_SCAN_DIRECTORIES", 2):
            result = scan_project(self.project_path)

        self.assertIn("evidence.ps1", result["reviewedFiles"])
        self.assertTrue(any(item["path"] == "evidence.ps1" for item in result["findings"]))
        finding = self.assert_resource_budget(result, "directories", 2, 3)
        self.assertEqual(finding["observedCounts"]["directoriesEncountered"], 3)

    def test_filesystem_entry_budget_bounds_total_traversal_work(self) -> None:
        flood = self.project_path / "flood"
        flood.mkdir()
        (self.project_path / "evidence.ps1").write_text("Invoke-Expression $payload", encoding="utf-8")
        (flood / "one.txt").write_text("ordinary content", encoding="utf-8")

        with patch.object(scanner, "MAX_SCAN_FILESYSTEM_ENTRIES", 2):
            result = scan_project(self.project_path)

        self.assertIn("evidence.ps1", result["reviewedFiles"])
        finding = self.assert_resource_budget(result, "filesystem-entries", 2, 3)
        self.assertEqual(finding["observedCounts"]["filesystemEntriesEncountered"], 3)

    def test_aggregate_byte_budget_stops_before_the_next_file_read(self) -> None:
        evidence = "Invoke-Expression $payload"
        (self.project_path / "a.ps1").write_text(evidence, encoding="utf-8")
        (self.project_path / "b.txt").write_text("x", encoding="utf-8")

        with patch.object(scanner, "MAX_SCAN_INSPECTED_BYTES", len(evidence.encode("utf-8"))):
            result = scan_project(self.project_path)

        self.assertIn("a.ps1", result["reviewedFiles"])
        self.assertNotIn("b.txt", result["reviewedFiles"])
        self.assertTrue(any(item["path"] == "a.ps1" for item in result["findings"]))
        self.assert_resource_budget(
            result,
            "inspected-bytes",
            len(evidence.encode("utf-8")),
            len(evidence.encode("utf-8")) + 1,
        )

    def test_finding_and_result_record_accumulation_are_bounded(self) -> None:
        (self.project_path / "a.ps1").write_text("Invoke-Expression $payload", encoding="utf-8")
        (self.project_path / "b.ps1").write_text("Invoke-Expression $payload", encoding="utf-8")

        with patch.object(scanner, "MAX_SCAN_FINDINGS", 2):
            finding_limited = scan_project(self.project_path)

        self.assertLessEqual(len(finding_limited["findings"]), 3)
        self.assertTrue(any(
            item["path"] == "a.ps1" and item["severity"] == "high"
            for item in finding_limited["findings"]
        ))
        self.assert_resource_budget(finding_limited, "findings", 2, 3)

        for path in self.project_path.iterdir():
            path.unlink()
        (self.project_path / "a.txt").write_text("ordinary", encoding="utf-8")
        (self.project_path / "b.txt").write_text("ordinary", encoding="utf-8")
        with patch.object(scanner, "MAX_SCAN_RESULT_RECORDS", 1):
            result_limited = scan_project(self.project_path)

        self.assertEqual(result_limited["reviewedFiles"], ["a.txt"])
        self.assert_resource_budget(result_limited, "result-records", 1, 2)

    def test_repository_ignore_policy_cannot_claim_complete_security_coverage(self) -> None:
        scripts_path = self.project_path / "scripts"
        scripts_path.mkdir()
        (self.project_path / ".glacialignore").write_text(
            "package.json\nscripts/install.ps1\n",
            encoding="utf-8",
        )
        (self.project_path / "package.json").write_text(
            '{"scripts":{"postinstall":"node setup.js"}}',
            encoding="utf-8",
        )
        (scripts_path / "install.ps1").write_text("Invoke-Expression $payload", encoding="utf-8")

        result = scan_project(self.project_path)

        self.assertEqual(result["ignoredFiles"], ["package.json", "scripts/install.ps1"])
        self.assertEqual(result["manifests"], [])
        self.assertEqual(result["lifecycleScripts"], [])
        self.assertFalse(any(
            finding["path"] in {"package.json", "scripts/install.ps1"}
            for finding in result["findings"]
        ))
        self.assertEqual(result["overall_risk"], "none")
        self.assertEqual(result["scanCompleteness"]["policyExcludedFileCount"], 2)
        self.assertEqual(result["scanCompleteness"]["issueCount"], 2)
        self.assertFalse(result["scanCompleteness"]["complete"])

    def test_legitimate_ignored_noise_remains_excluded_and_visible(self) -> None:
        generated_path = self.project_path / "generated"
        generated_path.mkdir()
        (self.project_path / ".glacialignore").write_text(
            "generated\\noise.txt\n",
            encoding="utf-8",
        )
        (generated_path / "noise.txt").write_text("eval(untrusted_input)", encoding="utf-8")

        result = scan_project(self.project_path)

        self.assertEqual(result["ignoredFiles"], ["generated/noise.txt"])
        self.assertNotIn("generated/noise.txt", result["reviewedFiles"])
        self.assertFalse(any(
            finding["path"] == "generated/noise.txt"
            for finding in result["findings"]
        ))
        self.assertEqual(result["overall_risk"], "none")
        self.assertEqual(result["scanCompleteness"]["policyExcludedFileCount"], 1)
        self.assertFalse(result["scanCompleteness"]["complete"])

    def test_walk_error_is_recorded(self) -> None:
        blocked = self.project_path / "blocked"
        error = PermissionError(13, f"Access denied at {self.project_path}", str(blocked))

        with patch.object(scanner.os, "scandir", side_effect=error):
            result = scan_project(self.project_path)

        self.assertEqual(result["scanCompleteness"]["traversalFailureCount"], 1)
        self.assertFalse(result["scanCompleteness"]["complete"])
        self.assertTrue(any(
            finding["type"] == "directory-traversal-error" and finding["path"] == "blocked"
            for finding in result["findings"]
        ))
        finding = next(finding for finding in result["findings"] if finding["type"] == "directory-traversal-error")
        self.assertEqual(finding["error"], os.strerror(13))
        self.assertNotIn(str(self.project_path), finding["error"])

    def test_file_read_error_is_not_reviewed(self) -> None:
        target = self.project_path / "unreadable.txt"
        target.write_text("content", encoding="utf-8")
        original_open = Path.open

        def open_file(path: Path, *args: object, **kwargs: object) -> object:
            if path == target and args and args[0] == "rb":
                raise OSError(5, "Read failed")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", autospec=True, side_effect=open_file):
            result = scan_project(self.project_path)

        self.assertNotIn("unreadable.txt", result["reviewedFiles"])
        self.assertEqual(result["scanCompleteness"]["fileInspectionFailureCount"], 1)
        self.assertTrue(any(finding.get("operation") == "read-file-content" for finding in result["findings"]))

    def test_ignore_file_read_error_is_disclosed(self) -> None:
        ignore_file = self.project_path / ".glacialignore"
        ignore_file.write_text("payload.txt\n", encoding="utf-8")
        (self.project_path / "payload.txt").write_text("ordinary content", encoding="utf-8")
        original_open = Path.open

        def open_file(path: Path, *args: object, **kwargs: object) -> object:
            if path == ignore_file and args and args[0] == "rb":
                raise OSError(5, "Ignore read failed")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", autospec=True, side_effect=open_file):
            result = scan_project(self.project_path)

        self.assertEqual(result["scanCompleteness"]["fileInspectionFailureCount"], 1)
        self.assertNotIn("payload.txt", result["ignoredFiles"])
        self.assertNotIn(".glacialignore", result["reviewedFiles"])
        self.assertEqual(
            sum(finding.get("operation") == "read-ignore-file" for finding in result["findings"]),
            1,
        )
        self.assertTrue(any(
            finding.get("operation") == "read-ignore-file" and finding["path"] == ".glacialignore"
            for finding in result["findings"]
        ))

    def test_metadata_error_is_not_reviewed(self) -> None:
        target = self.project_path / "unstable.txt"
        target.write_text("content", encoding="utf-8")
        original_stat = Path.stat

        def stat_path(path: Path, *args: object, **kwargs: object) -> os.stat_result:
            if path == target:
                raise OSError(5, "Metadata failed")
            return original_stat(path, *args, **kwargs)

        with (
            patch.object(scanner, "is_reparse_point_or_symlink", return_value=False),
            patch.object(scanner, "has_multiple_hardlinks", return_value=False),
            patch.object(Path, "stat", autospec=True, side_effect=stat_path),
        ):
            result = scan_project(self.project_path)

        self.assertNotIn("unstable.txt", result["reviewedFiles"])
        self.assertEqual(result["scanCompleteness"]["fileInspectionFailureCount"], 1)
        self.assertTrue(any(finding.get("operation") == "inspect-file-metadata" for finding in result["findings"]))

    def test_oversized_file_is_disclosed_and_not_reviewed(self) -> None:
        target = self.project_path / "large.txt"
        target.write_bytes(b"x" * (scanner.MAX_TEXT_BYTES + 1))

        result = scan_project(self.project_path)

        self.assertNotIn("large.txt", result["reviewedFiles"])
        self.assertEqual(result["scanCompleteness"]["oversizedFileCount"], 1)
        finding = next(finding for finding in result["findings"] if finding["type"] == "oversized-file-skipped")
        self.assertEqual(finding["fileSizeBytes"], scanner.MAX_TEXT_BYTES + 1)
        self.assertEqual(finding["sizeLimitBytes"], scanner.MAX_TEXT_BYTES)
        self.assertEqual(result["overall_risk"], "low")

if __name__ == "__main__":
    unittest.main()
