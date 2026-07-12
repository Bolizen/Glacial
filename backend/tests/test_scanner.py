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
        (self.project_path / ".codexforgeignore").write_text(
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
        linked_ignore = self.project_path / ".codexforgeignore"
        linked_ignore.write_text("payload.txt\n", encoding="utf-8")
        (self.project_path / "payload.txt").write_text(
            "eval(untrusted_input)",
            encoding="utf-8",
        )

        result = self.scan_with_linked_paths(linked_ignore)

        self.assert_link_finding(result, ".codexforgeignore")
        self.assertNotIn(".codexforgeignore", result["reviewedFiles"])
        self.assertNotIn("payload.txt", result["ignoredFiles"])
        self.assertIn("payload.txt", result["reviewedFiles"])

    def test_hardlinked_ignore_file_is_reported_and_not_used(self) -> None:
        external_ignore = self.base_path / "external-ignore"
        external_ignore.write_text("payload.txt\n", encoding="utf-8")
        try:
            os.link(external_ignore, self.project_path / ".codexforgeignore")
        except OSError as exc:
            self.skipTest(f"Hardlinks are unavailable: {exc}")
        (self.project_path / "payload.txt").write_text("eval(untrusted_input)", encoding="utf-8")

        result = scan_project(self.project_path)

        self.assertTrue(any(
            finding["type"] == "hardlink" and finding["path"] == ".codexforgeignore"
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
            "issueCount": 0,
        })

    def test_walk_error_is_recorded(self) -> None:
        blocked = self.project_path / "blocked"

        def failing_walk(path: Path, *, followlinks: bool, onerror: object) -> list[tuple[str, list[str], list[str]]]:
            error = PermissionError(13, f"Access denied at {self.project_path}", str(blocked))
            onerror(error)
            onerror(error)
            return [(str(path), [], [])]

        with patch.object(scanner.os, "walk", side_effect=failing_walk):
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
        ignore_file = self.project_path / ".codexforgeignore"
        ignore_file.write_text("payload.txt\n", encoding="utf-8")
        (self.project_path / "payload.txt").write_text("ordinary content", encoding="utf-8")
        original_read_text = Path.read_text

        def read_text(path: Path, *args: object, **kwargs: object) -> str:
            if path == ignore_file:
                raise OSError(5, "Ignore read failed")
            return original_read_text(path, *args, **kwargs)

        with patch.object(Path, "read_text", autospec=True, side_effect=read_text):
            result = scan_project(self.project_path)

        self.assertEqual(result["scanCompleteness"]["fileInspectionFailureCount"], 1)
        self.assertNotIn("payload.txt", result["ignoredFiles"])
        self.assertNotIn(".codexforgeignore", result["reviewedFiles"])
        self.assertEqual(
            sum(finding.get("operation") == "read-ignore-file" for finding in result["findings"]),
            1,
        )
        self.assertTrue(any(
            finding.get("operation") == "read-ignore-file" and finding["path"] == ".codexforgeignore"
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
