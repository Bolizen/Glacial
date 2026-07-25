from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from app.database import _normalize_finding
from app.finding_explainability import (
    FINDING_EXPLAINABILITY_SCHEMA_VERSION,
    FINDING_RULE_VERSION,
    MAX_EVIDENCE_DETAILS,
    MAX_EVIDENCE_VALUE,
    build_finding_explainability,
    normalize_finding_explainability,
)
from app.scanner import scan_project


class FindingExplainabilityTests(unittest.TestCase):
    def test_canonical_model_answers_each_explainability_question(self) -> None:
        value = build_finding_explainability({
            "path": "package.json",
            "type": "package-lifecycle-script",
            "severity": "high",
            "explanation": "package.json defines a 'postinstall' lifecycle script.",
            "action": "Inspect the exact script before installing dependencies.",
            "script": "postinstall",
        })

        self.assertEqual(value["schemaVersion"], FINDING_EXPLAINABILITY_SCHEMA_VERSION)
        self.assertEqual(value["rule"], {
            "id": "scanner.package-lifecycle-script",
            "name": "Package Lifecycle Script",
            "version": FINDING_RULE_VERSION,
        })
        self.assertEqual(value["category"], "code execution")
        self.assertEqual(value["evidence"]["kind"], "manifest-field")
        self.assertEqual(value["evidence"]["path"], "package.json")
        self.assertEqual(value["evidence"]["location"], "scripts.postinstall")
        self.assertEqual(value["evidence"]["details"]["script"], "postinstall")
        for field in ("observation", "impact", "severityReason", "manualCheck", "limitations"):
            self.assertIsInstance(value[field], str)
            self.assertTrue(value[field])

    def test_suspicious_text_uses_existing_redacted_bounded_evidence(self) -> None:
        value = build_finding_explainability({
            "path": "src/evaluate.js",
            "type": "suspicious-text-pattern",
            "severity": "high",
            "explanation": "Dynamic code evaluation pattern found. Pattern: eval(",
            "pattern": "eval(",
            "evidence": {
                "line": 8,
                "matchCount": 2,
                "pattern": "eval(",
                "excerpt": "const output = eval(exampleInput);",
                "additionalMatchesOmitted": True,
            },
        })

        self.assertEqual(value["evidence"]["kind"], "text-match")
        self.assertEqual(value["evidence"]["location"], "line 8")
        self.assertEqual(value["evidence"]["excerpt"], "const output = eval(exampleInput);")
        self.assertEqual(value["evidence"]["details"]["matchCount"], 2)
        self.assertTrue(value["evidence"]["details"]["additionalMatchesOmitted"])

    def test_evidence_details_are_bounded_and_unknown_values_are_dropped(self) -> None:
        finding = {
            "path": "package-lock.json",
            "type": "dependency-analysis-incomplete",
            "severity": "medium",
            "explanation": "Dependency analysis is incomplete.",
            "metadata": {
                f"field{index}": "x" * (MAX_EVIDENCE_VALUE + 50)
                for index in range(MAX_EVIDENCE_DETAILS + 10)
            },
            "unsupported": object(),
        }

        details = build_finding_explainability(finding)["evidence"]["details"]

        self.assertLessEqual(len(details), MAX_EVIDENCE_DETAILS)
        self.assertLessEqual(len(details["metadata"]), 12)
        self.assertTrue(all(len(value) <= MAX_EVIDENCE_VALUE for value in details["metadata"].values()))
        self.assertNotIn("unsupported", details)

    def test_every_new_scanner_finding_has_canonical_explainability(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as temporary:
            project = Path(temporary) / "project"
            project.mkdir()
            (project / ".env.example").write_text("", encoding="utf-8")
            (project / "setup.ps1").write_text("Invoke-Expression $exampleInput", encoding="utf-8")
            (project / "package.json").write_text(json.dumps({
                "scripts": {"postinstall": "node setup.js"},
                "dependencies": {"example-package": "1.0.0"},
            }), encoding="utf-8")
            (project / "package-lock.json").write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"example-package": "1.0.0"}},
                    "node_modules/example-package": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/example-package/-/example-package-1.0.0.tgz",
                        "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    },
                },
            }), encoding="utf-8")

            findings = scan_project(project)["findings"]

        self.assertGreater(len(findings), 0)
        for finding in findings:
            value = finding.get("explainability")
            self.assertIsInstance(value, dict, finding["type"])
            self.assertEqual(value["rule"]["id"], f"scanner.{finding['type']}")
            self.assertEqual(value["rule"]["version"], FINDING_RULE_VERSION)
            self.assertEqual(value["evidence"]["path"], finding.get("path", ""))
            self.assertTrue(value["severityReason"])
            self.assertTrue(value["limitations"])
        secret = next(item for item in findings if item["type"] == "secret-looking-file")
        self.assertIn("did not open the file", secret["explainability"]["limitations"])
        self.assertNotIn("excerpt", secret["explainability"]["evidence"])

    def test_persisted_read_accepts_valid_current_metadata_and_drops_malformed_or_legacy_metadata(self) -> None:
        finding = {
            "path": "scripts/setup.ps1",
            "type": "executable-or-script-file",
            "severity": "high",
            "explanation": "PowerShell script found.",
        }
        explainability = build_finding_explainability(finding)

        current = _normalize_finding({**finding, "explainability": explainability})
        malformed = _normalize_finding({
            **finding,
            "explainability": {
                **explainability,
                "rule": {**explainability["rule"], "id": "scanner.different-rule"},
            },
        })
        legacy = _normalize_finding(finding)

        self.assertEqual(current["explainability"], explainability)
        self.assertNotIn("explainability", malformed)
        self.assertNotIn("explainability", legacy)
        self.assertIsNone(normalize_finding_explainability(
            {**explainability, "evidence": {**explainability["evidence"], "path": "../escape"}},
            finding_type=finding["type"],
            path=finding["path"],
        ))
        self.assertIsNone(normalize_finding_explainability(
            explainability,
            finding_type=finding["type"],
            path="C:/outside-project/setup.ps1",
        ))


if __name__ == "__main__":
    unittest.main()
