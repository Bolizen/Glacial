from __future__ import annotations

import base64
import io
import json
import sqlite3
import tempfile
import unittest
import zipfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from app import database, main
from app.finding_explainability import build_finding_explainability
from app.finding_reviews import finding_fingerprint
from app.privacy import (
    REDACTED_PROJECT_PATH,
    bounded_text_excerpt,
    safe_project_relative_path,
    sanitize_private_text,
    sanitize_scan_value,
    validate_structured_digest,
)
from app.remediation_brief import build_remediation_snapshot
from app.remediation_package import build_remediation_package
from app.schemas import (
    AgentPreviewRequest,
    FindingReviewRequest,
    NoteCreate,
    ProjectMetadataUpdate,
    ProjectPathRequest,
    TrustProfileRequest,
)
from app.version import GLACIAL_VERSION


FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
FAKE_GITHUB_TOKEN = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"
FAKE_BEARER = "privacy-bearer-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
FAKE_PASSWORD = "privacy-password-canary-0123456789"
FAKE_PRIVATE_KEY_BODY = "ZmFrZS1wcml2YXRlLWtleS1tYXRlcmlhbA=="
FAKE_WINDOWS_PATH = r"C:\Users\privacy-canary\AppData\Local\Temp\hostile.txt"
FAKE_UNC_PATH = r"\\privacy-server\private-share\hostile.txt"
FAKE_UNICODE_PATH = r"D:\Utilisateurs\Renée\秘密\hostile.txt"
FAKE_CONNECTION = "postgresql://privacy-user:privacy-db-password@localhost/private"
FAKE_ENV_LINE = "SERVICE_API_KEY=privacy-env-value-0123456789"
FAKE_HEX_CANARIES = (
    "A1" * 20,
    "b2" * 32,
    "C3d4" * 24,
    "e5F6" * 32,
)
FORBIDDEN = (
    FAKE_AWS_KEY,
    FAKE_GITHUB_TOKEN,
    FAKE_BEARER,
    FAKE_PASSWORD,
    FAKE_PRIVATE_KEY_BODY,
    "privacy-canary",
    "privacy-server",
    "Renée",
    "privacy-db-password",
    "privacy-env-value-0123456789",
    *FAKE_HEX_CANARIES,
)


def hostile_text() -> str:
    return "\n".join(
        (
            f"path={FAKE_WINDOWS_PATH}",
            f"unc={FAKE_UNC_PATH}",
            f"unicode={FAKE_UNICODE_PATH}",
            f"Authorization: Bearer {FAKE_BEARER}",
            f"password={FAKE_PASSWORD}",
            FAKE_ENV_LINE,
            f"url={FAKE_CONNECTION}",
            FAKE_AWS_KEY,
            FAKE_GITHUB_TOKEN,
            f"hex40={FAKE_HEX_CANARIES[0]}",
            f"prose contains {FAKE_HEX_CANARIES[1]} safely",
            FAKE_HEX_CANARIES[2],
            f"filename=reports/{FAKE_HEX_CANARIES[3]}.txt",
            "-----BEGIN PRIVATE KEY-----",
            FAKE_PRIVATE_KEY_BODY,
            "-----END PRIVATE KEY-----",
            "terminal=\u001b[31mred\u0000",
        )
    )


class PrivacyHelperTests(unittest.TestCase):
    def assert_private_canaries_absent(self, value: object) -> None:
        text = str(value)
        for canary in FORBIDDEN:
            self.assertNotIn(canary, text)

    def test_hostile_text_is_redacted_bounded_and_still_actionable(self) -> None:
        sanitized = sanitize_private_text(
            hostile_text(),
            limit=4000,
            preserve_lines=True,
        )
        self.assert_private_canaries_absent(sanitized)
        self.assertIn("[REDACTED]", sanitized)
        self.assertIn("<HOST_PATH>", sanitized)
        self.assertNotIn("\u001b", sanitized)
        self.assertNotIn("\u0000", sanitized)

        excerpt = bounded_text_excerpt(
            "\n".join(("safe before", hostile_text(), "safe after")),
            center_line=1,
        )
        self.assert_private_canaries_absent(excerpt)
        self.assertLessEqual(len(excerpt.splitlines()), 3)
        self.assertTrue(all(len(line) <= 160 for line in excerpt.splitlines()))

    def test_project_path_policy_preserves_safe_relative_paths_and_rejects_host_paths(self) -> None:
        self.assertEqual(
            safe_project_relative_path(r"src\unicode\秘密.py"),
            "src/unicode/秘密.py",
        )
        self.assertEqual(
            safe_project_relative_path("../outside.txt"),
            REDACTED_PROJECT_PATH,
        )
        self.assertEqual(
            safe_project_relative_path(FAKE_WINDOWS_PATH),
            REDACTED_PROJECT_PATH,
        )
        self.assertEqual(
            safe_project_relative_path(FAKE_UNC_PATH),
            REDACTED_PROJECT_PATH,
        )
        secret_filename = safe_project_relative_path(f"src/{FAKE_GITHUB_TOKEN}.js")
        self.assertEqual(secret_filename, "src/[REDACTED].js")
        hex_filename = safe_project_relative_path(
            f"reports/{FAKE_HEX_CANARIES[1]}.json"
        )
        self.assertEqual(hex_filename, "reports/[REDACTED].json")

    def test_generic_hex_tokens_redact_but_structured_digest_contracts_are_exact(self) -> None:
        for canary in FAKE_HEX_CANARIES:
            self.assertEqual(sanitize_private_text(canary), "[REDACTED]")
            self.assertNotIn(
                canary,
                sanitize_private_text(f"evidence before/{canary}.txt after"),
            )

        commit = "1a" * 20
        checksum = "B2" * 32
        fingerprint = "cf1_" + ("c3" * 32)
        self.assertEqual(validate_structured_digest(commit, "git-commit"), commit)
        self.assertEqual(validate_structured_digest(checksum, "sha256"), checksum)
        self.assertEqual(
            validate_structured_digest(fingerprint, "fingerprint"),
            fingerprint,
        )
        for value, contract in (
            ("f" * 39, "git-commit"),
            ("f" * 63, "sha256"),
            ("f" * 64, "fingerprint"),
            ("cf1_" + ("f" * 63), "fingerprint"),
        ):
            with self.assertRaises(ValueError):
                validate_structured_digest(value, contract)

    def test_scan_sanitization_retains_security_and_dependency_utility(self) -> None:
        value = {
            "findings": [
                {
                    "path": f"src/{FAKE_GITHUB_TOKEN}.js",
                    "ruleId": "scanner.suspicious-text-pattern",
                    "line": 17,
                    "excerpt": hostile_text(),
                },
                {
                    "path": "src/ordinary.js",
                    "ruleId": "scanner.package-lifecycle-script",
                    "line": 3,
                },
            ],
            "dependencyTrust": {
                "entries": [
                    {"name": "react", "version": "19.0.0"},
                    {"name": FAKE_GITHUB_TOKEN, "version": FAKE_PASSWORD},
                ]
            },
            "reviewedFiles": ["src/ordinary.js", FAKE_WINDOWS_PATH],
            "structured": {
                "fingerprint": "cf1_" + ("a2" * 32),
                "vcsRequestedRevision": "rev:sha256:" + ("b3" * 32),
                "integrity": "sha512-QUJDRA==",
            },
            "ordinary": {
                "description": FAKE_HEX_CANARIES[0],
                "notes": FAKE_HEX_CANARIES[1],
                "metadata": FAKE_HEX_CANARIES[2],
                "filename": f"{FAKE_HEX_CANARIES[3]}.txt",
                "fingerprint": FAKE_HEX_CANARIES[1],
            },
        }
        sanitized = sanitize_scan_value(value, project_root=r"C:\workspace\project")
        serialized = json.dumps(sanitized, ensure_ascii=False, sort_keys=True)
        self.assert_private_canaries_absent(serialized)
        self.assertEqual(
            [item["ruleId"] for item in sanitized["findings"]],
            [
                "scanner.suspicious-text-pattern",
                "scanner.package-lifecycle-script",
            ],
        )
        self.assertEqual(sanitized["findings"][0]["line"], 17)
        self.assertEqual(
            sanitized["dependencyTrust"]["entries"][0],
            {"name": "react", "version": "19.0.0"},
        )
        self.assertIn("src/ordinary.js", sanitized["reviewedFiles"])
        self.assertEqual(
            sanitized["structured"]["fingerprint"],
            "cf1_" + ("a2" * 32),
        )
        self.assertEqual(
            sanitized["structured"]["vcsRequestedRevision"],
            "rev:sha256:" + ("b3" * 32),
        )
        self.assertEqual(sanitized["structured"]["integrity"], "sha512-QUJDRA==")
        self.assertNotIn(FAKE_HEX_CANARIES[1], serialized)


class PrivacyPersistenceAndExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            dir=Path(__file__).resolve().parent
        )
        self.addCleanup(self.temporary_directory.cleanup)
        self.base = Path(self.temporary_directory.name)
        self.database_path = self.base / "glacial.db"
        self.root = self.base / "workspace"
        self.project = self.root / "project"
        self.project.mkdir(parents=True)

        patches = [
            patch.object(database, "DB_PATH", self.database_path),
            patch.object(database, "get_connection", side_effect=self.closing_connection),
            patch.object(main, "get_connection", side_effect=self.closing_connection),
        ]
        for active_patch in patches:
            active_patch.start()
            self.addCleanup(active_patch.stop)
        database.init_db()
        database.set_setting(database.WORKSPACE_ROOT_SETTING, str(self.root))
        with database.get_connection() as connection:
            connection.execute(
                "INSERT INTO projects (path, name, description, project_type, created_at) "
                "VALUES (?, ?, '', '', ?)",
                (str(self.project), "Privacy fixture", "2026-01-01T00:00:00+00:00"),
            )

    @contextmanager
    def closing_connection(self) -> object:
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

    def assert_private_canaries_absent(self, value: object) -> None:
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        for canary in FORBIDDEN:
            self.assertNotIn(canary, text)

    def hostile_scan(self) -> dict[str, object]:
        finding: dict[str, object] = {
            "path": f"src/{FAKE_GITHUB_TOKEN}.js",
            "type": "suspicious-text-pattern",
            "severity": "high",
            "explanation": "Network download command reference found. Pattern: curl",
            "pattern": "curl",
            "evidence": {
                "line": 17,
                "matchCount": 1,
                "pattern": "curl",
                "excerpt": (
                    "curl https://example.invalid\n"
                    f"Authorization: Bearer {FAKE_BEARER}\n"
                    f"path={FAKE_WINDOWS_PATH}"
                ),
                "additionalMatchesOmitted": False,
            },
        }
        finding["explainability"] = build_finding_explainability(finding)
        return {
            "overall_risk": "high",
            "findings": [finding],
            "manifests": ["package.json"],
            "lockfiles": ["package-lock.json"],
            "lifecycleScripts": [{"path": "package.json", "script": "postinstall"}],
            "secretFiles": [f"config/{FAKE_GITHUB_TOKEN}.env"],
            "ignoredFiles": ["dist/generated.js"],
            "reviewedFiles": ["package.json", "src/ordinary.js"],
            "reviewedFileCount": 2,
            "zone": hostile_text(),
            "scanCompleteness": {
                "complete": True,
                "traversalFailureCount": 0,
                "fileInspectionFailureCount": 0,
                "oversizedFileCount": 0,
                "unsafePathCount": 0,
                "dependencyAnalysisFailureCount": 0,
                "policyExcludedFileCount": 0,
                "builtInExcludedDirectoryCount": 0,
                "unsupportedEncodingFileCount": 0,
                "resourceBudgetExceededCount": 0,
                "issueCount": 0,
            },
            "dependencyTrust": {
                "schemaVersion": 1,
                "status": "complete",
                "ecosystems": ["node"],
                "manifests": ["package.json"],
                "lockfiles": ["package-lock.json"],
                "packageManagers": ["npm"],
                "entries": [
                    {
                        "ecosystem": "node",
                        "name": "react",
                        "version": "19.0.0",
                        "group": "runtime",
                        "direct": True,
                        "manifestPath": "package.json",
                        "lockfilePath": "package-lock.json",
                        "sourceType": "registry",
                        "sourceIdentifier": "registry:npmjs",
                        "requested": "19.0.0",
                        "integrityStatus": "present",
                    }
                ],
                "findings": [],
                "limitations": [hostile_text()],
            },
        }

    def test_database_allowlist_and_all_disclosure_outputs(self) -> None:
        with patch.object(main, "scan_project", return_value=self.hostile_scan()):
            scan = main.run_scan(ProjectPathRequest(project_path=str(self.project)))

        finding = scan["findings"][0]
        self.assertEqual(finding["explainability"]["rule"]["id"], "scanner.suspicious-text-pattern")
        self.assertEqual(finding["explainability"]["evidence"]["location"], "line 17")
        self.assertEqual(
            scan["dependencyTrust"]["entries"][0]["name"],
            "react",
        )
        self.assert_private_canaries_absent(scan)

        main.update_project_metadata(ProjectMetadataUpdate(
            project_path=str(self.project),
            description=hostile_text(),
            project_type=f"Python {FAKE_GITHUB_TOKEN}",
        ))
        note = main.add_note(NoteCreate(
            project_path=str(self.project),
            body=hostile_text(),
        ))
        profile = main.update_trust_profile(TrustProfileRequest(
            project_path=str(self.project),
            expectedManifestFiles=["package.json", FAKE_WINDOWS_PATH],
            notes=hostile_text(),
        ))
        fingerprint = finding_fingerprint(finding)
        review = main.update_finding_review(FindingReviewRequest(
            project_path=str(self.project),
            fingerprint=fingerprint,
            status="reviewed",
            note=hostile_text(),
            scan_id=scan["id"],
        ))
        self.assert_private_canaries_absent(note)
        self.assert_private_canaries_absent(profile)
        self.assert_private_canaries_absent(review)

        with database.get_connection() as connection:
            settings_path = connection.execute(
                "SELECT value FROM settings WHERE key = ?",
                (database.WORKSPACE_ROOT_SETTING,),
            ).fetchone()["value"]
            project_row = connection.execute(
                "SELECT path, description, project_type FROM projects"
            ).fetchone()
            scan_row = connection.execute(
                "SELECT project_path, findings_json, scan_metadata_json FROM scans"
            ).fetchone()
            private_rows = {
                "notes": connection.execute("SELECT body FROM notes").fetchall(),
                "profiles": connection.execute(
                    "SELECT profile_json FROM project_trust_profiles"
                ).fetchall(),
                "reviews": connection.execute(
                    "SELECT note FROM finding_reviews"
                ).fetchall(),
            }
        self.assertEqual(settings_path, str(self.root))
        self.assertEqual(project_row["path"], str(self.project))
        self.assertEqual(scan_row["project_path"], str(self.project))
        self.assert_private_canaries_absent(project_row["description"])
        self.assert_private_canaries_absent(project_row["project_type"])
        self.assert_private_canaries_absent(scan_row["findings_json"])
        self.assert_private_canaries_absent(scan_row["scan_metadata_json"])
        self.assert_private_canaries_absent({
            key: [dict(row) for row in rows]
            for key, rows in private_rows.items()
        })

        unreviewed_scan = {**scan, "findings": [{key: value for key, value in finding.items() if key != "review"}]}
        snapshot = build_remediation_snapshot(
            project_name=hostile_text(),
            project_identity=str(self.project),
            scan=unreviewed_scan,
            generator_version=GLACIAL_VERSION,
        )
        package = build_remediation_package(
            project_name=hostile_text(),
            project_identity=str(self.project),
            scan=unreviewed_scan,
            expected_snapshot_digest=snapshot["snapshotDigest"],
        )
        package_repeat = build_remediation_package(
            project_name=hostile_text(),
            project_identity=str(self.project),
            scan=unreviewed_scan,
            expected_snapshot_digest=snapshot["snapshotDigest"],
        )
        self.assertEqual(package["sha256"], package_repeat["sha256"])
        self.assertEqual(package["packageBase64"], package_repeat["packageBase64"])
        self.assert_private_canaries_absent(snapshot["brief"]["markdown"])
        archive_bytes = base64.b64decode(package["packageBase64"])
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            self.assertEqual(
                archive.namelist(),
                [
                    "README.md",
                    "AGENT_TASK.md",
                    "findings.json",
                    "manifest.json",
                    "CHECKSUMS.sha256",
                ],
            )
            extracted = {
                name: archive.read(name).decode("utf-8")
                for name in archive.namelist()
            }
        self.assert_private_canaries_absent(extracted)
        self.assertIn("scanner.suspicious-text-pattern", extracted["findings.json"])
        self.assertIn('"location": "line 17"', extracted["findings.json"])
        self.assertIn("react", json.dumps(scan["dependencyTrust"]))

        preview = main.preview_agents(AgentPreviewRequest(
            project_path=str(self.project),
            project_purpose=hostile_text(),
            project_rules="Keep src/ordinary.js reviewable.",
            build_commands=f"python {FAKE_WINDOWS_PATH}",
            test_commands="python -m unittest",
            security_notes=hostile_text(),
        ))
        self.assert_private_canaries_absent(preview["content"])
        self.assertIn("src/ordinary.js", preview["content"])

        with database.get_connection() as connection:
            after_export = connection.execute(
                "SELECT findings_json, scan_metadata_json FROM scans WHERE id = ?",
                (scan["id"],),
            ).fetchone()
        self.assertEqual(after_export["findings_json"], scan_row["findings_json"])
        self.assertEqual(after_export["scan_metadata_json"], scan_row["scan_metadata_json"])

    def test_first_party_runtime_network_boundary_is_loopback_only(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        desktop_entry = (
            repository / "backend" / "app" / "desktop_entry.py"
        ).read_text(encoding="utf-8")
        bridge = (
            repository / "frontend" / "src-tauri" / "src" / "api_bridge.rs"
        ).read_text(encoding="utf-8")
        tauri_config = json.loads(
            (repository / "frontend" / "src-tauri" / "tauri.conf.json").read_text(
                encoding="utf-8"
            )
        )
        first_party = "\n".join(
            path.read_text(encoding="utf-8")
            for root in (
                repository / "backend" / "app",
                repository / "frontend" / "src",
                repository / "frontend" / "src-tauri" / "src",
            )
            for path in root.rglob("*")
            if path.is_file() and path.suffix in {".py", ".js", ".jsx", ".rs"}
        ).casefold()
        self.assertIn('loopback_host = "127.0.0.1"', desktop_entry.casefold())
        self.assertIn("tcpstream::connect_timeout(&endpoint.address", bridge.casefold())
        self.assertIn("http://ipc.localhost", tauri_config["app"]["security"]["csp"])
        for prohibited in (
            "tauri_plugin_updater",
            "reqwest::client",
            "requests.post(",
            "requests.put(",
            "urllib.request.urlopen",
            "socket.create_connection",
        ):
            self.assertNotIn(prohibited, first_party)


if __name__ == "__main__":
    unittest.main()
