from __future__ import annotations

import base64
import hashlib
import io
import json
import sqlite3
import tempfile
import unittest
import zipfile
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote
from unittest.mock import patch

from app import database, main
from app.finding_explainability import build_finding_explainability
from app.finding_reviews import finding_fingerprint
from app.privacy import (
    REDACTED_PROJECT_PATH,
    bounded_text_excerpt,
    safe_project_relative_path,
    sanitize_dependency_locator,
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
from app.trusted_dependency_baseline import approval_for_analysis, snapshot_from_analysis
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


def percent_encode(value: str, rounds: int) -> str:
    for _ in range(rounds):
        value = quote(value, safe="")
    return value


LOCATOR_CASES = {
    "single-encoded-url": (
        percent_encode(
            "https://g099-single-user:g099-single-password@github.com/org/single.git?token=g099-single-query#g099-single-fragment",
            1,
        ),
        "https://github.com/org/single.git",
        ("g099-single-user", "g099-single-password", "g099-single-query", "g099-single-fragment"),
    ),
    "double-encoded-url": (
        percent_encode(
            "https://g099-double-user:g099-double-password@github.com/org/double.git?token=g099-double-query#g099-double-fragment",
            2,
        ),
        "https://github.com/org/double.git",
        ("g099-double-user", "g099-double-password", "g099-double-query", "g099-double-fragment"),
    ),
    "triple-encoded-url": (
        percent_encode(
            "https://g099-triple-user:g099-triple-password@github.com/org/triple.git?token=g099-triple-query#g099-triple-fragment",
            3,
        ),
        "https://github.com/org/triple.git",
        ("g099-triple-user", "g099-triple-password", "g099-triple-query", "g099-triple-fragment"),
    ),
    "eight-round-url": (
        percent_encode(
            "https://g099-eight-user:g099-eight-password@github.com/org/eight.git?token=g099-eight-query#g099-eight-fragment",
            8,
        ),
        "https://github.com/org/eight.git",
        ("g099-eight-user", "g099-eight-password", "g099-eight-query", "g099-eight-fragment"),
    ),
    "beyond-bound-url": (
        percent_encode(
            "https://g099-bound-user:g099-bound-password@github.com/org/bound.git?token=g099-bound-query#g099-bound-fragment",
            9,
        ),
        "redacted dependency locator",
        ("g099-bound-user", "g099-bound-password", "g099-bound-query", "g099-bound-fragment"),
    ),
    "g100-over-bound-scp": (
        percent_encode("git@internal:org/repo#pvtS7", 9),
        "redacted dependency locator",
        ("pvtS7",),
    ),
    "g100-malformed-scp": (
        "git@internal:org/repo%ZZ#pvtM7",
        "redacted dependency locator",
        ("pvtM7",),
    ),
    "g100-over-bound-url-suffix": (
        "https://github.com/org/repo.git"
        + percent_encode("?token=pvtQ7#pvtF7", 9),
        "redacted dependency locator",
        ("pvtQ7", "pvtF7"),
    ),
    "g100-encoded-slash-userinfo": (
        "https://pvtU7:443%2FpvtP7%40github.com/org/repo.git"
        "?token=pvtQ8#pvtF8",
        "https://github.com/org/repo.git",
        ("pvtU7", "pvtP7", "pvtQ8", "pvtF8"),
    ),
    "g100-double-userinfo": (
        "https://pvtD1:443%252FpvtD2%2540github.com/org/double.git"
        "?token=pvtD3#pvtD4",
        "https://github.com/org/double.git",
        ("pvtD1", "pvtD2", "pvtD3", "pvtD4"),
    ),
    "g100-backslash-userinfo": (
        "https://pvtB1%3ApvtB2%5CpvtB3%40github.com/org/backslash.git"
        "?token=pvtB4#pvtB5",
        "https://github.com/org/backslash.git",
        ("pvtB1", "pvtB2", "pvtB3", "pvtB4", "pvtB5"),
    ),
    "g102-minimal-mixed-path": (
        "https://mxu4a:1/mxp4b%40x/y",
        "redacted dependency locator",
        ("mxu4a", "mxp4b"),
    ),
    "g102-full-mixed-path": (
        "https://mxu4a:443/mxp4b%40github.com/fresh/ice.git"
        "?token=mxq4c#mxf4d",
        "redacted dependency locator",
        ("mxu4a", "mxp4b", "mxq4c", "mxf4d"),
    ),
    "g103-mixed-at-depth-one": (
        "https://au3a:7443/ap3b"
        + percent_encode("@mirror.example", 1)
        + "/org/one.git?token=aq3c#af3d",
        "redacted dependency locator",
        ("au3a", "ap3b", "aq3c", "af3d"),
    ),
    "g103-mixed-at-depth-two": (
        "https://au3e:7443/ap3f"
        + percent_encode("@mirror.example", 2)
        + "/org/two.git?token=aq3g#af3h",
        "redacted dependency locator",
        ("au3e", "ap3f", "aq3g", "af3h"),
    ),
    "g103-mixed-at-depth-eight": (
        "https://au3i:7443/ap3j"
        + percent_encode("@mirror.example", 8)
        + "/org/eight.git?token=aq3k#af3l",
        "redacted dependency locator",
        ("au3i", "ap3j", "aq3k", "af3l"),
    ),
    "g103-encoded-colon-in-path": (
        "https://github.com/org/pc3m%3Apc3n/repo.git",
        "redacted dependency locator",
        ("pc3m", "pc3n"),
    ),
    "g103-encoded-slash-in-path": (
        "https://github.com/org/ps3o%2Fps3p.git",
        "redacted dependency locator",
        ("ps3o", "ps3p"),
    ),
    "g103-encoded-backslash-in-path": (
        "https://github.com/org/pb3q%5Cpb3r.git",
        "redacted dependency locator",
        ("pb3q", "pb3r"),
    ),
    "g103-mixed-path-markers": (
        "https://mirror.example:9443/org/pm3s%253Apm3t%2540host.example/repo.git",
        "redacted dependency locator",
        ("pm3s", "pm3t"),
    ),
    "g103-benign-encoded-period": (
        "https://github.com/org/repo%2Egit",
        "https://github.com/org/repo.git",
        (),
    ),
    "g103-legitimate-port": (
        "https://github.com:8443/org/port.git",
        "https://github.com:8443/org/port.git",
        (),
    ),
    "encoded-delimiters-userinfo": (
        "https://g097-user%3Ag097-password%40github.com/org/encoded.git%3Ftoken%3Dg097-query%23g097-encoded-selector",
        "https://github.com/org/encoded.git",
        ("g097-user", "g097-password", "g097-query", "g097-encoded-selector"),
    ),
    "provider-selector": (
        "github:org/provider.git@g097-provider-selector",
        "github:org/provider.git",
        ("g097-provider-selector",),
    ),
    "bare-selector": (
        "org/bare.git@g097-bare-selector",
        "org/bare.git",
        ("g097-bare-selector",),
    ),
    "https-selector": (
        "https://github.com/org/https.git@g097-https-selector",
        "https://github.com/org/https.git",
        ("g097-https-selector",),
    ),
    "scp-selector": (
        "git@github.com:org/scp.git%23g097-scp-selector",
        "vcs:github.com/org/scp.git",
        ("g097-scp-selector",),
    ),
    "scp-no-dot-alias": (
        "git@internal:org/private.git%23g099-internal-selector",
        "vcs:internal/org/private.git",
        ("g099-internal-selector",),
    ),
    "scp-hostname-safe-alias": (
        "user@build-node-07:org/private.git%3Ftoken%3Dg099-alias-query%23g099-alias-fragment",
        "vcs:build-node-07/org/private.git",
        ("g099-alias-query", "g099-alias-fragment"),
    ),
    "scp-encoded-at-selector": (
        "deploy@host:org/private.git%40g099-scp-at-selector",
        "vcs:host/org/private.git",
        ("g099-scp-at-selector",),
    ),
    "malformed-scheme": (
        "https:/g097-malformed-user:g097-malformed-password@github.com/org/malformed.git#g097-malformed-selector",
        "malformed remote source",
        ("g097-malformed-user", "g097-malformed-password", "g097-malformed-selector"),
    ),
}
G104_SAME_ROUND_LOCATOR = (
    "https%3A%2F%2Fhush104aa.example%2Fhush104bb%40x%2Fy"
)
G105_SYNTHETIC_TOKEN = "ghp_G105syntheticOnly0123456789abcdefAB"
G105_LOCATOR_CASES = {
    "g105-exact-g104": (
        G104_SAME_ROUND_LOCATOR,
        "redacted dependency locator",
        ("hush104aa", "hush104bb"),
    ),
    "g105-credential-shaped": (
        percent_encode(
            f"https://safe.example/{G105_SYNTHETIC_TOKEN}@x/y",
            1,
        ),
        "redacted dependency locator",
        (G105_SYNTHETIC_TOKEN,),
    ),
    "g105-same-round-colon": (
        percent_encode(
            "https://g105colonhost.example/g105colonpath:pivot/repository.git",
            1,
        ),
        "redacted dependency locator",
        ("g105colonhost", "g105colonpath"),
    ),
    "g105-same-round-backslash": (
        percent_encode(
            "https://g105backhost.example/g105backpath\\pivot/repository.git",
            1,
        ),
        "redacted dependency locator",
        ("g105backhost", "g105backpath"),
    ),
    "g105-stripped-components": (
        percent_encode(
            "https://g105user:g105password@github.com/org/repository.git"
            "?token=g105query#g105fragment",
            1,
        ),
        "https://github.com/org/repository.git",
        ("g105user", "g105password", "g105query", "g105fragment"),
    ),
    "g105-depth-two": (
        percent_encode(
            "https://g105d2host.example/g105d2path@x/y",
            2,
        ),
        "redacted dependency locator",
        ("g105d2host", "g105d2path"),
    ),
    "g105-depth-eight": (
        percent_encode(
            "https://g105d8host.example/g105d8path@x/y",
            8,
        ),
        "redacted dependency locator",
        ("g105d8host", "g105d8path"),
    ),
    "g105-beyond-bound": (
        percent_encode(
            "https://g105d9host.example/g105d9path@x/y",
            9,
        ),
        "redacted dependency locator",
        ("g105d9host", "g105d9path"),
    ),
    "g105-url-before-selector": (
        percent_encode(
            "https://g105earlyhost.example/g105earlypath",
            1,
        )
        + percent_encode("@x/y", 2),
        "redacted dependency locator",
        ("g105earlyhost", "g105earlypath"),
    ),
    "g105-selector-before-url": (
        percent_encode(
            "https://g105latehost.example/g105latepath",
            2,
        )
        + percent_encode("@x/y", 1),
        "redacted dependency locator",
        ("g105latehost", "g105latepath"),
    ),
    "g105-authority-before-path": (
        percent_encode("https://g105aphost.example", 1)
        + percent_encode("/g105appath@x/y", 2),
        "redacted dependency locator",
        ("g105aphost", "g105appath"),
    ),
    "g105-partial-components": (
        percent_encode("https://g105pcuser:g105pcpassword@", 1)
        + percent_encode(
            "g105pchost.example/g105pcpath@x/y",
            2,
        )
        + percent_encode("?token=g105pcquery#g105pcfragment", 3),
        "redacted dependency locator",
        (
            "g105pcuser",
            "g105pcpassword",
            "g105pchost",
            "g105pcpath",
            "g105pcquery",
            "g105pcfragment",
        ),
    ),
}
LOCATOR_CASES.update(G105_LOCATOR_CASES)
G105_COMPATIBILITY_CASES = {
    "ordinary-https": (
        "https://github.com/org/repository.git",
        "https://github.com/org/repository.git",
    ),
    "ordinary-port": (
        "https://github.com:8443/org/repository.git",
        "https://github.com:8443/org/repository.git",
    ),
    "encoded-non-structural": (
        "https://github.com/org/repository%2Egit",
        "https://github.com/org/repository.git",
    ),
    "encoded-userinfo": (
        "https://g105controluser%3Ag105controlpassword%40"
        "github.com/org/repository.git",
        "https://github.com/org/repository.git",
    ),
    "fully-encoded-safe-url": (
        percent_encode("https://github.com/org/encoded-safe.git", 1),
        "https://github.com/org/encoded-safe.git",
    ),
    "literal-selector": (
        "https://github.com/org/repository.git@g105controlselector",
        "https://github.com/org/repository.git",
    ),
    "provider": (
        "github:org/repository.git@g105controlselector",
        "github:org/repository.git",
    ),
    "scp": (
        "git@github.com:org/repository.git%23g105controlselector",
        "vcs:github.com/org/repository.git",
    ),
    "bare": (
        "org/repository.git@g105controlselector",
        "org/repository.git",
    ),
    "scoped-npm": (
        "npm:@scope/package@1.0.0",
        "npm:@scope/package@1.0.0",
    ),
}
G106_UNICODE_CANARY = "ghp_G106UnicodeCanary0123456789abcdefAB"
G106_PROVIDER_CANARY = "ghp_G106ProviderCanary0123456789abcdefAB"
G106_SCP_CANARY = "ghp_G106ScpCanary0123456789abcdefAB"
G106_BARE_CANARY = "ghp_G106BareCanary0123456789abcdefAB"
G106_HOSTILE_CASES = {
    "unicode-fullwidth-at": (
        percent_encode(
            f"https://safe.example/{G106_UNICODE_CANARY}\uff20x/y",
            1,
        ),
        (G106_UNICODE_CANARY,),
    ),
    "unicode-small-at-mixed-rounds": (
        percent_encode("https://safe.example", 1)
        + percent_encode(
            f"/ghp_G106SmallAtCanary0123456789abcdefAB\ufe6bx/y",
            2,
        ),
        ("ghp_G106SmallAtCanary0123456789abcdefAB",),
    ),
    "provider-manufactured-at": (
        f"github:{G106_PROVIDER_CANARY}%40x/y",
        (G106_PROVIDER_CANARY,),
    ),
    "provider-manufactured-prefix-and-path": (
        "github%3Aorg%2Fghp_G106ProviderPrefixCanary0123456789abcdefAB%40selector",
        ("ghp_G106ProviderPrefixCanary0123456789abcdefAB",),
    ),
    "provider-manufactured-query": (
        "github:ghp_G106ProviderQueryCanary0123456789abcdefAB%3Fx/y",
        ("ghp_G106ProviderQueryCanary0123456789abcdefAB",),
    ),
    "scp-manufactured-path-and-selector": (
        f"git@github.com:{G106_SCP_CANARY}%2Frepo%40selector",
        (G106_SCP_CANARY,),
    ),
    "bare-manufactured-path-and-selector": (
        f"{G106_BARE_CANARY}%2Frepo%40selector",
        (G106_BARE_CANARY,),
    ),
    "encoded-plus-and-later-at": (
        "git%2Bhttps://safe.example/org/"
        "ghp_G106PlusCanary0123456789abcdefAB%2540x/y",
        ("ghp_G106PlusCanary0123456789abcdefAB",),
    ),
    "backslash-slash-composition": (
        "https%3A%2F%2Fsafe.example%2Forg%2F"
        "ghp_G106BackslashCanary0123456789abcdefAB%255Cpivot%252Fx",
        ("ghp_G106BackslashCanary0123456789abcdefAB",),
    ),
}
G107_CONVERGENCE_CASES = {
    "g107-fullwidth-percent": (
        "github:org/repo%EF%BC%852540g107-private-selector",
        "redacted dependency locator",
        ("g107-private-selector",),
    ),
    "g107-nfkc-provider": (
        "\uff47\uff49\uff54\uff48\uff55\uff42:org/repo%40g107-private-selector",
        "redacted dependency locator",
        ("g107-private-selector",),
    ),
}
LOCATOR_CASES.update(G107_CONVERGENCE_CASES)
G108_MULTIPLE_SELECTOR_CASES = {
    "g108-provider-multi-at": (
        "github:org/repository@g108-private-selector@release",
        "github:org/repository",
        ("g108-private-selector",),
    ),
    "g108-url-multi-at": (
        "https://github.com/org/repository.git@g108-private-selector@release",
        "https://github.com/org/repository.git",
        ("g108-private-selector",),
    ),
    "g108-scp-multi-at": (
        "git@github.com:org/repository.git@g108-private-selector@release",
        "vcs:github.com/org/repository.git",
        ("g108-private-selector",),
    ),
}
LOCATOR_CASES.update(G108_MULTIPLE_SELECTOR_CASES)
LOCATOR_CANARIES = tuple(
    canary
    for _, _, canaries in LOCATOR_CASES.values()
    for canary in canaries
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
    *LOCATOR_CANARIES,
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

    def test_persistence_sanitizer_fails_closed_for_locator_fields(self) -> None:
        value = {
            "requestedSpecification": "owner/repository#private-selector",
            "resolvedVersion": "https://user:password@github.com/org/repository.git?token=query-secret#fragment-secret",
            "metadata": {
                "resolvedVersion": "github:owner/repository?token=metadata-query#metadata-fragment",
            },
        }
        sanitized = sanitize_scan_value(value, project_root=r"C:\workspace\project")
        serialized = json.dumps(sanitized, sort_keys=True)
        self.assertEqual(sanitized["requestedSpecification"], "owner/repository")
        self.assertEqual(sanitized["resolvedVersion"], "https://github.com/org/repository.git")
        self.assertEqual(sanitized["metadata"]["resolvedVersion"], "github:owner/repository")
        for secret in ("private-selector", "user", "password", "query-secret", "fragment-secret", "metadata-query", "metadata-fragment"):
            self.assertNotIn(secret, serialized)

    def test_dependency_locator_representations_remove_private_selectors(self) -> None:
        nested = {
            "metadata": {
                label: {"source": locator}
                for label, (locator, _, _) in LOCATOR_CASES.items()
            },
            "ordinary": {
                "version": "1.2.3",
                "package": "@scope/package",
                "sentence": "review owner/repository with the maintainer",
            },
        }
        sanitized = sanitize_scan_value(nested, project_root=r"C:\workspace\project")
        serialized = json.dumps(sanitized, sort_keys=True).casefold()

        for label, (locator, expected, canaries) in LOCATOR_CASES.items():
            self.assertEqual(sanitize_dependency_locator(locator), expected, label)
            self.assertEqual(sanitized["metadata"][label]["source"], expected, label)
            for canary in canaries:
                self.assertNotIn(canary.casefold(), serialized, label)
        self.assertEqual(sanitized["ordinary"], nested["ordinary"])

    def test_g105_url_transition_provenance_fails_closed_without_canaries(self) -> None:
        for label, (locator, expected, canaries) in G105_LOCATOR_CASES.items():
            direct = sanitize_dependency_locator(locator)
            nested_value = sanitize_scan_value(
                {"requestedSpecification": locator},
                project_root=r"C:\workspace\project",
            )["requestedSpecification"]
            self.assertEqual(direct, expected, label)
            self.assertEqual(nested_value, expected, label)
            direct_folded = direct.casefold()
            nested_folded = json.dumps(nested_value, ensure_ascii=False).casefold()
            for canary in canaries:
                self.assertNotIn(canary.casefold(), direct_folded, label)
                self.assertNotIn(canary.casefold(), nested_folded, label)

    def test_g105_legitimate_dependency_locator_controls_remain_useful(self) -> None:
        for label, (locator, expected) in G105_COMPATIBILITY_CASES.items():
            direct = sanitize_dependency_locator(locator)
            nested = sanitize_scan_value(
                {"requestedSpecification": locator},
                project_root=r"C:\workspace\project",
            )["requestedSpecification"]
            self.assertEqual(direct, expected, label)
            self.assertEqual(nested, expected, label)

    def test_g106_decoded_structure_cannot_retain_private_locator_identity(self) -> None:
        for label, (locator, canaries) in G106_HOSTILE_CASES.items():
            direct = sanitize_dependency_locator(locator)
            nested = sanitize_scan_value(
                {"requestedSpecification": locator},
                project_root=r"C:\workspace\project",
            )["requestedSpecification"]
            self.assertEqual(direct, "redacted dependency locator", label)
            self.assertEqual(nested, "redacted dependency locator", label)
            for output in (direct, nested):
                folded = output.casefold()
                for canary in canaries:
                    self.assertNotIn(canary.casefold(), folded, label)

    def test_g106_nfkc_delimiter_lookalikes_fail_closed(self) -> None:
        lookalikes = {
            "plus": "\uff0b",
            "slash": "\uff0f",
            "backslash": "\uff3c",
            "colon": "\uff1a",
            "at": "\uff20",
            "query": "\uff1f",
            "fragment": "\uff03",
        }
        for label, lookalike in lookalikes.items():
            canary = f"ghp_G106{label.title()}Canary0123456789abcdefAB"
            locator = percent_encode(
                f"https://safe.example/org/{canary}{lookalike}pivot/repository.git",
                1,
            )
            direct = sanitize_dependency_locator(locator)
            nested = sanitize_scan_value(
                {"requestedSpecification": locator},
                project_root=r"C:\workspace\project",
            )["requestedSpecification"]
            self.assertEqual(direct, "redacted dependency locator", label)
            self.assertEqual(nested, "redacted dependency locator", label)
            self.assertNotIn(canary.casefold(), direct.casefold(), label)
            self.assertNotIn(canary.casefold(), nested.casefold(), label)

    def test_g106_structure_sentinel_collisions_fail_closed_or_remain_inert(self) -> None:
        literal_sentinel = "\ue000"
        inert_locator = f"https://safe.example/org/{literal_sentinel}-repository.git"
        self.assertEqual(sanitize_dependency_locator(inert_locator), inert_locator)
        self.assertEqual(
            sanitize_scan_value(
                {"requestedSpecification": inert_locator},
                project_root=r"C:\workspace\project",
            )["requestedSpecification"],
            inert_locator,
        )

        collision_canary = "ghp_G106SentinelCanary0123456789abcdefAB"
        collision_cases = (
            percent_encode(
                f"https://safe.example/org/{literal_sentinel}{collision_canary}@x/y",
                1,
            ),
            percent_encode(
                percent_encode(
                    f"https://safe.example/org/{literal_sentinel}{collision_canary}@x/y",
                    1,
                ),
                1,
            ),
        )
        for locator in collision_cases:
            direct = sanitize_dependency_locator(locator)
            nested = sanitize_scan_value(
                {"requestedSpecification": locator},
                project_root=r"C:\workspace\project",
            )["requestedSpecification"]
            self.assertEqual(direct, "redacted dependency locator")
            self.assertEqual(nested, "redacted dependency locator")
            self.assertNotIn(collision_canary.casefold(), direct.casefold())
            self.assertNotIn(collision_canary.casefold(), nested.casefold())

        exhausted = "https://safe.example/org/" + "".join(
            chr(codepoint) for codepoint in range(0xE000, 0xF900)
        )
        exhausted += "/repository.git"
        self.assertEqual(
            sanitize_dependency_locator(exhausted),
            "redacted dependency locator",
        )
        self.assertEqual(
            sanitize_scan_value(
                {"requestedSpecification": exhausted},
                project_root=r"C:\workspace\project",
            )["requestedSpecification"],
            "redacted dependency locator",
        )

    def test_g106_reproduced_bypasses_do_not_reach_serialized_scan_metadata(self) -> None:
        for label in (
            "unicode-fullwidth-at",
            "provider-manufactured-at",
            "scp-manufactured-path-and-selector",
            "bare-manufactured-path-and-selector",
        ):
            locator, canaries = G106_HOSTILE_CASES[label]
            result = sanitize_scan_value(
                {
                    "dependencyTrust": {
                        "entries": [
                            {"requestedSpecification": locator},
                        ],
                    },
                },
                project_root=r"C:\workspace\project",
            )
            persisted = json.dumps(
                {"scan_metadata_json": result},
                ensure_ascii=False,
                sort_keys=True,
            ).casefold()
            self.assertEqual(
                result["dependencyTrust"]["entries"][0]["requestedSpecification"],
                "redacted dependency locator",
                label,
            )
            for canary in canaries:
                self.assertNotIn(canary.casefold(), persisted, label)

    def test_g108_multiple_at_selectors_do_not_enter_trusted_baseline(self) -> None:
        entries = []
        expected_by_name = {}
        for label, (locator, expected, canaries) in G108_MULTIPLE_SELECTOR_CASES.items():
            sanitized = sanitize_scan_value(
                {
                    "metadata": {"source": locator},
                    "requestedSpecification": locator,
                },
                project_root=r"C:\workspace\project",
            )
            self.assertEqual(sanitize_dependency_locator(locator), expected, label)
            self.assertEqual(sanitized["metadata"]["source"], expected, label)
            self.assertEqual(sanitized["requestedSpecification"], expected, label)
            for canary in canaries:
                self.assertNotIn(canary, json.dumps(sanitized), label)
            expected_by_name[label] = expected
            entries.append({
                "ecosystem": "node",
                "name": label,
                "group": "dependencies",
                "requestedSpecification": locator,
                "lockedVersion": "1.0.0",
                "sourceType": "vcs",
                "sourceIdentifier": "vcs:github.com/org/repository",
                "vcsRequestedRevision": (
                    "ref:sha256:"
                    + hashlib.sha256(locator.encode("utf-8")).hexdigest()
                ),
                "integrity": "",
                "integrityPresent": False,
                "direct": True,
                "optional": False,
                "dev": False,
                "peer": False,
                "installScriptIndicator": False,
                "manifestPath": "package.json",
                "lockfilePath": "package-lock.json",
            })

        dependency_trust = sanitize_scan_value(
            {
                "schemaVersion": 1,
                "status": "complete",
                "ecosystems": ["node"],
                "manifests": ["package.json"],
                "lockfiles": ["package-lock.json"],
                "packageManagers": ["npm"],
                "entries": entries,
            },
            project_root=r"C:\workspace\project",
        )
        approval = approval_for_analysis(dependency_trust)
        snapshot = snapshot_from_analysis(dependency_trust)
        self.assertTrue(approval["eligible"])
        self.assertEqual(
            {
                entry["name"]: entry["requestedSpecification"]
                for entry in snapshot["entries"]
            },
            expected_by_name,
        )
        self.assertNotIn("g108-private-selector", json.dumps(snapshot))

        for label in ("provider-selector", "https-selector", "scp-encoded-at-selector"):
            locator, expected, _ = LOCATOR_CASES[label]
            self.assertEqual(sanitize_dependency_locator(locator), expected, label)

    def test_dependency_locator_malformed_inputs_fail_closed_without_false_positives(self) -> None:
        malformed = sanitize_scan_value(
            {
                "requestedSpecification": (
                    "https%ZZg099-malformed-user:g099-malformed-password@"
                    "github.com/org/repository.git#g099-malformed-fragment"
                )
            },
            project_root=r"C:\workspace\project",
        )
        self.assertEqual(
            malformed["requestedSpecification"],
            "redacted dependency locator",
        )

        negative_controls = (
            "label:value",
            "release:1.2.3",
            "@scope/package",
            "owner/repository",
            r"C:relative\package.json",
            "registry:org/package",
            "git@@internal:org/repository",
            "git@-internal:org/repository",
            "git@internal:single-segment",
            "review owner/repository with the maintainer",
        )
        for value in negative_controls:
            sanitized = sanitize_scan_value(
                {"metadata": {"source": value}},
                project_root=r"C:\workspace\project",
            )
            self.assertEqual(sanitized["metadata"]["source"], value)

        ordinary_versions = ("1.2.3", "^2.4.0", "workspace:*", "npm:@scope/package@1.0.0")
        for value in ordinary_versions:
            sanitized = sanitize_scan_value(
                {"requestedSpecification": value},
                project_root=r"C:\workspace\project",
            )
            self.assertEqual(sanitized["requestedSpecification"], value)


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
                    },
                    {
                        "ecosystem": "node",
                        "name": "locator-boundary",
                        "version": "0.0.0",
                        "group": "runtime",
                        "direct": True,
                        "manifestPath": "package.json",
                        "lockfilePath": "package-lock.json",
                        "sourceType": "vcs",
                        "sourceIdentifier": "vcs:github.com/org/locator-boundary.git",
                        "requested": LOCATOR_CASES["triple-encoded-url"][0],
                        "lockedVersion": LOCATOR_CASES["scp-no-dot-alias"][0],
                        "metadata": {
                            label: {"source": locator}
                            for label, (locator, _, _) in LOCATOR_CASES.items()
                        },
                        "integrityStatus": "not-applicable",
                    },
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
        locator_entry = scan["dependencyTrust"]["entries"][1]
        self.assertEqual(
            locator_entry["requested"],
            LOCATOR_CASES["triple-encoded-url"][1],
        )
        self.assertEqual(
            locator_entry["lockedVersion"],
            LOCATOR_CASES["scp-no-dot-alias"][1],
        )
        for label, (_, expected, _) in LOCATOR_CASES.items():
            self.assertEqual(locator_entry["metadata"][label]["source"], expected)

        history = main.scan_history(str(self.project))["scans"]
        self.assertEqual(len(history), 1)
        self.assert_private_canaries_absent(history)
        self.assertEqual(
            history[0]["dependencyTrust"]["entries"][1]["requested"],
            LOCATOR_CASES["triple-encoded-url"][1],
        )

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
