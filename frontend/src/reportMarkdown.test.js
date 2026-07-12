import assert from "node:assert/strict";
import test from "node:test";

import { buildScanReportMarkdown } from "./reportMarkdown.js";

const FINDINGS = [
  finding("manifest", "package.json", "Manifest explanation."),
  finding("lockfile", "package-lock.json", "Lockfile explanation."),
  finding("package-lifecycle-script", "package.json", "Lifecycle explanation.", { script: "postinstall" }),
  finding("secret-looking-file", ".env.local", "Secret explanation."),
  finding("executable-or-script-file", "scripts/setup.ps1", "Executable explanation."),
  finding(
    "suspicious-text-pattern",
    "src/[loader]*`test`.js",
    "Review *carefully* [before] using `eval`.",
    { pattern: "eval(", match_count: 2 },
  ),
  finding("symlink-or-reparse-point", "linked/config", "Linked-path explanation."),
  finding("hardlink", "shared/tool.exe", "Hardlink explanation."),
  finding("filesystem-entry-inspection-error", "locked/file.txt", "Inspection explanation."),
  finding("package-json-read-error", "examples/package.json", "Parse explanation."),
  finding("future-scanner-signal", "future/item.dat", "Future explanation.", {
    evidence: { matches: 3, source: "future_scanner" },
  }),
];

test("exports every current and future finding with complete detailed evidence", () => {
  const markdown = buildScanReportMarkdown(
    scanResult(FINDINGS),
    reportFixture({ totalFindings: 999 }),
    comparisonFixture(),
    trustContextFixture(),
  );

  assert.match(markdown, /^## Findings$/m);
  const findingNumbers = Array.from(markdown.matchAll(/^### Finding (\d+):/gm), (match) => Number(match[1]));
  assert.deepEqual(findingNumbers, Array.from({ length: FINDINGS.length }, (_, index) => index + 1));
  assert.match(markdown, new RegExp(`^Findings: ${FINDINGS.length}$`, "m"));
  assert.doesNotMatch(markdown, /^Findings: 999$/m);

  for (const item of FINDINGS) {
    assert.equal(markdown.match(new RegExp("^- Type: `" + escapeRegExp(item.type) + "`$", "gm"))?.length, 1);
    assert.match(markdown, new RegExp(escapeRegExp(item.path)));
    assert.match(markdown, new RegExp(escapeRegExp(item.explanation.replaceAll("*", "\\*").replaceAll("[", "\\[").replaceAll("]", "\\]").replaceAll("`", "\\`"))));
    assert.match(markdown, new RegExp(escapeRegExp(item.action)));
  }

  assert.match(markdown, /- Category: executable file/);
  assert.match(markdown, /- Category: zone\/metadata/);
  assert.match(markdown, /- Category: symlink or reparse point/);
  assert.match(markdown, /- Category: hardlink/);
  assert.match(markdown, /- Category: filesystem entry inspection error/);
  assert.match(markdown, /- Category: future scanner signal/);
  assert.match(markdown, /- Metadata:/);
  assert.match(markdown, /- Match count: `2`/);
  assert.match(markdown, /- Pattern: `eval\(`/);
  assert.match(markdown, /- Evidence: `\{"matches":3,"source":"future_scanner"\}`/);

  for (const heading of [
    "Summary",
    "Risk score",
    "Manifests",
    "Lockfiles",
    "Lifecycle scripts",
    "Secrets",
    "Ignored files",
    "Reviewed files",
    "Zone",
    "Trust Profile Context",
    "Comparison with previous scan",
  ]) {
    assert.match(markdown, new RegExp(`^## ${escapeRegExp(heading)}$`, "m"));
  }
  assert.match(markdown, /Project: `Z:\\workspace\\project`/);
  assert.match(markdown, /- Package managers: npm/);
  assert.match(markdown, /- Risk: LOW to HIGH/);
});

test("unknown findings with missing optional fields remain visible without empty placeholders", () => {
  const markdown = buildScanReportMarkdown(
    scanResult([
      {
        type: "brand-new-check",
        severity: "medium",
        message: "A future scanner message.",
        optional_value: null,
        unused_value: undefined,
        _internal_sort_key: "do-not-export",
        details: {
          count: 0,
          enabled: false,
          empty: "",
          ignored: null,
          tags: ["one", null, "", 0, false],
          _private: "do-not-export",
        },
      },
    ]),
    reportFixture(),
    null,
    { configured: false },
  );

  assert.match(markdown, /^Findings: 1$/m);
  assert.match(markdown, /^### Finding 1: brand new check$/m);
  assert.match(markdown, /- Type: `brand-new-check`/);
  assert.match(markdown, /- Message: A future scanner message\./);
  assert.match(markdown, /- Recommended action: Review this item before running, sharing, or committing the project\./);
  assert.doesNotMatch(markdown, /- Path:/);
  assert.doesNotMatch(markdown, /- Explanation:/);
  assert.doesNotMatch(markdown, /optional value|unused value/i);
  assert.doesNotMatch(markdown, /internal sort key|private|do-not-export/i);
  assert.match(markdown, /- Details: `\{"count":0,"enabled":false,"tags":\["one",0,false\]\}`/);
  assert.doesNotMatch(markdown, /undefined|null/);
  assert.doesNotMatch(markdown, /\[object Object\]/);
});

test("finding order and Markdown escaping are deterministic", () => {
  const result = scanResult(FINDINGS);
  const original = structuredClone(result);
  const forward = buildScanReportMarkdown(result, reportFixture(), null, { configured: false });
  const reversed = buildScanReportMarkdown(
    { ...result, findings: [...FINDINGS].reverse() },
    reportFixture(),
    null,
    { configured: false },
  );

  assert.equal(reversed, forward);
  assert.deepEqual(result, original);
  assert.match(forward, /``src\/\[loader\]\*`test`\.js``/);
  assert.match(forward, /Review \\\*carefully\\\* \\\[before\\\] using \\`eval\\`\./);
});

test("legacy summary sections preserve input order and omit malformed empty rows", () => {
  const report = reportFixture({
    manifests: ["z-manifest.json", "a-manifest.json", null],
    lockfiles: ["z.lock", "a.lock"],
    lifecycleScripts: [
      { path: "z/package.json", script: "postinstall" },
      { path: "a/package.json", script: "prepare" },
      {},
    ],
    secretFiles: ["z.secret", "a.secret"],
    ignoredFiles: ["z.ignore", "a.ignore"],
    reviewedFiles: ["z.js", "a.js"],
  });
  const trustContext = {
    ...trustContextFixture(),
    packageManagers: ["zpm", "apm"],
    manifests: [
      { status: "Unexpected", path: "z-manifest.json" },
      { status: "Expected", path: "a-manifest.json" },
      {},
    ],
  };

  const markdown = buildScanReportMarkdown(scanResult([]), report, null, trustContext);

  assertOrdered(markdown, "`z-manifest.json`", "`a-manifest.json`");
  assertOrdered(markdown, "`z.lock`", "`a.lock`");
  assertOrdered(markdown, "`z/package.json`: postinstall", "`a/package.json`: prepare");
  assertOrdered(markdown, "`z.secret`", "`a.secret`");
  assertOrdered(markdown, "`z.ignore`", "`a.ignore`");
  assertOrdered(markdown, "`z.js`", "`a.js`");
  assertOrdered(markdown, "zpm, apm", "- Risk tolerance:");
  assertOrdered(markdown, "Unexpected: `z-manifest.json`", "Expected: `a-manifest.json`");
  assert.doesNotMatch(markdown, /^-\s*:\s*$/m);
  assert.doesNotMatch(markdown, /^\s+-\s*:\s*$/m);
});

function finding(type, path, explanation, metadata = {}) {
  return {
    type,
    severity: type === "lockfile" || type === "manifest" ? "low" : "high",
    path,
    explanation,
    action: `Action for ${type}.`,
    ...metadata,
  };
}

function scanResult(findings) {
  return {
    project_path: "Z:\\workspace\\project",
    scan_date: "2026-07-11T12:00:00Z",
    overall_risk: "high",
    findings,
  };
}

function reportFixture(overrides = {}) {
  return {
    totalFindings: FINDINGS.length,
    reviewedFileCount: 14,
    ignoredFileCount: 2,
    manifests: ["package.json"],
    lockfiles: ["package-lock.json"],
    lifecycleScripts: [{ path: "package.json", script: "postinstall" }],
    secretFiles: [".env.local"],
    ignoredFiles: ["dist/generated.js"],
    reviewedFiles: ["package.json", "src/index.js"],
    zone: "Untrusted",
    ...overrides,
  };
}

function comparisonFixture() {
  return {
    riskChange: "LOW to HIGH",
    findingDelta: "+3 findings",
    reviewedDelta: "+2 reviewed files",
    ignoredDelta: "No change",
    typeSummary: "hardlink: +1",
  };
}

function trustContextFixture() {
  return {
    configured: true,
    packageManagers: ["npm"],
    riskTolerance: "cautious",
    manifests: [{ status: "Expected", path: "package.json" }],
    lockfiles: [{ status: "Expected", path: "package-lock.json" }],
    lifecycleScripts: [{ status: "Needs review", path: "package.json: postinstall" }],
    reviewedPaths: [],
    ignoredPaths: [],
    notes: "Review before install.",
  };
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function assertOrdered(value, first, second) {
  assert.ok(value.indexOf(first) >= 0, `Missing ${first}`);
  assert.ok(value.indexOf(second) > value.indexOf(first), `${second} should follow ${first}`);
}
