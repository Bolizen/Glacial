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
    "Raw risk",
    "Finding review status",
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

test("review status preserves raw evidence and separates unresolved risk", () => {
  const reviewed = {
    ...finding("suspicious-text-pattern", "tests/fixture.py", "Expected eval fixture.", { pattern: "eval(" }),
    fingerprint: `cf1_${"a".repeat(64)}`,
    review: {
      status: "expected",
      note: "Regression fixture for the scanner.",
      created_at: "2026-07-12T10:00:00Z",
      updated_at: "2026-07-12T10:00:00Z",
    },
  };
  const unresolved = {
    ...finding("secret-looking-file", ".env.example", "Review this filename."),
    severity: "low",
    fingerprint: `cf1_${"b".repeat(64)}`,
    review: null,
  };
  const markdown = buildScanReportMarkdown(
    scanResult([reviewed, unresolved]),
    reportFixture({ totalFindings: 2 }),
    null,
    { configured: false },
  );

  assert.match(markdown, /^## Raw risk\nHIGH$/m);
  assert.match(markdown, /- Raw findings: 2/);
  assert.match(markdown, /- Reviewed findings: 1/);
  assert.match(markdown, /- Unresolved findings: 1/);
  assert.match(markdown, /- Highest unreviewed severity: LOW/);
  assert.match(markdown, /- Review status: Reviewed as expected/);
  assert.match(markdown, /- Review reason: Regression fixture for the scanner\./);
  assert.match(markdown, /Expected eval fixture\./);
  assert.equal(markdown.match(/Expected eval fixture\./g)?.length, 1);
  assert.match(markdown, /- Review status: Unreviewed/);
  assert.doesNotMatch(markdown, /cf1_[a-f0-9]{64}|created at|updated at/i);
});

test("review reasons cannot inject HTML or break Markdown structure", () => {
  const result = scanResult([{
    ...finding("suspicious-text-pattern", "tests/fixture.py", "Fixture evidence.", { pattern: "eval(" }),
    fingerprint: `cf1_${"c".repeat(64)}`,
    review: {
      status: "expected",
      note: "Expected fixture.\n<script>alert('x')</script> [unsafe](https://example.invalid)",
    },
  }]);
  const markdown = buildScanReportMarkdown(result, reportFixture({ totalFindings: 1 }), null, { configured: false });

  assert.ok(markdown.includes("- Review reason: Expected fixture. \\<script\\>alert('x')\\</script\\> \\[unsafe\\](https://example.invalid)"));
  assert.doesNotMatch(markdown, /<script>|\[unsafe\]\(https:\/\/example\.invalid\)/);
  assert.equal(markdown.match(/^### Finding \d+:/gm)?.length, 1);
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

test("exports complete, incomplete, and unknown scan coverage conservatively", () => {
  const emptyReport = reportFixture({
    manifests: [],
    lockfiles: [],
    lifecycleScripts: [],
    secretFiles: [],
    ignoredFiles: [],
    reviewedFiles: [],
    ignoredFileCount: 0,
    reviewedFileCount: 0,
    zone: "Unknown",
  });
  const incomplete = buildScanReportMarkdown({
    ...scanResult([]),
    scanCompleteness: {
      complete: false,
      traversalFailureCount: 1,
      fileInspectionFailureCount: 2,
      oversizedFileCount: 3,
      unsafePathCount: 1,
      policyExcludedFileCount: 4,
      resourceBudgetExceededCount: 5,
      issueCount: 16,
    },
  }, emptyReport, null, { configured: false });
  assert.match(incomplete, /^## Scan completeness$/m);
  assert.match(incomplete, /^Status: Incomplete$/m);
  assert.match(incomplete, /Directory traversal failures: 1/);
  assert.match(incomplete, /File inspection\/read failures: 2/);
  assert.match(incomplete, /Oversized files skipped: 3/);
  assert.match(incomplete, /Repository policy exclusions: 4/);
  assert.match(incomplete, /Scanner resource budgets exceeded: 5/);
  assert.match(incomplete, /Total inspection issues: 16/);
  assert.match(incomplete, /No manifests recorded in this scan; coverage incomplete\./);
  assert.match(incomplete, /No lockfiles recorded in this scan; coverage incomplete\./);
  assert.match(incomplete, /No package lifecycle scripts recorded in this scan; coverage incomplete\./);
  assert.match(incomplete, /No secret-looking files recorded in this scan; coverage incomplete\./);
  assert.match(incomplete, /No ignored files recorded in this scan; coverage incomplete\./);
  assert.match(incomplete, /No reviewed files recorded in this scan; coverage incomplete\./);
  assert.match(incomplete, /No zone\/context recorded in this scan; coverage incomplete\./);

  const legacyIgnored = buildScanReportMarkdown({
    ...scanResult([]),
    ignoredFiles: ["package.json"],
    ignoredFileCount: 1,
    scanCompleteness: {
      complete: true,
      traversalFailureCount: 0,
      fileInspectionFailureCount: 0,
      oversizedFileCount: 0,
      unsafePathCount: 0,
      dependencyAnalysisFailureCount: 0,
      issueCount: 0,
    },
  }, reportFixture({
    ignoredFiles: ["package.json"],
    ignoredFileCount: 1,
  }), null, { configured: false });
  assert.match(legacyIgnored, /^Status: Incomplete$/m);
  assert.match(legacyIgnored, /Repository policy exclusions: 1/);
  assert.doesNotMatch(legacyIgnored, /^Status: Complete$/m);

  const complete = buildScanReportMarkdown({
    ...scanResult([]),
    scanCompleteness: {
      complete: true,
      traversalFailureCount: 0,
      fileInspectionFailureCount: 0,
      oversizedFileCount: 0,
      unsafePathCount: 0,
      issueCount: 0,
    },
  }, emptyReport, null, { configured: false });
  assert.match(complete, /^Status: Complete$/m);
  assert.match(complete, /No manifests found\./);
  assert.match(complete, /No lockfiles found\./);
  assert.match(complete, /No package lifecycle scripts found\./);
  assert.match(complete, /No secret-looking files found\./);
  assert.match(complete, /No files ignored by \.glacialignore\./);
  assert.doesNotMatch(complete, /coverage (?:unknown|incomplete)/i);

  const older = buildScanReportMarkdown(scanResult([]), emptyReport, {
    riskChange: "Recorded risk unchanged; coverage comparison unavailable",
    coverageChange: "Unavailable because at least one scan lacks coverage metadata",
    findingDelta: "No change",
  }, { configured: false });
  assert.match(older, /Status: Coverage unknown/);
  assert.doesNotMatch(older, /^Status: Complete$/m);
  assert.match(older, /No manifests recorded in this scan; coverage unknown\./);
  assert.match(older, /No lockfiles recorded in this scan; coverage unknown\./);
  assert.match(older, /No package lifecycle scripts recorded in this scan; coverage unknown\./);
  assert.match(older, /No secret-looking files recorded in this scan; coverage unknown\./);
  assert.match(older, /No ignored files recorded in this scan; coverage unknown\./);
  assert.match(older, /No reviewed files recorded in this scan; coverage unknown\./);
  assert.match(older, /No zone\/context recorded in this scan; coverage unknown\./);
  assert.match(older, /Risk: Recorded risk unchanged; coverage comparison unavailable/);
  assert.match(older, /Coverage: Unavailable because at least one scan lacks coverage metadata/);
});

test("exports dependency trust summaries, changes, limitations, and detailed evidence once", () => {
  const dependencyFinding = finding(
    "dependency-integrity-changed",
    "locks/[prod]|package-lock.json",
    "Integrity `changed` for the same locked material.",
    { package: "alpha", ecosystem: "node" },
  );
  const result = {
    ...scanResult([dependencyFinding]),
    dependencyTrust: {
      schemaVersion: 1,
      status: "incomplete",
      ecosystems: ["node", "python"],
      manifests: ["package.json", "pyproject.toml"],
      lockfiles: ["package-lock.json"],
      directDependencyCount: 1,
      lockedDependencyCount: 2,
      integrityCoverage: { total: 2, present: 1, missing: 1 },
      unusualSourceCount: 1,
      installScriptIndicatorCount: 1,
      consistencyIssueCount: 0,
      entries: [{
        ecosystem: "node",
        name: "alpha|tool",
        group: "dependencies",
        requestedSpecification: "^1|^2",
        lockedVersion: "1.2.0",
        sourceType: "registry",
        sourceIdentifier: "registry.example",
        integrityPresent: true,
        direct: true,
      }],
      comparison: {
        baselineStatus: "available",
        changeCount: 2,
        changes: [{ changeType: "analysis-status-changed", previousValue: "complete", currentValue: "incomplete" }],
        fileChanges: { manifestsAdded: [], manifestsRemoved: [], lockfilesAdded: ["locks/[prod]|package-lock.json"], lockfilesRemoved: [] },
      },
      limitations: [{ reason: "size-limit", path: "locks/[prod]|package-lock.json", explanation: "Lockfile exceeded the local limit." }],
      offlineOnly: true,
    },
  };

  const markdown = buildScanReportMarkdown(result, reportFixture({ totalFindings: 1 }), null, { configured: false });

  assert.match(markdown, /^## Dependency Trust$/m);
  assert.match(markdown, /^Status: Analysis incomplete$/m);
  assert.match(markdown, /Integrity coverage: 1\/2/);
  assert.match(markdown, /alpha\\\|tool/);
  assert.match(markdown, /analysis-status-changed: `incomplete` \(previously `complete`\)/);
  assert.match(markdown, /lockfile-added: `locks\/\[prod\]\|package-lock\.json`/);
  assert.match(markdown, /Offline-only: Glacial did not contact registries/);
  assert.equal(markdown.match(/- Type: `dependency-integrity-changed`/g)?.length, 1);
  assert.doesNotMatch(markdown, /undefined|null|\[object Object\]/);
});

test("dependency Markdown distinguishes empty, unsupported, and legacy analysis", () => {
  const emptyResult = {
    ...scanResult([]),
    dependencyTrust: {
      schemaVersion: 1,
      status: "unsupported",
      ecosystems: [],
      manifests: [],
      lockfiles: [],
      packageManagers: [],
      entries: [],
      comparison: { baselineStatus: "unavailable", changes: [] },
    },
  };
  const empty = buildScanReportMarkdown(emptyResult, reportFixture({ totalFindings: 0 }), null, { configured: false });
  assert.match(empty, /^Status: No supported dependency metadata detected$/m);
  assert.match(empty, /No supported Node or Python dependency graph was analyzed/);
  assert.doesNotMatch(empty, /Integrity coverage: 0\/0|Supported checks complete|clean|verified/i);

  const unsupported = buildScanReportMarkdown({
    ...emptyResult,
    dependencyTrust: { ...emptyResult.dependencyTrust, manifests: ["dependencies.custom"] },
  }, reportFixture({ totalFindings: 0 }), null, { configured: false });
  assert.match(unsupported, /^Status: Unsupported dependency metadata$/m);
  assert.match(unsupported, /format is not supported/);
  assert.doesNotMatch(unsupported, /No supported dependency metadata detected/);

  const legacy = buildScanReportMarkdown(scanResult([]), reportFixture({ totalFindings: 0 }), null, { configured: false });
  assert.match(legacy, /^Status: Analysis unavailable$/m);
  assert.match(legacy, /predates dependency analysis/);
  assert.doesNotMatch(legacy, /No supported dependency metadata detected/);
});

test("dependency Markdown remains bounded for a capped adversarial inventory", () => {
  const entries = Array.from({ length: 80 }, (_, index) => ({
    ecosystem: "node",
    name: `package-${String(index).padStart(3, "0")}`,
    group: "dependencies",
    requestedSpecification: "^1",
    lockedVersion: "1.2.3",
    sourceType: "registry",
    sourceIdentifier: "registry.example",
    integrityPresent: true,
    direct: true,
  }));
  const result = {
    ...scanResult([]),
    dependencyTrust: {
      schemaVersion: 1,
      status: "complete",
      ecosystems: ["node"],
      manifests: ["package.json"],
      lockfiles: ["package-lock.json"],
      directDependencyCount: 80,
      lockedDependencyCount: 80,
      integrityCoverage: { total: 80, present: 80, missing: 0 },
      entries,
      comparison: { baselineStatus: "unavailable", changeCount: 0, changes: [] },
      limitations: [],
      offlineOnly: true,
    },
  };

  const markdown = buildScanReportMarkdown(result, reportFixture({ totalFindings: 0 }), null, { configured: false });

  assert.equal((markdown.match(/^\| node \| package-/gm) || []).length, 50);
  assert.match(markdown, /30 additional normalized entries are omitted/);
  assert.ok(markdown.length < 20_000);
});

test("trusted dependency baseline Markdown distinguishes configuration and comparison states", () => {
  const statuses = [
    ["identical", "Matches approved baseline"],
    ["drift", "Drift detected"],
    ["incomplete", "Comparison incomplete"],
    ["incompatible", "Incompatible"],
    ["invalid", "Baseline unavailable"],
  ];
  for (const [status, label] of statuses) {
    const baseline = markdownBaseline(status);
    const markdown = buildScanReportMarkdown(
      scanResult([]),
      reportFixture({ totalFindings: 0, dependencyTrust: { trustedBaseline: baseline } }),
      null,
      { configured: false },
    );
    assert.match(markdown, /^## Trusted Dependency Baseline$/m);
    assert.match(markdown, new RegExp(`^Status: ${label}$`, "m"));
    assert.match(markdown, /This comparison records explicit baseline drift; it does not verify that dependencies are safe or malware-free/);
  }
});

test("trusted baseline Markdown escapes notes and exports only compact drift evidence", () => {
  const baseline = markdownBaseline("drift", {
    note: "Reviewed <script>bad()</script> [link](https://example.invalid)\nnext line",
    comparison: {
      status: "drift",
      explanation: "Drift detected from approved baseline.",
      changeCount: 3,
      highestSeverity: "high",
      findings: [
        { type: "trusted-baseline-integrity-changed", severity: "high" },
        { type: "trusted-baseline-version-changed", severity: "low" },
        { type: "trusted-baseline-version-changed", severity: "low" },
      ],
    },
    snapshot: { sourceIdentifier: "user:token@example.invalid?secret=yes" },
  });
  const result = {
    ...scanResult([]),
    dependencyTrust: {
      schemaVersion: 1,
      status: "complete",
      ecosystems: ["node"],
      manifests: ["package.json"],
      lockfiles: ["package-lock.json"],
      packageManagers: ["npm"],
      entries: [],
      comparison: { baselineStatus: "available", changeCount: 0, changes: [] },
    },
  };
  const markdown = buildScanReportMarkdown(
    result,
    reportFixture({ totalFindings: 0, dependencyTrust: { trustedBaseline: baseline } }),
    null,
    { configured: false },
  );

  assert.match(markdown, /- Drift changes: 3/);
  assert.match(markdown, /- Highest drift severity: HIGH/);
  assert.match(markdown, /`trusted-baseline-integrity-changed`: 1/);
  assert.match(markdown, /`trusted-baseline-version-changed`: 2/);
  assert.match(markdown, /HIGH `trusted-baseline-integrity-changed`/);
  assert.match(markdown, /LOW `trusted-baseline-version-changed`/);
  assert.ok(markdown.includes("Reviewed \\<script\\>bad()\\</script\\> \\[link\\](https://example.invalid) next line"));
  assert.doesNotMatch(markdown, /<script>|user:token|secret=yes|sourceIdentifier|snapshot/);
  assert.match(markdown, /^## Comparison with previous scan$/m);
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

function markdownBaseline(status, overrides = {}) {
  const comparison = overrides.comparison || {};
  return {
    configured: true,
    valid: status !== "invalid",
    fingerprint: `cfdb2_${"a".repeat(64)}`,
    sourceScanDate: "2026-07-12T10:00:00Z",
    createdAt: "2026-07-12T10:05:00Z",
    note: "Approved locally.",
    comparison: {
      status,
      explanation: `${status} trusted baseline comparison.`,
      changeCount: 0,
      highestSeverity: "none",
      changes: [],
      findings: [],
      ...comparison,
    },
    ...overrides,
    comparison: {
      status,
      explanation: `${status} trusted baseline comparison.`,
      changeCount: 0,
      highestSeverity: "none",
      changes: [],
      findings: [],
      ...comparison,
    },
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
