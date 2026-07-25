import assert from "node:assert/strict";
import test from "node:test";

import { buildProjectSecurityStatus } from "./projectSecurityStatus.js";

test("no scan produces Insufficient evidence", () => {
  const result = buildProjectSecurityStatus({ scans: [], profile: {} });

  assert.equal(result.label, "Insufficient evidence");
  assert.equal(result.sections.find((item) => item.id === "coverage").status, "Indeterminate");
  assert.equal(result.actions[0].id, "run-scan");
});

test("incomplete or malformed latest coverage produces Blocked by incomplete scan", () => {
  const incomplete = completeScan(2);
  incomplete.scanCompleteness = {
    ...incomplete.scanCompleteness,
    complete: false,
    fileInspectionFailureCount: 1,
    issueCount: 1,
  };
  const blocked = statusFor(incomplete, { scans: [incomplete, completeScan(1)] });
  assert.equal(blocked.label, "Blocked by incomplete scan");

  const malformed = completeScan(3);
  malformed.scanCompleteness.issueCount = 5;
  assert.equal(statusFor(malformed, { scans: [malformed] }).label, "Blocked by incomplete scan");
});

test("malformed current metadata and dependency data never produce a positive status", () => {
  const metadata = completeScan(2);
  metadata.scanMetadataReliable = false;
  assert.equal(statusFor(metadata).label, "Insufficient evidence");

  const dependency = completeScan(2);
  const result = statusFor(dependency, {
    report: reportFor(dependency, { status: "malformed" }),
  });
  assert.equal(result.label, "Insufficient evidence");
  assert.equal(result.sections.find((item) => item.id === "dependencies").status, "Indeterminate");

  const unsupported = statusFor(completeScan(3), {
    report: reportFor(completeScan(3), dependencyTrust({
      status: "unsupported",
      packageManagers: ["custom"],
    })),
  });
  assert.equal(unsupported.label, "Insufficient evidence");
  assert.equal(unsupported.sections.find((item) => item.id === "dependencies").status, "Indeterminate");
});

test("reliable unreviewed findings require review and new high findings are significant", () => {
  const low = completeScan(2, {
    findings: [finding("low-1", "low")],
  });
  const review = statusFor(low, { scans: [low] });
  assert.equal(review.label, "Review required");
  assert.equal(review.sections.find((item) => item.id === "findings").counts.needsReview, 1);

  const baseline = completeScan(1);
  const high = completeScan(2, {
    findings: [finding("high-1", "high")],
  });
  const significant = statusFor(high, { scans: [high, baseline] });
  assert.equal(significant.label, "Significant changes detected");
  assert.equal(significant.sections.find((item) => item.id === "findings").counts.newHigh, 1);
});

test("an incomplete target never reports findings as resolved", () => {
  const baseline = completeScan(1, {
    findings: [finding("old-high", "high")],
  });
  const target = completeScan(2);
  target.scanCompleteness = {
    ...target.scanCompleteness,
    complete: false,
    traversalFailureCount: 1,
    issueCount: 1,
  };

  const result = statusFor(target, { scans: [target, baseline] });

  assert.equal(result.label, "Blocked by incomplete scan");
  const findings = result.sections.find((item) => item.id === "findings");
  assert.equal(findings.status, "Indeterminate");
  assert.match(findings.explanation, /prevents claims about absent, removed, or resolved findings/i);
});

test("an unavailable trusted baseline is prominent and never falls back automatically", () => {
  const latest = completeScan(3);
  const automatic = completeScan(2);
  const result = statusFor(latest, {
    scans: [latest, automatic],
    trustedBaseline: {
      configured: true,
      status: "unavailable",
      baseline: { scanId: 1 },
      message: "Reference unavailable.",
    },
  });
  const baseline = result.sections.find((item) => item.id === "baseline");

  assert.equal(result.label, "Significant changes detected");
  assert.equal(result.baselineSource, "Trusted baseline unavailable");
  assert.equal(baseline.status, "Significant change");
  assert.match(baseline.explanation, /no automatic baseline/i);
});

test("a fully reviewed reliable project can be Ready for reviewed work", () => {
  const baseline = completeScan(1, {
    findings: [finding("known-low", "low", "expected")],
  });
  const latest = completeScan(2, {
    findings: [finding("known-low", "low", "expected")],
  });

  const result = statusFor(latest, { scans: [latest, baseline] });

  assert.equal(result.label, "Ready for reviewed work");
  assert.equal(result.actions.length, 0);
  assert.ok(result.sections.filter((item) => item.status !== "Not applicable").every((item) => item.status === "Satisfied"));
  assert.match(result.disclaimer, /not a guarantee/i);
});

test("checkpoint parity boundaries keep not-applicable dependencies ready and new reviewed high findings blocked", () => {
  const noDependencies = dependencyTrust({
    status: "unsupported",
    ecosystems: [],
    manifests: [],
    lockfiles: [],
    packageManagers: [],
    entries: [],
    trustedBaseline: {
      configured: false,
      valid: false,
      comparison: { status: "not-configured" },
    },
  });
  const ordinary = completeScan(10, {
    manifests: [],
    dependencyTrust: { ...noDependencies, available: undefined },
  });
  const ready = statusFor(ordinary, {
    scans: [ordinary],
    report: reportFor(ordinary, noDependencies),
    profile: { reviewedPaths: ["src/index.js"] },
  });
  assert.equal(ready.label, "Ready for reviewed work");
  assert.equal(ready.sections.find((item) => item.id === "dependencies").status, "Not applicable");

  const baseline = completeScan(11);
  const reviewedHigh = completeScan(12, {
    findings: [finding("new-reviewed-high", "high", "expected")],
  });
  const significant = statusFor(reviewedHigh, { scans: [reviewedHigh, baseline] });
  assert.equal(significant.label, "Significant changes detected");
  assert.equal(significant.sections.find((item) => item.id === "findings").counts.newHigh, 1);

  const trusted = statusFor(reviewedHigh, {
    scans: [reviewedHigh],
    trustedBaseline: {
      configured: true,
      status: "valid",
      baseline: { scanId: baseline.id, scan: baseline },
    },
  });
  assert.equal(trusted.label, "Significant changes detected");
  assert.equal(trusted.sections.find((item) => item.id === "findings").counts.newHigh, 1);

  const malformedBaseline = { ...baseline, findings: "malformed" };
  const indeterminate = statusFor(reviewedHigh, {
    scans: [reviewedHigh, malformedBaseline],
  });
  assert.equal(indeterminate.label, "Insufficient evidence");
  assert.equal(indeterminate.sections.find((item) => item.id === "findings").status, "Indeterminate");
});

test("section-level indeterminate state remains visible and actions are conservatively ordered and capped", () => {
  const baseline = completeScan(1);
  const latest = completeScan(2, {
    findings: [finding("high-new", "high")],
  });
  const trust = dependencyTrust({
    comparison: {
      baselineStatus: "available",
      changeCount: 4,
      changes: [
        { changeType: "version-changed", name: "alpha" },
        { changeType: "added", name: "beta" },
        { changeType: "added", name: "gamma" },
        { changeType: "added", name: "delta" },
      ],
    },
    trustedBaseline: {
      configured: true,
      valid: true,
      comparison: { status: "drift" },
    },
  });
  const significant = statusFor(latest, {
    scans: [latest, baseline],
    report: reportFor(latest, trust),
    profile: {},
  });
  assert.deepEqual(significant.actions.map((item) => item.id), [
    "review-high-findings",
    "review-dependencies",
    "create-expectations",
  ]);
  assert.equal(significant.actions.length, 3);

  const unavailable = statusFor(latest, {
    scans: [latest, baseline],
    report: reportFor(latest, { available: false, status: "unavailable" }),
  });
  assert.equal(unavailable.label, "Insufficient evidence");
  assert.equal(unavailable.sections.find((item) => item.id === "dependencies").status, "Indeterminate");
  assert.equal(unavailable.sections.find((item) => item.id === "coverage").status, "Satisfied");
});

test("dismissed suggestions do not hide observed drift and calculation performs no writes", () => {
  const baseline = completeScan(1);
  const latest = completeScan(2, { manifests: ["package.json", "extra.json"] });
  const profile = {
    ...approvedProfile(),
    dismissedSuggestions: { expectedManifestFiles: ["extra.json"] },
  };
  const input = {
    project: { path: "C:/workspace/project" },
    scan: latest,
    scans: [latest, baseline],
    report: reportFor(latest),
    profile,
    trustedBaseline: { configured: false, status: "not-configured" },
  };
  const before = structuredClone(input);

  const result = buildProjectSecurityStatus(input);

  const expectations = result.sections.find((item) => item.id === "expectations");
  assert.equal(expectations.status, "Significant change");
  assert.equal(expectations.counts.added, 1);
  assert.deepEqual(input, before);

  const reviewedPathAddition = completeScan(3, {
    reviewedFiles: ["src/index.js", "src/new.js"],
  });
  const ordinary = statusFor(reviewedPathAddition, {
    scans: [reviewedPathAddition, baseline],
  });
  assert.equal(ordinary.sections.find((item) => item.id === "expectations").status, "Action required");

  const ignoredPathAddition = completeScan(4, {
    ignoredFiles: ["vendor/generated.js"],
  });
  const securityRelevant = statusFor(ignoredPathAddition, {
    scans: [ignoredPathAddition, baseline],
  });
  assert.equal(securityRelevant.sections.find((item) => item.id === "expectations").status, "Significant change");
});

test("unknown historical data is handled conservatively without corrupting current readiness evidence", () => {
  const legacy = { id: 1, scan_date: "not-a-date", findings: "malformed" };
  const latest = completeScan(2);

  const result = statusFor(latest, { scans: [latest, legacy] });

  assert.equal(result.sections.find((item) => item.id === "baseline").status, "Not applicable");
  assert.notEqual(result.sections.find((item) => item.id === "baseline").status, "Satisfied");
});

function statusFor(scan, overrides = {}) {
  return buildProjectSecurityStatus({
    project: { path: "C:/workspace/project", name: "Project" },
    scan,
    scans: overrides.scans || [scan],
    report: overrides.report || reportFor(scan),
    profile: overrides.profile || approvedProfile(),
    trustedBaseline: overrides.trustedBaseline || { configured: false, status: "not-configured" },
  });
}

function completeScan(id, overrides = {}) {
  return {
    id,
    project_path: "C:/workspace/project",
    scan_date: `2026-07-${String(id).padStart(2, "0")}T12:00:00Z`,
    findings: [],
    findingCount: 0,
    reviewedFileCount: 1,
    ignoredFileCount: 0,
    manifests: ["package.json"],
    lockfiles: [],
    lifecycleScripts: [],
    ignoredFiles: [],
    reviewedFiles: ["src/index.js"],
    scanMetadataReliable: true,
    scanCompleteness: {
      complete: true,
      traversalFailureCount: 0,
      fileInspectionFailureCount: 0,
      oversizedFileCount: 0,
      unsafePathCount: 0,
      dependencyAnalysisFailureCount: 0,
      policyExcludedFileCount: 0,
      resourceBudgetExceededCount: 0,
      issueCount: 0,
    },
    dependencyTrust: dependencyTrust(),
    ...overrides,
  };
}

function finding(fingerprint, severity, reviewStatus = "") {
  return {
    fingerprint,
    type: "test-finding",
    path: `src/${fingerprint}.js`,
    severity,
    review: reviewStatus ? { status: reviewStatus, note: "Deliberately reviewed." } : null,
  };
}

function reportFor(scan, trust = dependencyTrust()) {
  return {
    completeness: { known: true, complete: true, issueCount: 0 },
    dependencyTrust: trust,
  };
}

function dependencyTrust(overrides = {}) {
  return {
    available: true,
    schemaVersion: 1,
    status: "complete",
    ecosystems: ["node"],
    manifests: ["package.json"],
    lockfiles: [],
    packageManagers: ["npm"],
    entries: [],
    lockedDependencyCount: 0,
    comparison: {
      baselineStatus: "available",
      changeCount: 0,
      changes: [],
    },
    trustedBaseline: {
      configured: true,
      valid: true,
      comparison: { status: "identical" },
    },
    ...overrides,
  };
}

function approvedProfile() {
  return {
    trustedPackageManagers: ["npm"],
    expectedManifestFiles: ["package.json"],
    expectedEcosystems: ["node"],
    reviewedPaths: ["src/index.js"],
  };
}
