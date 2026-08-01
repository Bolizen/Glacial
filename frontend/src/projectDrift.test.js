import assert from "node:assert/strict";
import test from "node:test";
import { buildProjectDriftSummary } from "./projectDrift.js";

test("no prior complete scan reports that no baseline exists", () => {
  const summary = buildProjectDriftSummary({ scans: [completeScan(2)], profile: {} });

  assert.equal(summary.scanToScan.status, "no-baseline");
  assert.match(summary.scanToScan.message, /baseline has not been established/);
  assert.notEqual(summary.scanToScan.status, "unchanged");
});

test("unchanged complete scans report no observed metadata drift", () => {
  const latest = completeScan(2, { manifests: ["package.json"] });
  const previous = completeScan(1, { manifests: ["package.json"] });
  const summary = buildProjectDriftSummary({ scans: [latest, previous], profile: {} });

  assert.equal(summary.scanToScan.status, "unchanged");
  assert.match(summary.scanToScan.message, /No observed metadata drift was detected/);
  assert.equal(summary.scanToScan.counts.unchanged, 1);
});

test("added observed values stay added when no previous value was removed", () => {
  const summary = buildProjectDriftSummary({
    scans: [
      completeScan(2, { manifests: ["package.json"] }),
      completeScan(1),
    ],
    profile: {},
  });

  assert.deepEqual(category(summary.scanToScan, "expectedManifestFiles").added, ["package.json"]);
  assert.equal(summary.scanToScan.counts.added, 1);
});

test("removed observed values stay removed when no current value replaces them", () => {
  const summary = buildProjectDriftSummary({
    scans: [
      completeScan(2),
      completeScan(1, { lockfiles: ["package-lock.json"] }),
    ],
    profile: {},
  });

  assert.deepEqual(category(summary.scanToScan, "expectedLockfiles").removed, ["package-lock.json"]);
  assert.equal(summary.scanToScan.counts.removed, 1);
});

test("one removed and one added value in a category form a deterministic changed pair", () => {
  const summary = buildProjectDriftSummary({
    scans: [
      completeScan(2, { manifests: ["pyproject.toml"] }),
      completeScan(1, { manifests: ["package.json"] }),
    ],
    profile: {},
  });

  assert.deepEqual(category(summary.scanToScan, "expectedManifestFiles").changed, [{
    before: "package.json",
    after: "pyproject.toml",
  }]);
  assert.equal(summary.scanToScan.counts.changed, 1);
});

test("approved expectation matching a reliable observation is unchanged", () => {
  const summary = buildProjectDriftSummary({
    scans: [completeScan(2, { manifests: ["package.json"] })],
    profile: { expectedManifestFiles: ["package.json"] },
  });

  assert.equal(summary.expectations.status, "unchanged");
  assert.deepEqual(category(summary.expectations, "expectedManifestFiles").unchanged, ["package.json"]);
});

test("approved expectation differing from observation is a changed pair", () => {
  const summary = buildProjectDriftSummary({
    scans: [completeScan(2, { manifests: ["pyproject.toml"] })],
    profile: { expectedManifestFiles: ["package.json"] },
  });

  assert.equal(summary.expectations.status, "drift");
  assert.deepEqual(category(summary.expectations, "expectedManifestFiles").changed, [{
    before: "package.json",
    after: "pyproject.toml",
  }]);
});

test("reliable observed value with no approval remains a new unapproved observation", () => {
  const summary = buildProjectDriftSummary({
    scans: [completeScan(2, { packageManagers: ["npm"] })],
    profile: {},
  });

  assert.equal(summary.expectations.status, "unconfigured");
  assert.deepEqual(category(summary.expectations, "trustedPackageManagers").added, ["npm"]);
});

test("approved value no longer observed remains missing", () => {
  const summary = buildProjectDriftSummary({
    scans: [completeScan(2)],
    profile: { expectedLockfiles: ["package-lock.json"] },
  });

  assert.deepEqual(category(summary.expectations, "expectedLockfiles").removed, ["package-lock.json"]);
});

test("dismissed suggestion remains dismissed without hiding its observation from drift", () => {
  const profile = {
    dismissedSuggestions: { expectedManifestFiles: ["package.json"] },
  };
  const before = structuredClone(profile);
  const summary = buildProjectDriftSummary({
    scans: [completeScan(2, { manifests: ["package.json"] })],
    profile,
  });

  assert.deepEqual(category(summary.expectations, "expectedManifestFiles").added, ["package.json"]);
  assert.deepEqual(profile, before, "drift calculation must not mutate dismissal state");
});

test("incomplete latest scan makes both drift comparisons indeterminate", () => {
  const latest = completeScan(2);
  latest.scanCompleteness = {
    ...latest.scanCompleteness,
    complete: false,
    fileInspectionFailureCount: 1,
    issueCount: 1,
  };
  const summary = buildProjectDriftSummary({
    scans: [latest, completeScan(1)],
    profile: { expectedManifestFiles: ["package.json"] },
  });

  assert.equal(summary.scanToScan.status, "indeterminate");
  assert.equal(summary.expectations.status, "indeterminate");
  assert.match(summary.scanToScan.message, /incomplete coverage/);
});

test("unreliable historical scan is not treated as an unchanged baseline", () => {
  const historical = completeScan(1);
  delete historical.scanCompleteness;
  const summary = buildProjectDriftSummary({
    scans: [completeScan(2), historical],
    profile: {},
  });

  assert.equal(summary.scanToScan.status, "no-baseline");
  assert.match(summary.scanToScan.message, /unavailable as a baseline/);
});

test("a preceding reliable baseline can be selected past an explicitly skipped unreliable scan", () => {
  const incomplete = completeScan(2);
  incomplete.scanCompleteness.complete = false;
  const summary = buildProjectDriftSummary({
    scans: [
      completeScan(3, { manifests: ["package.json"] }),
      incomplete,
      completeScan(1, { manifests: ["package.json"] }),
    ],
    profile: {},
  });

  assert.equal(summary.scanToScan.status, "unchanged");
  assert.equal(summary.scanToScan.skippedUnreliableScans, 1);
  assert.match(summary.scanToScan.message, /skipped/);
});

test("malformed persisted metadata is conservative", () => {
  const malformed = completeScan(2);
  malformed.scanMetadataReliable = false;
  const summary = buildProjectDriftSummary({
    scans: [malformed, completeScan(1)],
    profile: {},
  });

  assert.equal(summary.scanToScan.status, "indeterminate");
  assert.match(summary.scanToScan.message, /malformed persisted project metadata/);
});

test("legacy Project Expectations data loads conservatively without invented approvals", () => {
  const summary = buildProjectDriftSummary({
    scans: [completeScan(2, { manifests: ["package.json"] })],
    profile: {
      expectedManifestFiles: "package.json",
      dismissedSuggestions: ["malformed"],
      expectationProvenance: ["malformed"],
    },
  });

  assert.equal(summary.expectations.status, "unconfigured");
  assert.deepEqual(category(summary.expectations, "expectedManifestFiles").added, ["package.json"]);
});

test("malformed dependency analysis prevents a no-drift claim", () => {
  const malformed = completeScan(2);
  malformed.dependencyTrust.status = "malformed";
  const summary = buildProjectDriftSummary({
    scans: [malformed, completeScan(1)],
    profile: {},
  });

  assert.equal(summary.scanToScan.status, "indeterminate");
  assert.equal(summary.expectations.status, "indeterminate");
  assert.match(summary.scanToScan.message, /dependency metadata/);
});

test("large drift keeps exact counts while bounding rendered details", () => {
  const manifests = Array.from({ length: 25 }, (_, index) => `manifest-${String(index).padStart(2, "0")}.json`);
  const summary = buildProjectDriftSummary({
    scans: [completeScan(2, { manifests }), completeScan(1)],
    profile: {},
  });
  const manifestsDrift = category(summary.scanToScan, "expectedManifestFiles");

  assert.equal(summary.scanToScan.counts.added, 25);
  assert.equal(manifestsDrift.added.length, 10);
  assert.equal(manifestsDrift.omittedDetailCount, 15);
});

function category(section, field) {
  const result = section.categories.find((item) => item.field === field);
  assert.ok(result, `Expected ${field} drift category`);
  return result;
}

function completeScan(id, overrides = {}) {
  const {
    packageManagers = [],
    ecosystems = [],
    dependencyTrust = {},
    ...scanOverrides
  } = overrides;
  return {
    id,
    project_path: "C:/workspace/project",
    scan_date: `2026-07-${String(id).padStart(2, "0")}T12:00:00Z`,
    manifests: [],
    lockfiles: [],
    lifecycleScripts: [],
    ignoredFiles: [],
    reviewedFiles: [],
    scanMetadataReliable: true,
    scanCompleteness: {
      complete: true,
      traversalFailureCount: 0,
      fileInspectionFailureCount: 0,
      oversizedFileCount: 0,
      unsafePathCount: 0,
      dependencyAnalysisFailureCount: 0,
      policyExcludedFileCount: 0,
      builtInExcludedDirectoryCount: 0,
      unsupportedEncodingFileCount: 0,
      resourceBudgetExceededCount: 0,
      issueCount: 0,
    },
    dependencyTrust: {
      schemaVersion: 1,
      status: "complete",
      packageManagers,
      ecosystems,
      ...dependencyTrust,
    },
    ...scanOverrides,
  };
}
