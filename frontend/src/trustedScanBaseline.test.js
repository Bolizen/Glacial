import assert from "node:assert/strict";
import test from "node:test";

import { buildProjectDriftSummary } from "./projectDrift.js";
import {
  normalizeTrustedScanBaseline,
  trustedBaselinePreview,
  trustedComparisonSelection,
  trustedScanEligibility,
} from "./trustedScanBaseline.js";

test("trusted scan baseline eligibility accepts only complete, reliable persisted scans", () => {
  const eligible = completeScan(1);
  assert.equal(trustedScanEligibility(eligible).eligible, true);

  const incomplete = completeScan(2);
  incomplete.scanCompleteness = {
    ...incomplete.scanCompleteness,
    complete: false,
    fileInspectionFailureCount: 1,
    issueCount: 1,
  };
  assert.equal(trustedScanEligibility(incomplete).eligible, false);

  const malformed = completeScan(3);
  malformed.reviewedFileCount = 2;
  assert.equal(trustedScanEligibility(malformed).eligible, false);

  const reduced = completeScan(4, { reviewedFilesTruncated: true });
  const reducedEligibility = trustedScanEligibility(reduced);
  assert.equal(reducedEligibility.eligible, false);
  assert.match(reducedEligibility.reason, /metadata was reduced/);

  const unsupported = completeScan(5);
  unsupported.dependencyTrust.status = "incomplete";
  assert.equal(trustedScanEligibility(unsupported).eligible, false);
});

test("valid trusted baseline overrides the newer automatic candidate", () => {
  const latest = completeScan(3, { manifests: ["latest.json"] });
  const automaticCandidate = completeScan(2, { manifests: ["latest.json"] });
  const pinned = completeScan(1, { manifests: ["pinned.json"] });
  const state = validState(pinned, latest);

  const summary = buildProjectDriftSummary({
    scans: [latest, automaticCandidate, pinned],
    profile: {},
    trustedBaseline: state,
  });

  assert.equal(summary.baselineSource.type, "trusted");
  assert.equal(summary.baselineSource.scan.id, 1);
  assert.equal(summary.scanToScan.status, "drift");
  assert.equal(summary.scanToScan.baselineScan.id, 1);
});

test("invalid trusted baseline never falls back and latest baseline is neutral", () => {
  const latest = completeScan(3);
  const automaticCandidate = completeScan(2);
  const invalid = buildProjectDriftSummary({
    scans: [latest, automaticCandidate],
    profile: {},
    trustedBaseline: {
      configured: true,
      status: "invalid",
      baseline: { scanId: 1, scanDate: "2026-07-01T12:00:00Z", scan: null },
      message: "Trusted baseline unavailable. No automatic baseline was substituted.",
    },
  });
  assert.equal(invalid.scanToScan.status, "trusted-baseline-unavailable");
  assert.notEqual(invalid.scanToScan.status, "unchanged");
  assert.equal(invalid.scanToScan.baselineScan, undefined);

  const same = buildProjectDriftSummary({
    scans: [latest, automaticCandidate],
    profile: {},
    trustedBaseline: validState(latest, latest),
  });
  assert.equal(same.scanToScan.status, "baseline-is-latest");
  assert.notEqual(same.scanToScan.status, "unchanged");
});

test("baseline preview distinguishes replacement and normalization preserves unavailable references", () => {
  const scan = completeScan(3);
  const preview = trustedBaselinePreview(
    { name: "Alpine" },
    scan,
    { configured: true, baseline: { scanId: 1 } },
  );
  assert.equal(preview.projectName, "Alpine");
  assert.equal(preview.scanId, 3);
  assert.equal(preview.replacesScanId, 1);
  assert.equal(preview.reliabilityState, "Reliable");

  const normalized = normalizeTrustedScanBaseline({
    configured: true,
    status: "unavailable",
    baseline: { scanId: 9, pinnedAt: "2026-07-01T00:00:00Z", provenance: "manual" },
    latestScan: { id: 10, scanDate: "2026-07-02T00:00:00Z" },
    message: "Reference preserved.",
  });
  assert.equal(normalized.baseline.scanId, 9);
  assert.equal(normalized.status, "unavailable");
  assert.equal(normalized.message, "Reference preserved.");
});

test("compare latest to trusted baseline preselects exact base and target and refuses self-comparison", () => {
  const baseline = completeScan(1);
  const latest = completeScan(3);
  const selection = trustedComparisonSelection(validState(baseline, latest), [{
    id: 2,
    scanDate: "2026-07-02T12:00:00Z",
    completionState: "complete",
    reliabilityStatus: "reliable",
  }]);

  assert.equal(selection.baseScanId, 1);
  assert.equal(selection.targetScanId, 3);
  assert.deepEqual(selection.options.map((scan) => scan.id), [2, 1, 3]);
  assert.equal(trustedComparisonSelection(validState(latest, latest)), null);
});

function validState(baseline, latest) {
  return {
    configured: true,
    status: "valid",
    baseline: {
      scanId: baseline.id,
      scanDate: baseline.scan_date,
      completionState: "complete",
      reliabilityStatus: "reliable",
      scan: baseline,
    },
    latestScan: {
      id: latest.id,
      scanDate: latest.scan_date,
      completionState: "complete",
      reliabilityStatus: "reliable",
    },
    isLatest: baseline.id === latest.id,
  };
}

function completeScan(id, overrides = {}) {
  const scan = {
    id,
    project_path: "C:/workspace/project",
    scan_date: `2026-07-${String(id).padStart(2, "0")}T12:00:00Z`,
    manifests: [],
    lockfiles: [],
    lifecycleScripts: [],
    ignoredFiles: [],
    reviewedFiles: ["src/index.js"],
    ignoredFileCount: 0,
    reviewedFileCount: 1,
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
      packageManagers: ["npm"],
      ecosystems: ["node"],
    },
  };
  return { ...scan, ...overrides };
}
