import assert from "node:assert/strict";
import test from "node:test";
import {
  comparisonCountLabel,
  normalizeScanComparison,
} from "./scanComparison.js";

test("project metadata comparison reuses drift normalization and deterministic pairing", () => {
  const reviewedFiles = Array.from({ length: 12 }, (_, index) => `src/file-${index}.js`);
  const result = normalizeScanComparison(comparisonFixture({
    baseMetadata: metadataScan({ manifests: ["./package.json"], reviewedFiles }),
    targetMetadata: metadataScan({ manifests: ["pyproject.toml"], reviewedFiles }),
  }));

  const manifests = result.sections.projectMetadata.categories
    .find((category) => category.field === "expectedManifestFiles");
  assert.equal(result.sections.projectMetadata.status, "comparable");
  assert.deepEqual(manifests.changed, [{
    before: "package.json",
    after: "pyproject.toml",
  }]);
  assert.equal(manifests.counts.changed, 1);
  const reviewed = result.sections.projectMetadata.categories
    .find((category) => category.field === "reviewedPaths");
  assert.equal(reviewed.counts.unchanged, 12);
  assert.equal(reviewed.unchanged.length, 10);
  assert.equal(reviewed.omittedDetailCount, 2);
});

test("unknown or malformed historical comparison data stays renderable and conservative", () => {
  const result = normalizeScanComparison({
    baseScan: { id: 1, metadataSource: { reliable: false, reason: "Malformed metadata." } },
    targetScan: { id: 2, metadataSource: { reliable: true, scan: metadataScan() } },
    overallStatus: "future-status",
    sections: {
      findings: { status: "future-status", counts: { added: "zero" }, examples: { added: "bad" } },
      dependencies: null,
      coverage: { status: "indeterminate", metrics: { filesScanned: { base: "one", target: 2 } } },
    },
  });

  assert.equal(result.overallStatus, "indeterminate");
  assert.equal(result.sections.projectMetadata.status, "indeterminate");
  assert.equal(result.sections.findings.counts.added, null);
  assert.equal(comparisonCountLabel(result.sections.findings.counts.added), "Indeterminate");
  assert.deepEqual(result.sections.findings.examples.added, []);
});

function comparisonFixture({ baseMetadata = metadataScan(), targetMetadata = metadataScan() } = {}) {
  return {
    baseScan: {
      id: 1,
      scanDate: "2026-05-01T12:00:00Z",
      completionState: "complete",
      reliabilityStatus: "reliable",
      metadataSource: { reliable: true, scan: baseMetadata },
    },
    targetScan: {
      id: 2,
      scanDate: "2026-05-02T12:00:00Z",
      completionState: "complete",
      reliabilityStatus: "reliable",
      metadataSource: { reliable: true, scan: targetMetadata },
    },
    overallStatus: "comparable",
    sections: {
      findings: { status: "comparable", counts: {}, examples: {} },
      dependencies: { status: "comparable", counts: {}, examples: {} },
      coverage: { status: "partially-comparable", metrics: {} },
    },
  };
}

function metadataScan(overrides = {}) {
  return {
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
      packageManagers: ["npm"],
      ecosystems: ["node"],
    },
    ...overrides,
  };
}
