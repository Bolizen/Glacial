import assert from "node:assert/strict";
import test from "node:test";

import {
  buildReviewCheckpointPreview,
  normalizeReviewCheckpointPage,
  reviewCheckpointEligibility,
} from "./reviewCheckpoints.js";

test("checkpoint eligibility requires the canonical ready status and exact reliable evidence", () => {
  const page = normalizeReviewCheckpointPage(checkpointPage());
  assert.equal(reviewCheckpointEligibility({ status: "review", label: "Review required", evaluatorVersion: 2 }, page).eligible, false);
  assert.equal(reviewCheckpointEligibility({ status: "ready", label: "Ready for reviewed work", evaluatorVersion: 2 }, page).eligible, true);

  const current = normalizeReviewCheckpointPage(checkpointPage({
    state: { id: "current", reasons: ["Exact evidence match."] },
  }));
  assert.equal(reviewCheckpointEligibility({ status: "ready", evaluatorVersion: 2 }, current).eligible, false);

  const notApplicableValue = checkpointPage();
  notApplicableValue.currentEvidence.dependencyAnalysisFingerprint = `cpda1_${"b".repeat(64)}`;
  notApplicableValue.currentEvidence.dependencyApprovalFingerprint = "";
  notApplicableValue.currentEvidence.dependencyApprovalState = "not-applicable";
  const notApplicable = normalizeReviewCheckpointPage(notApplicableValue);
  assert.equal(notApplicable.currentEvidence.reliable, true);
  assert.equal(reviewCheckpointEligibility({ status: "ready", evaluatorVersion: 2 }, notApplicable).eligible, true);
});

test("checkpoint malformed evidence and stale reasons remain conservative and bounded", () => {
  const malformed = normalizeReviewCheckpointPage({
    state: {
      id: "future-state",
      reasons: ["one", "two", "three", "unbounded"],
    },
    currentEvidence: {
      reliable: true,
      scanId: 2,
      evaluatorVersion: 999,
      evidenceFingerprint: "forged",
    },
    history: [{ checkpointId: "rcp_one", scanId: "bad", malformed: true }],
  });

  assert.equal(malformed.state.id, "indeterminate");
  assert.equal(malformed.state.reasons.length, 3);
  assert.equal(malformed.currentEvidence.reliable, false);
  assert.equal(reviewCheckpointEligibility({ status: "ready", evaluatorVersion: 2 }, malformed).eligible, false);
  assert.equal(malformed.history[0].malformed, true);
});

test("checkpoint confirmation preview exposes bounded normalized evidence without mutation", () => {
  const raw = checkpointPage();
  const before = structuredClone(raw);
  const page = normalizeReviewCheckpointPage(raw);
  const preview = buildReviewCheckpointPreview(
    { name: "Project", path: "C:/workspace/project" },
    page,
  );

  assert.equal(preview.scanId, 42);
  assert.equal(preview.baselineProvenance, "manual");
  assert.equal(preview.findingCount, 2);
  assert.equal(preview.unresolvedHighCount, 0);
  assert.match(preview.evidenceFingerprint, /^cpr1_/);
  assert.deepEqual(raw, before);
});

function checkpointPage(overrides = {}) {
  const hex = "a".repeat(64);
  return {
    state: { id: "no-checkpoint", reasons: ["No checkpoint."] },
    currentEvidence: {
      reliable: true,
      readyForCheckpoint: true,
      projectId: "C:/workspace/project",
      scanId: 42,
      scanTimestamp: "2026-08-01T10:00:00Z",
      baselineScanId: 41,
      baselineProvenance: "manual",
      baselineComparisonState: "unchanged",
      expectationsFingerprint: `cpex1_${hex}`,
      dependencyAnalysisFingerprint: `cfdb2_${hex}`,
      dependencyApprovalFingerprint: `cfdb2_${hex}`,
      dependencyApprovalState: "approved",
      findingReviewsFingerprint: `cpfr1_${hex}`,
      baselineFindingsFingerprint: `cpbf1_${hex}`,
      newCriticalHighCount: 0,
      findingReviewComplete: true,
      findingCount: 2,
      reviewedFindingCount: 2,
      unresolvedCriticalCount: 0,
      unresolvedHighCount: 0,
      coverageFingerprint: `cpcov1_${hex}`,
      coverageComplete: true,
      coverageIssueCount: 0,
      metadataReliable: true,
      checkpointSchemaVersion: 1,
      evaluatorVersion: 2,
      evidenceFingerprint: `cpr1_${hex}`,
      reasons: [],
    },
    history: [],
    hasMore: false,
    ...overrides,
  };
}
