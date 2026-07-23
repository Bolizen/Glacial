import assert from "node:assert/strict";
import test from "node:test";

import {
  buildGuidedReviewState,
  dependencyReviewState,
  dismissGuidedReview,
  GUIDED_REVIEW_DISMISSALS_KEY,
  readGuidedReviewDismissals,
} from "./guidedReview.js";


const PROJECT = { path: "C:/workspace/project", name: "Project" };
const COMPLETE_COVERAGE = { known: true, complete: true, issueCount: 0 };
const INCOMPLETE_COVERAGE = { known: true, complete: false, issueCount: 2 };
const NOT_APPLICABLE = {
  available: true,
  schemaVersion: 1,
  status: "unsupported",
  ecosystems: [],
  manifests: [],
  lockfiles: [],
  packageManagers: [],
  entries: [],
};


test("new project starts with a compact first-scan checklist", () => {
  const state = buildGuidedReviewState({
    project: PROJECT,
    scan: null,
    completeness: { known: false, complete: false, issueCount: 0 },
    dependencyTrust: { available: false },
  });

  assert.equal(state.status, "not-started");
  assert.equal(state.title, "Review not started");
  assert.equal(state.completedStepCount, 1);
  assert.deepEqual(state.remaining, ["Run the first scan."]);
  assert.deepEqual(state.steps.map((step) => [step.id, step.complete]), [
    ["project-registered", true],
    ["first-scan", false],
    ["findings-reviewed", false],
    ["coverage-understood", false],
    ["dependencies-reviewed", false],
  ]);
});


test("unresolved findings keep the review workflow incomplete", () => {
  const state = buildGuidedReviewState({
    project: PROJECT,
    scan: scan([{ review: null, severity: "high" }, reviewedFinding()]),
    completeness: COMPLETE_COVERAGE,
    dependencyTrust: NOT_APPLICABLE,
  });

  assert.equal(state.title, "Finding review in progress");
  assert.equal(state.reviewSummary.unreviewedFindingCount, 1);
  assert.equal(state.workflowComplete, false);
  assert.match(state.summary, /1 of 2 findings remain unresolved/);
});


test("reviewed findings do not conceal incomplete coverage", () => {
  const state = buildGuidedReviewState({
    project: PROJECT,
    scan: scan([reviewedFinding()]),
    completeness: INCOMPLETE_COVERAGE,
    dependencyTrust: NOT_APPLICABLE,
  });

  assert.equal(state.allFindingsReviewed, true);
  assert.equal(state.coverageComplete, false);
  assert.equal(state.title, "Finding review complete; coverage remains unresolved");
  assert.match(state.remaining.join(" "), /2 scan-coverage gaps remain/);
});


test("applicable dependency data requires explicit snapshot approval", () => {
  const trust = applicableDependencyTrust();
  const dependency = dependencyReviewState(trust);
  const state = buildGuidedReviewState({
    project: PROJECT,
    scan: scan([reviewedFinding()]),
    completeness: COMPLETE_COVERAGE,
    dependencyTrust: trust,
  });

  assert.equal(dependency.status, "review-required");
  assert.equal(dependency.requiresAction, true);
  assert.equal(state.title, "Finding review complete; dependency review remains");
  assert.equal(state.workflowComplete, false);
});


test("genuinely complete review requires reviews, coverage, and an approved dependency snapshot", () => {
  const state = buildGuidedReviewState({
    project: PROJECT,
    scan: scan([reviewedFinding(), reviewedFinding()]),
    completeness: COMPLETE_COVERAGE,
    dependencyTrust: applicableDependencyTrust({
      configured: true,
      valid: true,
      comparison: { status: "identical" },
    }),
  });

  assert.equal(state.workflowComplete, true);
  assert.equal(state.title, "Review complete for this scan");
  assert.equal(state.completedStepCount, 5);
  assert.deepEqual(state.remaining, []);
  assert.match(state.summary, /All 2 findings have a review state/);
});


test("legacy, malformed, drifted, and not-applicable dependency states stay distinct", () => {
  assert.equal(dependencyReviewState(undefined).status, "unavailable");
  assert.equal(dependencyReviewState({ available: true, status: "malformed" }).status, "malformed");
  assert.equal(dependencyReviewState(NOT_APPLICABLE).status, "not-applicable");
  assert.equal(dependencyReviewState(applicableDependencyTrust({
    configured: true,
    valid: true,
    comparison: { status: "drift" },
  })).status, "changed");

  const malformedScan = buildGuidedReviewState({
    project: PROJECT,
    scan: { findings: "not-an-array" },
    completeness: { known: false, complete: true, issueCount: -1 },
    dependencyTrust: { available: true, status: "malformed" },
  });
  assert.equal(malformedScan.workflowComplete, false);
  assert.equal(malformedScan.allFindingsReviewed, false);
  assert.match(malformedScan.steps[2].detail, /unavailable or malformed/);
  assert.equal(malformedScan.coverageComplete, false);
  assert.equal(malformedScan.dependency.status, "malformed");
});


test("checklist dismissal writes only local UI state and never mutates project or scan data", () => {
  const values = new Map();
  const storage = {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
  };
  const project = structuredClone(PROJECT);
  const sourceScan = scan([{ review: null }]);
  const projectBefore = structuredClone(project);
  const scanBefore = structuredClone(sourceScan);

  const dismissals = dismissGuidedReview(project.path, [], storage);

  assert.deepEqual(dismissals, [project.path]);
  assert.deepEqual(readGuidedReviewDismissals(storage), [project.path]);
  assert.equal(values.size, 1);
  assert.ok(values.has(GUIDED_REVIEW_DISMISSALS_KEY));
  assert.deepEqual(project, projectBefore);
  assert.deepEqual(sourceScan, scanBefore);
});


function scan(findings) {
  return {
    id: 1,
    scan_date: "2026-07-23T12:00:00Z",
    findings,
  };
}


function reviewedFinding() {
  return { review: { status: "reviewed" }, severity: "low" };
}


function applicableDependencyTrust(baseline = {}) {
  return {
    available: true,
    schemaVersion: 1,
    status: "complete",
    ecosystems: ["node"],
    manifests: ["package.json"],
    lockfiles: ["package-lock.json"],
    packageManagers: ["npm"],
    entries: [{ ecosystem: "node", name: "example", direct: true }],
    trustedBaseline: {
      configured: false,
      valid: false,
      comparison: { status: "not-configured" },
      ...baseline,
    },
  };
}
