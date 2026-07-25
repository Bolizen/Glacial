import assert from "node:assert/strict";
import test from "node:test";

import { buildReviewWorkspaceModel, reviewActionDestination } from "./reviewWorkspace.js";

test("builds one primary action, two secondary actions, and the canonical evidence order", () => {
  const model = buildReviewWorkspaceModel({
    evidenceTimestamp: "2026-07-25T12:00:00Z",
    actions: [
      { id: "review-high-findings", label: "Review high findings", destination: "reports" },
      { id: "review-dependencies", label: "Review dependencies", destination: "reports" },
      { id: "review-expectation-drift", label: "Review drift", destination: "trustProfiles" },
      { id: "ignored", label: "Ignored", destination: "workspace" },
    ],
    sections: [
      { id: "coverage" },
      { id: "findings" },
      { id: "dependencies" },
      { id: "expectations" },
      { id: "baseline" },
      { id: "completion" },
    ],
  });

  assert.equal(model.hasScan, true);
  assert.equal(model.primaryAction.id, "review-high-findings");
  assert.deepEqual(model.secondaryActions.map((action) => action.id), [
    "review-dependencies",
    "review-expectation-drift",
  ]);
  assert.deepEqual(model.sections.map((section) => section.id), [
    "coverage",
    "findings",
    "dependencies",
    "expectations",
    "baseline",
    "completion",
  ]);
  assert.deepEqual(model.sections.map((section) => section.action.targetId), [
    "scan-completeness",
    "finding-workbench",
    "dependency-trust",
    "project-drift-summary",
    "scan-comparison",
    "finding-workbench",
  ]);
});

test("maps review actions to stable sections and focused containers without executing mutations", () => {
  assert.deepEqual(reviewActionDestination({ id: "run-scan" }), {
    section: "workspace",
    targetId: "workspace-scan-area",
  });
  assert.deepEqual(reviewActionDestination({ id: "review-high-findings" }), {
    section: "reports",
    targetId: "finding-workbench",
    findingFilter: "unresolved-high",
  });
  assert.deepEqual(reviewActionDestination({ id: "review-expectation-drift" }), {
    section: "trustProfiles",
    targetId: "project-drift-summary",
  });
  assert.deepEqual(reviewActionDestination({ id: "compare-baseline" }), {
    section: "scanComparison",
    targetId: "scan-comparison",
  });
});
