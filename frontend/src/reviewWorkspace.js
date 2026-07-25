const ACTION_DESTINATIONS = Object.freeze({
  "run-scan": { section: "workspace", targetId: "workspace-scan-area" },
  "review-high-findings": {
    section: "reports",
    targetId: "finding-workbench",
    findingFilter: "unresolved-high",
  },
  "complete-finding-review": {
    section: "reports",
    targetId: "finding-workbench",
    findingFilter: "unresolved",
  },
  "review-dependencies": { section: "reports", targetId: "dependency-trust" },
  "approve-dependencies": { section: "reports", targetId: "dependency-trust" },
  "create-expectations": { section: "trustProfiles", targetId: "project-expectations" },
  "review-expectation-drift": { section: "trustProfiles", targetId: "project-drift-summary" },
  "replace-baseline": { section: "trustProfiles", targetId: "trusted-scan-baseline" },
  "compare-baseline": { section: "scanComparison", targetId: "scan-comparison" },
});

const EVIDENCE_ACTIONS = Object.freeze({
  coverage: { id: "review-scan-coverage", label: "Review details", destination: "reports", targetId: "scan-completeness" },
  findings: { id: "review-findings", label: "Review details", destination: "reports", targetId: "finding-workbench" },
  dependencies: { id: "review-dependencies", label: "Review details", destination: "reports", targetId: "dependency-trust" },
  expectations: { id: "review-expectation-drift", label: "Review details", destination: "trustProfiles", targetId: "project-drift-summary" },
  baseline: { id: "compare-baseline", label: "Review details", destination: "scanComparison", targetId: "scan-comparison" },
  completion: { id: "review-completion", label: "Review details", destination: "reports", targetId: "finding-workbench" },
});

export function buildReviewWorkspaceModel(securityStatus, { hasScan = false } = {}) {
  const value = securityStatus && typeof securityStatus === "object" ? securityStatus : {};
  const actions = Array.isArray(value.actions) ? value.actions.slice(0, 3) : [];
  const sections = Array.isArray(value.sections)
    ? value.sections.map((section) => ({
      ...section,
      action: EVIDENCE_ACTIONS[section.id] || null,
    }))
    : [];
  return {
    hasScan: Boolean(hasScan),
    primaryAction: actions[0] || null,
    secondaryActions: actions.slice(1, 3),
    sections,
  };
}

export function reviewActionDestination(action) {
  if (!action || typeof action !== "object") return null;
  const mapped = ACTION_DESTINATIONS[action.id];
  if (mapped) return { ...mapped };
  if (["workspace", "reports", "trustProfiles", "scanComparison", "activity"].includes(action.destination)) {
    return {
      section: action.destination,
      targetId: typeof action.targetId === "string" ? action.targetId : "",
      findingFilter: typeof action.findingFilter === "string" ? action.findingFilter : "",
    };
  }
  return null;
}
