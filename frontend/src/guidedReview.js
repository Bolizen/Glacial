import { dependencyTrustHasNoSupportedMetadata } from "./dependencyTrust.js";
import { findingReviewSummary } from "./findingReviews.js";


export const GUIDED_REVIEW_DISMISSALS_KEY = "glacial.guided-review.dismissed.v1";
const MAX_DISMISSALS = 100;


export function buildGuidedReviewState({
  project,
  scan,
  completeness,
  dependencyTrust,
} = {}) {
  const projectRegistered = Boolean(project?.path);
  const hasScan = Boolean(scan && typeof scan === "object");
  const findingsDataKnown = hasScan && Array.isArray(scan?.findings);
  const reviews = findingReviewSummary(scan);
  const findingsReviewed = findingsDataKnown
    && reviews.unreviewedFindingCount === 0
    && reviews.reviewedFindingCount === reviews.rawFindingCount;
  const coverageComplete = hasScan
    && completeness?.known === true
    && completeness?.complete === true
    && completeness?.issueCount === 0;
  const dependency = dependencyReviewState(dependencyTrust);
  const workflowComplete = projectRegistered
    && hasScan
    && findingsReviewed
    && coverageComplete
    && dependency.complete;
  const remaining = [];

  if (!hasScan) {
    remaining.push("Run the first scan.");
  } else {
    if (!findingsReviewed) {
      remaining.push(`${reviews.unreviewedFindingCount} unresolved ${plural(reviews.unreviewedFindingCount, "finding")} ${verb(reviews.unreviewedFindingCount, "still needs", "still need")} a review state.`);
    }
    if (!coverageComplete) {
      remaining.push(coverageRemaining(completeness));
    }
    if (!dependency.complete) {
      remaining.push(dependency.remaining);
    }
  }

  const steps = [
    checklistStep(
      "project-registered",
      "Project registered",
      projectRegistered,
      projectRegistered ? "Selected project is registered locally." : "Register or create a project.",
    ),
    checklistStep(
      "first-scan",
      "First scan completed",
      hasScan,
      hasScan ? `Scan recorded ${formatRecordedDate(scan?.scan_date)}.` : "Run the first scan without executing project content.",
    ),
    checklistStep(
      "findings-reviewed",
      "Unresolved findings reviewed",
      findingsReviewed,
      findingsReviewDetail(hasScan, findingsDataKnown, reviews),
    ),
    checklistStep(
      "coverage-understood",
      "Scan coverage understood",
      coverageComplete,
      coverageDetail(hasScan, completeness),
    ),
    checklistStep(
      "dependencies-reviewed",
      "Dependency state reviewed when applicable",
      dependency.complete,
      dependency.detail,
    ),
  ];

  return {
    allFindingsReviewed: findingsReviewed,
    completedStepCount: steps.filter((step) => step.complete).length,
    coverageComplete,
    dependency,
    hasScan,
    remaining,
    reviewSummary: reviews,
    status: workflowComplete ? "complete" : hasScan ? "incomplete" : "not-started",
    steps,
    summary: completionSummary({
      hasScan,
      findingsReviewed,
      coverageComplete,
      dependency,
      reviews,
    }),
    title: completionTitle({
      hasScan,
      findingsReviewed,
      coverageComplete,
      dependency,
      workflowComplete,
    }),
    workflowComplete,
  };
}


export function dependencyReviewState(trust) {
  if (!trust || trust.available !== true) {
    return dependencyState(
      "unavailable",
      "Dependency state unavailable",
      "This scan does not contain current dependency-analysis data.",
      "Dependency analysis is unavailable for this scan.",
    );
  }
  if (dependencyTrustHasNoSupportedMetadata(trust)) {
    return dependencyState(
      "not-applicable",
      "Not applicable",
      "No supported dependency metadata was detected; no snapshot approval is available.",
      "",
      true,
      false,
    );
  }
  if (trust.status === "malformed") {
    return dependencyState(
      "malformed",
      "Malformed",
      "Dependency metadata could not be parsed reliably.",
      "Resolve or manually review the malformed dependency metadata.",
    );
  }
  if (trust.status === "incomplete") {
    return dependencyState(
      "incomplete",
      "Incomplete",
      "The dependency analysis has recorded gaps.",
      "Complete or manually account for the dependency-analysis gaps.",
    );
  }
  if (trust.status === "unsupported") {
    return dependencyState(
      "unsupported",
      "Unsupported",
      "Detected dependency metadata is not supported for snapshot approval.",
      "Manually review the unsupported dependency metadata.",
    );
  }
  if (trust.status !== "complete") {
    return dependencyState(
      "unavailable",
      "Dependency state unavailable",
      "The dependency state is missing or unrecognized.",
      "Dependency analysis is unavailable for this scan.",
    );
  }

  const baseline = trust.trustedBaseline;
  const comparisonStatus = baseline?.comparison?.status;
  if (baseline?.configured === true && baseline?.valid === true && comparisonStatus === "identical") {
    return dependencyState(
      "approved",
      "Approved snapshot",
      "This scan matches the valid project-approved dependency snapshot.",
      "",
      true,
    );
  }
  if (comparisonStatus === "drift") {
    return dependencyState(
      "changed",
      "Approved snapshot changed",
      "The current dependency state differs from the approved snapshot.",
      "Review the dependency changes and explicitly replace the approved snapshot if appropriate.",
    );
  }
  return dependencyState(
    "review-required",
    "Approval required",
    "Supported dependency metadata is available, but this snapshot has not been explicitly approved.",
    "Review and explicitly approve the applicable dependency snapshot.",
  );
}


export function readGuidedReviewDismissals(storage = browserStorage()) {
  try {
    const value = JSON.parse(storage?.getItem(GUIDED_REVIEW_DISMISSALS_KEY) || "[]");
    if (!Array.isArray(value)) return [];
    return uniqueProjectPaths(value).slice(-MAX_DISMISSALS);
  } catch {
    return [];
  }
}


export function dismissGuidedReview(projectPath, current, storage = browserStorage()) {
  const next = uniqueProjectPaths([...(Array.isArray(current) ? current : []), projectPath])
    .slice(-MAX_DISMISSALS);
  try {
    storage?.setItem(GUIDED_REVIEW_DISMISSALS_KEY, JSON.stringify(next));
  } catch {
    return Array.isArray(current) ? current : [];
  }
  return next;
}


function checklistStep(id, label, complete, detail) {
  return { id, label, complete: complete === true, detail };
}


function dependencyState(status, label, detail, remaining, complete = false, applicable = true) {
  return {
    applicable,
    complete,
    detail,
    label,
    remaining,
    requiresAction: applicable && !complete,
    status,
  };
}


function completionTitle({
  hasScan,
  findingsReviewed,
  coverageComplete,
  dependency,
  workflowComplete,
}) {
  if (!hasScan) return "Review not started";
  if (workflowComplete) return "Review complete for this scan";
  if (!findingsReviewed) return "Finding review in progress";
  if (!coverageComplete) return "Finding review complete; coverage remains unresolved";
  if (!dependency.complete) return "Finding review complete; dependency review remains";
  return "Review remains incomplete";
}


function completionSummary({
  hasScan,
  findingsReviewed,
  coverageComplete,
  dependency,
  reviews,
}) {
  if (!hasScan) return "Run the first scan to establish findings, coverage, and dependency context.";
  const findings = findingsReviewed
    ? reviews.rawFindingCount === 0
      ? "No findings were recorded."
      : reviewedFindingsSentence(reviews.rawFindingCount)
    : `${reviews.unreviewedFindingCount} of ${reviews.rawFindingCount} ${plural(reviews.rawFindingCount, "finding")} ${verb(reviews.rawFindingCount, "remains", "remain")} unresolved.`;
  const coverage = coverageComplete
    ? "Scan coverage is complete."
    : "Scan coverage is incomplete or unavailable.";
  return `${findings} ${coverage} Dependency state: ${dependency.label.toLowerCase()}.`;
}


function findingsReviewDetail(hasScan, findingsDataKnown, reviews) {
  if (!hasScan) return "Waiting for the first scan.";
  if (!findingsDataKnown) return "Finding data is unavailable or malformed for this scan.";
  if (reviews.unreviewedFindingCount > 0) {
    return `${reviews.unreviewedFindingCount} unresolved ${plural(reviews.unreviewedFindingCount, "finding")} ${verb(reviews.unreviewedFindingCount, "remains", "remain")}.`;
  }
  if (reviews.rawFindingCount === 0) return "No findings were recorded for this scan.";
  return reviewedFindingsSentence(reviews.rawFindingCount);
}


function coverageDetail(hasScan, completeness) {
  if (!hasScan) return "Waiting for the first scan.";
  if (completeness?.known !== true) return "Coverage metadata is unavailable for this scan.";
  if (completeness.complete === true && completeness.issueCount === 0) {
    return "No inspection gaps were recorded.";
  }
  const count = nonNegativeInteger(completeness?.issueCount);
  return `${count} inspection ${plural(count, "gap")} ${verb(count, "remains", "remain")}.`;
}


function coverageRemaining(completeness) {
  if (completeness?.known !== true) {
    return "Run a current scan because coverage metadata is unavailable.";
  }
  const count = nonNegativeInteger(completeness?.issueCount);
  return `${count} scan-coverage ${plural(count, "gap")} ${verb(count, "remains", "remain")}.`;
}


function formatRecordedDate(value) {
  if (!value) return "for this project";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "for this project" : date.toLocaleDateString();
}


function uniqueProjectPaths(values) {
  const seen = new Set();
  return values.filter((value) => {
    if (typeof value !== "string" || !value || value.length > 4096 || seen.has(value)) return false;
    seen.add(value);
    return true;
  });
}


function nonNegativeInteger(value) {
  const number = Number(value);
  return Number.isInteger(number) && number >= 0 ? number : 0;
}


function plural(count, singular) {
  return count === 1 ? singular : `${singular}s`;
}


function verb(count, singular, pluralForm) {
  return count === 1 ? singular : pluralForm;
}


function reviewedFindingsSentence(count) {
  return count === 1
    ? "The finding has a review state."
    : `All ${count} findings have a review state.`;
}


function browserStorage() {
  try {
    return globalThis.localStorage || globalThis.window?.localStorage || null;
  } catch {
    return null;
  }
}
