import { dependencyReviewState } from "./guidedReview.js";
import { normalizeProjectExpectations, PROJECT_EXPECTATION_FIELDS } from "./projectExpectations.js";
import { buildProjectDriftSummary } from "./projectDrift.js";

export const SECURITY_STATUS_LABELS = Object.freeze({
  ready: "Ready for reviewed work",
  review: "Review required",
  significant: "Significant changes detected",
  insufficient: "Insufficient evidence",
  blocked: "Blocked by incomplete scan",
});
export const SECURITY_STATUS_EVALUATOR_VERSION = 2;

const SECTION_LABELS = {
  coverage: "Scan coverage",
  findings: "Findings",
  dependencies: "Dependencies",
  expectations: "Project Expectations",
  baseline: "Baseline and drift",
  completion: "Review completion",
};
const SECURITY_RELEVANT_EXPECTATION_FIELDS = new Set([
  "trustedPackageManagers",
  "expectedManifestFiles",
  "expectedLockfiles",
  "allowedLifecycleScripts",
]);
const MAX_EXAMPLES = 3;

export function buildProjectSecurityStatus({
  project,
  scan,
  scans,
  report,
  profile,
  trustedBaseline,
} = {}) {
  const orderedScans = Array.isArray(scans) ? scans : [];
  const current = scan && typeof scan === "object" && !Array.isArray(scan) ? scan : null;
  const normalizedProfile = normalizeProjectExpectations(profile);
  const expectationCount = PROJECT_EXPECTATION_FIELDS.reduce(
    (total, { field }) => total + normalizedProfile[field].length,
    0,
  );
  const drift = buildProjectDriftSummary({
    scans: orderedScans,
    profile: normalizedProfile,
    currentScanId: current?.id,
    trustedBaseline,
  });

  if (!current) {
    const sections = [
      section("coverage", "Indeterminate", "No persisted scan exists for this project."),
      section("findings", "Indeterminate", "Findings are unavailable until a scan is recorded."),
      section("dependencies", "Indeterminate", "Dependency analysis is unavailable until a scan is recorded."),
      section(
        "expectations",
        expectationCount ? "Action required" : "Not applicable",
        expectationCount
          ? `${expectationCount} approved expectation values exist, but there is no current observation to compare.`
          : "No Project Expectations values are configured.",
        { approved: expectationCount },
      ),
      section("baseline", "Not applicable", "No current scan is available for a baseline comparison."),
      section("completion", "Indeterminate", "Review completion cannot be evaluated without a scan."),
    ];
    return summary("insufficient", current, trustedBaseline, sections, [
      action("run-scan", "Run a complete scan", "workspace"),
      ...(!expectationCount ? [action("create-expectations", "Create Project Expectations", "trustProfiles")] : []),
    ]);
  }

  const coverage = coverageEvidence(current);
  const findings = findingsEvidence(current, orderedScans, drift, trustedBaseline, coverage);
  const dependencies = dependencyEvidence(report?.dependencyTrust);
  const expectations = expectationEvidence(drift.expectations, expectationCount);
  const baseline = baselineEvidence(drift.scanToScan, drift.baselineSource, trustedBaseline);
  const completion = completionEvidence({
    coverage,
    findings,
    dependencies,
    expectations,
    baseline,
  });
  const sections = [coverage, findings, dependencies, expectations, baseline, completion];

  let status = "ready";
  if (coverage.status === "Action required" && coverage.blocking) status = "blocked";
  else if (
    current.scanMetadataReliable !== true
    || sections.some((item) => item.insufficient)
  ) status = "insufficient";
  else if (sections.some((item) => item.status === "Significant change")) status = "significant";
  else if (sections.some((item) => item.status === "Action required" || item.status === "Indeterminate")) status = "review";

  return summary(
    status,
    current,
    trustedBaseline,
    sections,
    recommendedActions({ status, coverage, findings, dependencies, expectations, baseline }),
  );
}

function coverageEvidence(scan) {
  const value = scan.scanCompleteness;
  const fields = [
    "traversalFailureCount",
    "fileInspectionFailureCount",
    "oversizedFileCount",
    "unsafePathCount",
    "dependencyAnalysisFailureCount",
    "policyExcludedFileCount",
    "resourceBudgetExceededCount",
  ];
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return section("coverage", "Action required", "Coverage metadata is unavailable for the latest scan.", {}, [], {
      blocking: true,
    });
  }
  const countsValid = fields.every((field) => Number.isSafeInteger(value[field]) && value[field] >= 0);
  const issueCount = countsValid ? fields.reduce((total, field) => total + value[field], 0) : null;
  if (
    !countsValid
    || !Number.isSafeInteger(value.issueCount)
    || value.issueCount !== issueCount
    || value.complete !== (issueCount === 0)
  ) {
    return section("coverage", "Action required", "Coverage metadata is malformed or internally inconsistent.", {}, [], {
      blocking: true,
    });
  }
  if (!value.complete) {
    return section(
      "coverage",
      "Action required",
      `${issueCount} recorded inspection ${plural(issueCount, "gap")} ${issueCount === 1 ? "prevents" : "prevent"} the latest scan from representing the complete project state.`,
      { inspectionGaps: issueCount },
      coverageExamples(value),
      { blocking: true },
    );
  }
  return section("coverage", "Satisfied", "The latest scan records complete, internally consistent coverage.", {
    inspectionGaps: 0,
    reviewedFiles: validCount(scan.reviewedFileCount),
    ignoredFiles: validCount(scan.ignoredFileCount),
  });
}

function findingsEvidence(scan, scans, drift, trustedBaseline, coverage) {
  if (!Array.isArray(scan.findings)) {
    return section("findings", "Indeterminate", "Persisted findings are unavailable or malformed.", {}, [], {
      insufficient: true,
    });
  }
  const normalized = [];
  for (const finding of scan.findings) {
    if (!finding || typeof finding !== "object" || Array.isArray(finding)) {
      return section("findings", "Indeterminate", "Persisted findings contain malformed records.", {}, [], {
        insufficient: true,
      });
    }
    normalized.push({
      finding,
      severity: severity(finding.severity),
      reviewed: Boolean(finding.review && typeof finding.review === "object" && !Array.isArray(finding.review)),
    });
  }
  const reviewed = normalized.filter((item) => item.reviewed).length;
  const unresolved = normalized.length - reviewed;
  const highUnresolved = normalized.filter((item) => !item.reviewed && ["critical", "high"].includes(item.severity));
  const reviewedHighWithoutExpectedDisposition = normalized.filter((item) => (
    item.reviewed
    && ["critical", "high"].includes(item.severity)
    && item.finding.review?.status !== "expected"
  ));
  const baselineScan = applicableBaselineScan(scans, drift, trustedBaseline);
  const counts = severityCounts(normalized);
  counts.total = normalized.length;
  counts.reviewed = reviewed;
  counts.needsReview = unresolved;
  if (coverage.blocking) {
    return section(
      "findings",
      "Indeterminate",
      `${normalized.length} findings were recorded, but incomplete coverage prevents claims about absent, removed, or resolved findings.`,
      counts,
      normalized.slice(0, MAX_EXAMPLES).map((item) => findingExample(item.finding)),
      { insufficient: true },
    );
  }
  const baselineFindings = baselineFindingEvidence(baselineScan);
  if (!baselineFindings.reliable) {
    return section(
      "findings",
      "Indeterminate",
      baselineFindings.reason,
      counts,
      [],
      { insufficient: true },
    );
  }
  const newHigh = baselineScan
    ? newFindings(normalized, baselineFindings.findings)
      .filter((item) => ["critical", "high"].includes(item.severity))
    : [];
  counts.newHigh = baselineScan ? newHigh.length : null;
  const unresolvedCritical = highUnresolved.filter((item) => item.severity === "critical");
  if (newHigh.length || unresolvedCritical.length) {
    const findingCount = newHigh.length || unresolvedCritical.length;
    const examples = (newHigh.length ? newHigh : unresolvedCritical)
      .slice(0, MAX_EXAMPLES)
      .map((item) => findingExample(item.finding));
    return section(
      "findings",
      "Significant change",
      `${findingCount} new or unresolved critical/high-severity ${plural(findingCount, "finding")} ${verb(findingCount, "requires", "require")} deliberate review.`,
      counts,
      examples,
    );
  }
  if (unresolved || reviewedHighWithoutExpectedDisposition.length) {
    return section(
      "findings",
      "Action required",
      unresolved
        ? `${unresolved} of ${normalized.length} ${plural(normalized.length, "finding")} ${verb(unresolved, "still needs", "still need")} a persisted review decision.`
        : `${reviewedHighWithoutExpectedDisposition.length} reviewed high-severity ${plural(reviewedHighWithoutExpectedDisposition.length, "finding")} ${verb(reviewedHighWithoutExpectedDisposition.length, "lacks", "lack")} an expected disposition.`,
      counts,
      normalized.filter((item) => !item.reviewed || reviewedHighWithoutExpectedDisposition.includes(item))
        .slice(0, MAX_EXAMPLES)
        .map((item) => findingExample(item.finding)),
    );
  }
  return section("findings", "Satisfied", `${reviewed} of ${normalized.length} findings have persisted review decisions. Reviewed does not mean fixed.`, counts);
}

function dependencyEvidence(trust) {
  if (!trust || trust.available !== true) {
    return section("dependencies", "Indeterminate", "Current dependency analysis is unavailable.", {}, [], {
      insufficient: true,
    });
  }
  const review = dependencyReviewState(trust);
  if (review.status === "not-applicable") {
    return section("dependencies", "Not applicable", "No supported dependency metadata was detected.");
  }
  if (trust.status !== "complete") {
    return section("dependencies", "Indeterminate", `Dependency analysis is ${trust.status || "unavailable"} and cannot support a positive status.`, {}, [], {
      insufficient: true,
    });
  }
  const comparison = trust.comparison || {};
  const changes = Array.isArray(comparison.changes) ? comparison.changes : [];
  const fileChanges = comparison.fileChanges || {};
  const changeDetailsComplete = validCount(comparison.hiddenChangeCount) === 0;
  const counts = {
    packages: validCount(trust.lockedDependencyCount ?? trust.entries?.length),
    changes: validCount(comparison.changeCount),
    additions: changeDetailsComplete
      ? changes.filter((change) => change?.changeType?.endsWith("-added") || change?.changeType === "added").length
      : null,
    removals: changeDetailsComplete
      ? changes.filter((change) => change?.changeType?.endsWith("-removed") || change?.changeType === "removed").length
      : null,
    versionChanges: changeDetailsComplete
      ? changes.filter((change) => change?.changeType === "version-changed").length
      : null,
    manifestChanges: arrayLength(fileChanges.manifestsAdded) + arrayLength(fileChanges.manifestsRemoved),
    lockfileChanges: arrayLength(fileChanges.lockfilesAdded) + arrayLength(fileChanges.lockfilesRemoved),
  };
  const significantChanges = changes.filter((change) => (
    ["version-changed", "source-changed", "integrity-changed", "install-script-changed"].includes(change?.changeType)
  ));
  if (significantChanges.length >= 1 || counts.changes >= 3 || review.status === "changed") {
    const changeCount = counts.changes || changes.length;
    const reference = review.status === "changed" ? "persisted approved snapshot" : "applicable scan baseline";
    const approvalNote = review.status === "changed" ? "" : " The current dependency fingerprint is not approved.";
    return section(
      "dependencies",
      "Significant change",
      `${changeCount} dependency ${plural(changeCount, "change")} ${verb(changeCount, "differs", "differ")} from the ${reference}.${approvalNote}`,
      counts,
      changes.slice(0, MAX_EXAMPLES).map(dependencyExample),
    );
  }
  if (!review.complete) {
    return section("dependencies", "Action required", review.detail, counts, changes.slice(0, MAX_EXAMPLES).map(dependencyExample));
  }
  return section("dependencies", "Satisfied", `${counts.packages} packages are represented by complete analysis matching the persisted approved fingerprint. This is not a package-safety guarantee.`, counts);
}

function expectationEvidence(value, approvedCount) {
  if (!value || value.status === "indeterminate") {
    return section("expectations", "Indeterminate", value?.message || "Expectation comparison is unavailable.", {}, [], {
      insufficient: true,
    });
  }
  const counts = {
    approved: approvedCount,
    matching: value.counts?.unchanged || 0,
    added: value.counts?.added || 0,
    removed: value.counts?.removed || 0,
    changed: value.counts?.changed || 0,
    indeterminate: value.counts?.unavailable || 0,
  };
  if (!approvedCount) {
    return section("expectations", "Action required", "No Project Expectations values are approved; reliable observations remain review context.", counts);
  }
  const changedCategories = (value.categories || []).filter((category) => category.status === "changed");
  const significant = changedCategories.filter(securityRelevantDrift);
  if (significant.length) {
    return section(
      "expectations",
      "Significant change",
      "Reliable observations conflict with security-relevant approved expectations, including tooling, lifecycle scripts, or reviewed and ignored paths.",
      counts,
      driftExamples(significant),
    );
  }
  if (value.status === "drift") {
    return section("expectations", "Action required", value.message, counts, driftExamples(changedCategories));
  }
  return section("expectations", "Satisfied", `${counts.matching} observed values match ${approvedCount} approved expectation values.`, counts);
}

function baselineEvidence(value, source, trustedBaseline) {
  if (trustedBaseline?.configured && trustedBaseline.status !== "valid") {
    return section(
      "baseline",
      "Significant change",
      "Trusted baseline unavailable. Its explicit reference was preserved and no automatic baseline was substituted.",
      {},
      [],
      { trustedUnavailable: true },
    );
  }
  if (!value || value.status === "indeterminate") {
    return section("baseline", "Indeterminate", value?.message || "Baseline comparison is unavailable.", {}, [], {
      insufficient: true,
    });
  }
  if (value.status === "baseline-is-latest") {
    return section("baseline", "Not applicable", "The trusted baseline is the latest scan, so no newer comparison is available.");
  }
  if (value.status === "no-baseline") {
    return section("baseline", "Not applicable", "No reliable historical baseline is available; change-over-time claims remain limited.");
  }
  const counts = {
    matching: value.counts?.unchanged || 0,
    added: value.counts?.added || 0,
    removed: value.counts?.removed || 0,
    changed: value.counts?.changed || 0,
  };
  const changedCategories = (value.categories || []).filter((category) => category.status === "changed");
  const significant = changedCategories.filter(securityRelevantDrift);
  if (significant.length) {
    return section(
      "baseline",
      "Significant change",
      `Latest reliable observations materially diverge from the ${source?.type === "trusted" ? "trusted" : "automatic"} baseline.`,
      counts,
      driftExamples(significant),
    );
  }
  if (value.status === "drift") {
    return section("baseline", "Action required", value.message, counts, driftExamples(changedCategories));
  }
  return section("baseline", "Satisfied", `The latest scan is reliably comparable with the ${source?.type === "trusted" ? "trusted" : "automatic"} baseline.`, counts);
}

function completionEvidence({ coverage, findings, dependencies, expectations, baseline }) {
  const applicable = [coverage, findings, dependencies, expectations, baseline]
    .filter((item) => item.status !== "Not applicable");
  const unresolved = applicable.filter((item) => item.status !== "Satisfied");
  if (!unresolved.length) {
    return section("completion", "Satisfied", "All applicable evidence sections have sufficient persisted review state.");
  }
  if (unresolved.some((item) => item.status === "Indeterminate")) {
    return section("completion", "Indeterminate", `${unresolved.length} applicable evidence ${plural(unresolved.length, "section")} ${verb(unresolved.length, "remains", "remain")} unresolved.`);
  }
  if (unresolved.some((item) => item.status === "Significant change")) {
    return section("completion", "Significant change", `${unresolved.length} applicable evidence ${plural(unresolved.length, "section")} ${verb(unresolved.length, "requires", "require")} deliberate review.`);
  }
  return section("completion", "Action required", `${unresolved.length} applicable evidence ${plural(unresolved.length, "section")} ${verb(unresolved.length, "still requires", "still require")} review.`);
}

function recommendedActions({ status, coverage, findings, dependencies, expectations, baseline }) {
  const candidates = [];
  if (status === "blocked" || status === "insufficient" || coverage.status !== "Satisfied") {
    candidates.push(action("run-scan", "Run a complete scan", "workspace"));
  }
  if (findings.status === "Significant change") {
    candidates.push(action(
      "review-high-findings",
      findings.counts?.newHigh > 0 ? "Review new high-severity findings" : "Review critical or high-severity findings",
      "reports",
    ));
  }
  else if (findings.status === "Action required") candidates.push(action("complete-finding-review", "Complete finding review", "reports"));
  if (dependencies.status === "Significant change") candidates.push(action("review-dependencies", "Review dependency changes", "reports"));
  else if (dependencies.status === "Action required") candidates.push(action("approve-dependencies", "Approve the current dependency fingerprint", "reports"));
  if (baseline.trustedUnavailable) candidates.push(action("replace-baseline", "Replace unavailable trusted baseline", "trustProfiles"));
  else if (baseline.status === "Action required") candidates.push(action("compare-baseline", "Compare latest scan with the baseline", "scanComparison"));
  if (expectations.status === "Significant change" || expectations.status === "Action required") {
    candidates.push(action(
      expectations.counts?.approved ? "review-expectation-drift" : "create-expectations",
      expectations.counts?.approved ? "Review observed expectation drift" : "Create Project Expectations",
      "trustProfiles",
    ));
  }
  const unique = [];
  for (const candidate of candidates) {
    if (!unique.some((item) => item.id === candidate.id)) unique.push(candidate);
  }
  return unique.slice(0, 3);
}

function summary(status, scan, trustedBaseline, sections, actions) {
  return {
    status,
    label: SECURITY_STATUS_LABELS[status],
    evaluatorVersion: SECURITY_STATUS_EVALUATOR_VERSION,
    interpretation: {
      ready: "Available persisted evidence has been reviewed sufficiently to proceed cautiously.",
      review: "Reliable evidence exists, but meaningful review work remains.",
      significant: "Reliable evidence shows material changes requiring deliberate review before proceeding.",
      insufficient: "Available persisted evidence is too limited or unreliable to support a work-readiness conclusion.",
      blocked: "The latest scan cannot reliably represent the complete current project state.",
    }[status],
    evidenceTimestamp: typeof scan?.scan_date === "string" ? scan.scan_date.slice(0, 100) : "",
    baselineSource: trustedBaseline?.configured
      ? trustedBaseline.status === "valid" ? "Trusted baseline" : "Trusted baseline unavailable"
      : sections.find((item) => item.id === "baseline")?.status === "Not applicable" ? "No baseline" : "Automatic baseline",
    sections,
    actions: actions.slice(0, 3),
    disclaimer: "Based on Glacial’s available local evidence; not a guarantee of security.",
  };
}

function section(id, status, explanation, counts = {}, examples = [], extra = {}) {
  return {
    id,
    label: SECTION_LABELS[id],
    status,
    explanation: bounded(explanation, 500),
    counts,
    examples: examples.filter(Boolean).slice(0, MAX_EXAMPLES).map((item) => bounded(item, 240)),
    destination: {
      coverage: "reports",
      findings: "reports",
      dependencies: "reports",
      expectations: "trustProfiles",
      baseline: "scanComparison",
      completion: "reports",
    }[id],
    ...extra,
  };
}

function action(id, label, destination) {
  return { id, label, destination };
}

function applicableBaselineScan(scans, drift, trustedBaseline) {
  const id = trustedBaseline?.configured
    ? trustedBaseline.status === "valid" ? trustedBaseline.baseline?.scanId : null
    : drift?.scanToScan?.baselineScan?.id;
  if (!Number.isSafeInteger(id)) return null;
  return scans.find((scan) => scan?.id === id)
    || (trustedBaseline?.configured && trustedBaseline.baseline?.scan?.id === id
      ? trustedBaseline.baseline.scan
      : null);
}

function baselineFindingEvidence(scan) {
  if (!scan) return { reliable: true, findings: [], reason: "" };
  if (
    !Array.isArray(scan.findings)
    || scan.findings.some((finding) => !finding || typeof finding !== "object" || Array.isArray(finding))
  ) {
    return {
      reliable: false,
      findings: [],
      reason: "Applicable baseline finding evidence is missing or malformed.",
    };
  }
  return { reliable: true, findings: scan.findings, reason: "" };
}

function newFindings(current, baselineFindings) {
  const baselineKeys = new Set(baselineFindings.filter((item) => item && typeof item === "object").map(findingKey));
  return current.filter((item) => !baselineKeys.has(findingKey(item.finding)));
}

function findingKey(finding) {
  if (typeof finding?.fingerprint === "string" && finding.fingerprint) return finding.fingerprint;
  return [
    bounded(finding?.type || finding?.finding_type, 100),
    bounded(finding?.path || finding?.file_path, 300),
    bounded(finding?.pattern, 120),
  ].join("\0");
}

function findingExample(finding) {
  return `${severity(finding?.severity)} · ${bounded(finding?.type || finding?.finding_type || "finding", 80)} · ${bounded(finding?.path || finding?.file_path || "path unavailable", 120)}`;
}

function dependencyExample(change) {
  return `${bounded(change?.changeType || "changed", 60)} · ${bounded(change?.name || change?.currentValue || "dependency", 140)}`;
}

function driftExamples(categories) {
  const examples = [];
  for (const category of categories) {
    for (const change of category.changed || []) examples.push(`${category.label}: ${change.before} → ${change.after}`);
    for (const value of category.added || []) examples.push(`${category.label}: added ${value}`);
    for (const value of category.removed || []) examples.push(`${category.label}: missing ${value}`);
  }
  return examples.slice(0, MAX_EXAMPLES);
}

function securityRelevantDrift(category) {
  if (SECURITY_RELEVANT_EXPECTATION_FIELDS.has(category.field)) return true;
  if (category.field === "ignoredPaths") {
    return Boolean(category.added?.length || category.removed?.length || category.changed?.length);
  }
  if (category.field === "reviewedPaths") {
    return Boolean(category.removed?.length || category.changed?.length);
  }
  return false;
}

function coverageExamples(value) {
  const labels = {
    traversalFailureCount: "directory traversal failures",
    fileInspectionFailureCount: "file inspection failures",
    oversizedFileCount: "oversized files",
    unsafePathCount: "unsafe paths",
    dependencyAnalysisFailureCount: "dependency-analysis failures",
    policyExcludedFileCount: "policy exclusions",
    resourceBudgetExceededCount: "resource budget limits",
  };
  return Object.entries(labels)
    .filter(([field]) => value[field] > 0)
    .map(([field, label]) => `${value[field]} ${label}`)
    .slice(0, MAX_EXAMPLES);
}

function severityCounts(items) {
  return items.reduce((counts, item) => {
    counts[item.severity] = (counts[item.severity] || 0) + 1;
    return counts;
  }, { critical: 0, high: 0, medium: 0, low: 0 });
}

function severity(value) {
  const normalized = String(value || "low").toLowerCase();
  return ["critical", "high", "medium", "low"].includes(normalized) ? normalized : "high";
}

function validCount(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function arrayLength(value) {
  return Array.isArray(value) ? value.length : 0;
}

function bounded(value, limit) {
  return typeof value === "string" ? value.replaceAll(/\s+/g, " ").trim().slice(0, limit) : "";
}

function plural(count, noun) {
  return count === 1 ? noun : `${noun}s`;
}

function verb(count, singular, pluralForm) {
  return count === 1 ? singular : pluralForm;
}
