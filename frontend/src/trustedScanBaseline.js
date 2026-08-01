import { compareProjectMetadataScans } from "./projectDrift.js";

export const EMPTY_TRUSTED_SCAN_BASELINE = Object.freeze({
  configured: false,
  status: "not-configured",
  baseline: null,
  latestScan: null,
  isLatest: false,
  message: "No trusted scan baseline is configured. Automatic baseline selection remains active.",
});

export function normalizeTrustedScanBaseline(value) {
  const configured = value?.configured === true;
  const baseline = configured ? normalizeBaseline(value?.baseline) : null;
  const latestScan = normalizeSummary(value?.latestScan);
  const status = configured && ["valid", "invalid", "unavailable"].includes(value?.status)
    ? value.status
    : configured ? "unavailable" : "not-configured";
  return {
    configured,
    status,
    baseline,
    latestScan,
    isLatest: configured && baseline && latestScan
      ? baseline.scanId === latestScan.id
      : value?.isLatest === true,
    message: bounded(value?.message, 500) || (
      configured
        ? "Trusted baseline unavailable. No automatic baseline was substituted."
        : EMPTY_TRUSTED_SCAN_BASELINE.message
    ),
  };
}

export function trustedScanEligibility(scan) {
  if (!scan || !Number.isSafeInteger(scan.id) || scan.id <= 0) {
    return { eligible: false, status: "indeterminate", reason: "Scan data is unavailable." };
  }
  const completeness = scan.scanCompleteness;
  if (!validCompleteness(completeness)) {
    return { eligible: false, status: "indeterminate", reason: "Coverage metadata is missing, malformed, or internally inconsistent." };
  }
  if (completeness.complete !== true) {
    return { eligible: false, status: "incomplete", reason: "Scan coverage is incomplete." };
  }
  if (
    !Array.isArray(scan.reviewedFiles)
    || scan.reviewedFiles.some((item) => typeof item !== "string")
    || scan.reviewedFiles.length !== scan.reviewedFileCount
    || !Array.isArray(scan.ignoredFiles)
    || scan.ignoredFiles.some((item) => typeof item !== "string")
    || scan.ignoredFiles.length !== scan.ignoredFileCount
  ) {
    return { eligible: false, status: "indeterminate", reason: "Persisted coverage file counts are inconsistent." };
  }
  const metadata = compareProjectMetadataScans(scan, scan);
  if (metadata.status !== "comparable") {
    return { eligible: false, status: "indeterminate", reason: metadata.message };
  }
  return {
    eligible: true,
    status: "reliable",
    reason: "Coverage and persisted scan metadata are complete and reliable.",
  };
}

export function trustedBaselinePreview(project, scan, currentBaseline) {
  const eligibility = trustedScanEligibility(scan);
  return {
    projectName: bounded(project?.name, 120) || "Selected project",
    scanId: Number.isSafeInteger(scan?.id) ? scan.id : null,
    scanDate: bounded(scan?.scan_date, 100),
    completionState: scan?.scanCompleteness?.complete === true ? "Complete" : "Incomplete or unknown",
    reliabilityState: eligibility.eligible ? "Reliable" : "Ineligible",
    replacesScanId: currentBaseline?.configured && currentBaseline?.baseline?.scanId !== scan?.id
      ? currentBaseline.baseline.scanId
      : null,
    eligibility,
  };
}

export function trustedComparisonSelection(state, options = []) {
  const baseline = state?.baseline;
  const latest = state?.latestScan;
  if (
    state?.status !== "valid"
    || !Number.isSafeInteger(baseline?.scanId)
    || !Number.isSafeInteger(latest?.id)
    || baseline.scanId === latest.id
  ) return null;
  const summaries = [
    ...options,
    {
      id: baseline.scanId,
      scanDate: baseline.scanDate,
      completionState: baseline.completionState,
      reliabilityStatus: baseline.reliabilityStatus,
    },
    latest,
  ];
  const deduplicated = [];
  for (const summary of summaries) {
    if (!Number.isSafeInteger(summary?.id) || summary.id <= 0) continue;
    if (deduplicated.some((item) => item.id === summary.id)) continue;
    deduplicated.push(summary);
  }
  return {
    options: deduplicated,
    baseScanId: baseline.scanId,
    targetScanId: latest.id,
  };
}

function normalizeBaseline(value) {
  if (!value || !Number.isSafeInteger(value.scanId) || value.scanId <= 0) return null;
  const summary = normalizeSummary({
    id: value.scanId,
    scanDate: value.scanDate,
    completionState: value.completionState,
    reliabilityStatus: value.reliabilityStatus,
    eligibility: value.eligibility,
  });
  return {
    scanId: value.scanId,
    pinnedAt: bounded(value.pinnedAt, 100),
    provenance: value.provenance === "manual" ? "manual" : "unknown",
    scanDate: summary?.scanDate || "",
    completionState: summary?.completionState || "unknown",
    reliabilityStatus: summary?.reliabilityStatus || "indeterminate",
    eligibility: normalizeEligibility(value.eligibility),
    scan: value.scan && typeof value.scan === "object" && !Array.isArray(value.scan)
      ? value.scan
      : null,
  };
}

function normalizeSummary(value) {
  if (!value || !Number.isSafeInteger(value.id) || value.id <= 0) return null;
  return {
    id: value.id,
    scanDate: bounded(value.scanDate, 100),
    completionState: ["complete", "incomplete", "unknown"].includes(value.completionState)
      ? value.completionState
      : "unknown",
    reliabilityStatus: ["reliable", "limited", "indeterminate"].includes(value.reliabilityStatus)
      ? value.reliabilityStatus
      : "indeterminate",
    eligibility: normalizeEligibility(value.eligibility),
  };
}

function normalizeEligibility(value) {
  return {
    eligible: value?.eligible === true,
    status: bounded(value?.status, 60) || "indeterminate",
    reason: bounded(value?.reason, 500) || "Eligibility is unavailable.",
  };
}

function validCompleteness(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const fields = [
    "traversalFailureCount",
    "fileInspectionFailureCount",
    "oversizedFileCount",
    "unsafePathCount",
    "dependencyAnalysisFailureCount",
    "policyExcludedFileCount",
    "builtInExcludedDirectoryCount",
    "unsupportedEncodingFileCount",
    "resourceBudgetExceededCount",
  ];
  if (fields.some((field) => !Number.isSafeInteger(value[field]) || value[field] < 0)) return false;
  const issueCount = fields.reduce((total, field) => total + value[field], 0);
  return Number.isSafeInteger(value.issueCount)
    && value.issueCount === issueCount
    && value.complete === (issueCount === 0);
}

function bounded(value, limit) {
  return typeof value === "string" ? value.trim().slice(0, limit) : "";
}
