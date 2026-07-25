import { SECURITY_STATUS_EVALUATOR_VERSION } from "./projectSecurityStatus.js";

export const REVIEW_CHECKPOINT_EVALUATOR_VERSION = SECURITY_STATUS_EVALUATOR_VERSION;

export const EMPTY_REVIEW_CHECKPOINTS = Object.freeze({
  state: {
    id: "no-checkpoint",
    label: "No checkpoint",
    reasons: ["No manual project review checkpoint has been recorded."],
  },
  currentEvidence: null,
  history: [],
  hasMore: false,
  nextOffset: null,
  loading: false,
  error: "",
});

const STATE_LABELS = {
  current: "Current",
  "review-required": "Review required",
  indeterminate: "Indeterminate",
  "no-checkpoint": "No checkpoint",
};

export function normalizeReviewCheckpointPage(value) {
  const source = objectValue(value);
  const state = normalizeState(source.state);
  const currentEvidence = normalizeEvidence(source.currentEvidence);
  const history = Array.isArray(source.history)
    ? source.history.slice(0, 20).map(normalizeCheckpoint).filter(Boolean)
    : [];
  return {
    state,
    currentEvidence,
    history,
    hasMore: source.hasMore === true,
    nextOffset: positiveInteger(source.nextOffset),
    loading: false,
    error: "",
  };
}

export function reviewCheckpointEligibility(securityStatus, page) {
  const state = page?.state;
  const evidence = page?.currentEvidence;
  if (state?.id === "current") {
    return { eligible: false, reason: "The latest checkpoint is already current." };
  }
  if (securityStatus?.status !== "ready") {
    return {
      eligible: false,
      reason: `Record a checkpoint only when project security status is ${securityStatus?.label || "Ready for reviewed work"}.`,
    };
  }
  if (securityStatus.evaluatorVersion !== REVIEW_CHECKPOINT_EVALUATOR_VERSION) {
    return { eligible: false, reason: "The project security status evaluator version is unsupported." };
  }
  if (!evidence || evidence.reliable !== true) {
    return { eligible: false, reason: "Current checkpoint evidence is indeterminate." };
  }
  if (
    evidence.readyForCheckpoint !== true
    || evidence.evaluatorVersion !== REVIEW_CHECKPOINT_EVALUATOR_VERSION
    || !evidence.evidenceFingerprint
  ) {
    return { eligible: false, reason: "Current evidence is not eligible for a review checkpoint." };
  }
  return { eligible: true, reason: "" };
}

export function buildReviewCheckpointPreview(project, page) {
  const evidence = page?.currentEvidence;
  if (!evidence?.reliable || !evidence.evidenceFingerprint) return null;
  return {
    projectId: text(project?.path, 1000),
    projectName: text(project?.name, 120) || "Selected project",
    scanId: evidence.scanId,
    scanTimestamp: evidence.scanTimestamp,
    baselineScanId: evidence.baselineScanId,
    baselineProvenance: evidence.baselineProvenance,
    expectationsFingerprint: evidence.expectationsFingerprint,
    dependencyAnalysisFingerprint: evidence.dependencyAnalysisFingerprint,
    dependencyApprovalFingerprint: evidence.dependencyApprovalFingerprint,
    dependencyApprovalState: evidence.dependencyApprovalState,
    baselineFindingsFingerprint: evidence.baselineFindingsFingerprint,
    newCriticalHighCount: evidence.newCriticalHighCount,
    findingCount: evidence.findingCount,
    reviewedFindingCount: evidence.reviewedFindingCount,
    unresolvedCriticalCount: evidence.unresolvedCriticalCount,
    unresolvedHighCount: evidence.unresolvedHighCount,
    coverageComplete: evidence.coverageComplete,
    coverageIssueCount: evidence.coverageIssueCount,
    metadataReliable: evidence.metadataReliable,
    evaluatorVersion: evidence.evaluatorVersion,
    evidenceFingerprint: evidence.evidenceFingerprint,
  };
}

function normalizeState(value) {
  const source = objectValue(value);
  const id = Object.hasOwn(STATE_LABELS, source.id) ? source.id : "indeterminate";
  const reasons = stringList(source.reasons, 3, 300);
  return {
    id,
    label: STATE_LABELS[id],
    reasons: reasons.length
      ? reasons
      : [id === "indeterminate" ? "Checkpoint state cannot be determined reliably." : "No additional checkpoint context is available."],
  };
}

function normalizeEvidence(value) {
  const source = objectValue(value);
  if (!Object.keys(source).length) return null;
  const reliable = source.reliable === true
    && positiveInteger(source.scanId) !== null
    && /^cpr1_[0-9a-f]{64}$/.test(text(source.evidenceFingerprint, 100))
    && /^cpex1_[0-9a-f]{64}$/.test(text(source.expectationsFingerprint, 100))
    && (
      /^cfdb2_[0-9a-f]{64}$/.test(text(source.dependencyAnalysisFingerprint, 100))
      || /^cpda1_[0-9a-f]{64}$/.test(text(source.dependencyAnalysisFingerprint, 100))
    )
    && /^cpfr1_[0-9a-f]{64}$/.test(text(source.findingReviewsFingerprint, 100))
    && /^cpcov1_[0-9a-f]{64}$/.test(text(source.coverageFingerprint, 100))
    && (
      ["not-applicable", "not-configured"].includes(source.dependencyApprovalState)
      || /^cfdb2_[0-9a-f]{64}$/.test(text(source.dependencyApprovalFingerprint, 100))
    )
    && (
      source.dependencyApprovalState === "not-applicable"
        ? /^cpda1_[0-9a-f]{64}$/.test(text(source.dependencyAnalysisFingerprint, 100))
          && !text(source.dependencyApprovalFingerprint, 100)
        : /^cfdb2_[0-9a-f]{64}$/.test(text(source.dependencyAnalysisFingerprint, 100))
    )
    && (
      positiveInteger(source.baselineScanId) === null
        ? !text(source.baselineFindingsFingerprint, 100)
        : /^cpbf1_[0-9a-f]{64}$/.test(text(source.baselineFindingsFingerprint, 100))
    )
    && count(source.newCriticalHighCount) !== null
    && source.evaluatorVersion === REVIEW_CHECKPOINT_EVALUATOR_VERSION;
  return {
    reliable,
    readyForCheckpoint: reliable && source.readyForCheckpoint === true,
    projectId: text(source.projectId, 1000),
    scanId: positiveInteger(source.scanId),
    scanTimestamp: text(source.scanTimestamp, 100),
    baselineScanId: positiveInteger(source.baselineScanId),
    baselineProvenance: ["manual", "automatic", "none"].includes(source.baselineProvenance)
      ? source.baselineProvenance
      : "none",
    baselineComparisonState: text(source.baselineComparisonState, 80),
    expectationsFingerprint: fingerprint(source.expectationsFingerprint, "cpex1_"),
    dependencyAnalysisFingerprint: fingerprint(
      source.dependencyAnalysisFingerprint,
      source.dependencyApprovalState === "not-applicable" ? "cpda1_" : "cfdb2_",
    ),
    dependencyApprovalFingerprint: source.dependencyApprovalFingerprint
      ? fingerprint(source.dependencyApprovalFingerprint, "cfdb2_")
      : "",
    dependencyApprovalState: ["approved", "changed", "significant-change", "not-applicable", "not-configured"].includes(source.dependencyApprovalState)
      ? source.dependencyApprovalState
      : "indeterminate",
    findingReviewsFingerprint: fingerprint(source.findingReviewsFingerprint, "cpfr1_"),
    baselineFindingsFingerprint: source.baselineFindingsFingerprint
      ? fingerprint(source.baselineFindingsFingerprint, "cpbf1_")
      : "",
    newCriticalHighCount: count(source.newCriticalHighCount),
    findingReviewComplete: source.findingReviewComplete === true,
    findingCount: count(source.findingCount),
    reviewedFindingCount: count(source.reviewedFindingCount),
    unresolvedCriticalCount: count(source.unresolvedCriticalCount),
    unresolvedHighCount: count(source.unresolvedHighCount),
    coverageFingerprint: fingerprint(source.coverageFingerprint, "cpcov1_"),
    coverageComplete: source.coverageComplete === true,
    coverageIssueCount: count(source.coverageIssueCount),
    metadataReliable: source.metadataReliable === true,
    checkpointSchemaVersion: source.checkpointSchemaVersion === 1 ? 1 : null,
    evaluatorVersion: source.evaluatorVersion === REVIEW_CHECKPOINT_EVALUATOR_VERSION
      ? REVIEW_CHECKPOINT_EVALUATOR_VERSION
      : null,
    evidenceFingerprint: reliable ? text(source.evidenceFingerprint, 100) : "",
    reasons: stringList(source.reasons, 3, 300),
  };
}

function normalizeCheckpoint(value) {
  const source = objectValue(value);
  const checkpointId = text(source.checkpointId, 100);
  if (!checkpointId) return null;
  return {
    checkpointId,
    scanId: positiveInteger(source.scanId),
    baselineScanId: positiveInteger(source.baselineScanId),
    baselineProvenance: ["manual", "automatic", "none"].includes(source.baselineProvenance)
      ? source.baselineProvenance
      : "unknown",
    createdAt: text(source.createdAt, 100),
    provenance: source.provenance === "manual" ? "manual" : "unknown",
    evaluatorVersion: positiveInteger(source.evaluatorVersion),
    malformed: source.malformed === true,
  };
}

function fingerprint(value, prefix) {
  const normalized = text(value, 100);
  return new RegExp(`^${prefix}[0-9a-f]{64}$`).test(normalized) ? normalized : "";
}

function objectValue(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function stringList(value, limit, length) {
  return Array.isArray(value)
    ? value.filter((item) => typeof item === "string").map((item) => text(item, length)).filter(Boolean).slice(0, limit)
    : [];
}

function count(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0 ? value : null;
}

function text(value, limit) {
  return typeof value === "string" ? value.replaceAll(/\s+/g, " ").trim().slice(0, limit) : "";
}
