import {
  normalizeProjectExpectations,
  PROJECT_EXPECTATION_FIELDS,
} from "./projectExpectations.js";
import { dependencyTrustHasNoSupportedMetadata } from "./dependencyTrust.js";

const SCAN_COUNT_FIELDS = [
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

const CATEGORY_SOURCES = {
  trustedPackageManagers: "dependency",
  expectedManifestFiles: "scan",
  expectedLockfiles: "scan",
  allowedLifecycleScripts: "scan",
  expectedEcosystems: "dependency",
  reviewedPaths: "scan",
  ignoredPaths: "scan",
};
const MAX_DRIFT_DETAILS_PER_CATEGORY = 10;

export function buildProjectDriftSummary({ scans, profile, currentScanId, trustedBaseline } = {}) {
  const orderedScans = Array.isArray(scans) ? scans : [];
  const currentIndex = currentScanId === undefined || currentScanId === null
    ? 0
    : orderedScans.findIndex((scan) => scan?.id === currentScanId);
  const currentScan = currentIndex >= 0 ? orderedScans[currentIndex] : null;
  const current = snapshotForScan(currentScan);
  const normalizedProfile = normalizeProjectExpectations(profile);

  if (!currentScan) {
    return {
      currentScan: null,
      scanToScan: unavailableSection(
        "indeterminate",
        "No scan is available, so scan-to-scan drift cannot be determined.",
      ),
      baselineSource: { type: "no-baseline", scan: null },
      expectations: unavailableSection(
        "indeterminate",
        "No scan is available, so approved expectations cannot be compared with observations.",
      ),
    };
  }

  const expectations = buildExpectationDrift(current, normalizedProfile);
  if (trustedBaseline?.configured === true) {
    return {
      currentScan: scanIdentity(currentScan),
      scanToScan: trustedBaselineComparison(currentScan, trustedBaseline),
      expectations,
      baselineSource: trustedBaselineSource(trustedBaseline),
    };
  }
  if (!current.reliable) {
    return {
      currentScan: scanIdentity(currentScan),
      scanToScan: unavailableSection("indeterminate", current.reason),
      expectations,
      baselineSource: { type: "no-baseline", scan: null },
    };
  }

  const historical = orderedScans.slice(currentIndex + 1);
  const baselineIndex = historical.findIndex((scan) => snapshotForScan(scan).reliable);
  if (baselineIndex < 0) {
    const unreliableCount = historical.length;
    const message = unreliableCount > 0
      ? `No suitable previous complete, reliable scan exists. ${unreliableCount} older ${pluralize(unreliableCount, "scan was", "scans were")} unavailable as a baseline.`
      : "No previous complete, reliable scan exists yet, so a scan-to-scan baseline has not been established.";
    return {
      currentScan: scanIdentity(currentScan),
      scanToScan: unavailableSection("no-baseline", message),
      expectations,
      baselineSource: { type: "no-baseline", scan: null },
    };
  }

  const baselineScan = historical[baselineIndex];
  const baseline = snapshotForScan(baselineScan);
  const categories = PROJECT_EXPECTATION_FIELDS.map(({ field, label }) => (
    compareCategory(field, label, baseline.values[field], current.values[field])
  ));
  const counts = aggregateCounts(categories);
  const driftDetected = counts.added + counts.removed + counts.changed > 0;
  const skippedCount = baselineIndex;
  const skippedMessage = skippedCount > 0
    ? ` ${skippedCount} newer historical ${pluralize(skippedCount, "scan was", "scans were")} skipped because it was not a complete, reliable baseline.`
    : "";

  return {
    currentScan: scanIdentity(currentScan),
    scanToScan: {
      status: driftDetected ? "drift" : "unchanged",
      message: driftDetected
        ? `Observed project metadata changed from the previous complete, reliable scan.${skippedMessage}`
        : `No observed metadata drift was detected across the supported categories.${skippedMessage}`,
      baselineScan: scanIdentity(baselineScan),
      skippedUnreliableScans: skippedCount,
      counts,
      categories,
    },
    expectations,
    baselineSource: { type: "automatic", scan: scanIdentity(baselineScan) },
  };
}

export function compareProjectMetadataScans(baseScan, targetScan) {
  const base = snapshotForScan(baseScan);
  const target = snapshotForScan(targetScan);
  if (!base.reliable || !target.reliable) {
    return unavailableSection(
      "indeterminate",
      [
        !base.reliable ? `Base scan: ${base.reason}` : "",
        !target.reliable ? `Target scan: ${target.reason}` : "",
      ].filter(Boolean).join(" "),
    );
  }
  const categories = PROJECT_EXPECTATION_FIELDS.map(({ field, label }) => (
    compareCategory(field, label, base.values[field], target.values[field])
  ));
  const counts = aggregateCounts(categories);
  return {
    status: "comparable",
    message: "Observed project metadata is comparable across both selected scans.",
    counts,
    categories,
  };
}

function trustedBaselineComparison(currentScan, trustedBaseline) {
  if (
    trustedBaseline.status !== "valid"
    || !trustedBaseline.baseline
    || !trustedBaseline.baseline.scan
  ) {
    return unavailableSection(
      "trusted-baseline-unavailable",
      trustedBaseline.message
        || "Trusted baseline unavailable. No automatic baseline was substituted.",
    );
  }
  const baselineScan = trustedBaseline.baseline.scan;
  if (baselineScan.id === currentScan.id) {
    return {
      ...unavailableSection(
        "baseline-is-latest",
        "Baseline is the latest scan. A scan is never compared against itself.",
      ),
      baselineScan: scanIdentity(baselineScan),
    };
  }
  const comparison = compareProjectMetadataScans(baselineScan, currentScan);
  if (comparison.status !== "comparable") {
    return {
      ...comparison,
      status: "indeterminate",
      baselineScan: scanIdentity(baselineScan),
      message: `Trusted baseline comparison is indeterminate. ${comparison.message}`,
    };
  }
  const driftDetected = comparison.counts.added
    + comparison.counts.removed
    + comparison.counts.changed > 0;
  return {
    ...comparison,
    status: driftDetected ? "drift" : "unchanged",
    baselineScan: scanIdentity(baselineScan),
    message: driftDetected
      ? "Observed project metadata changed from the exact trusted baseline."
      : "Observed project metadata matches the exact trusted baseline.",
  };
}

function trustedBaselineSource(value) {
  const scanId = value?.baseline?.scanId;
  const scanDate = value?.baseline?.scanDate;
  return {
    type: value?.status === "valid" ? "trusted" : "trusted-unavailable",
    scan: Number.isSafeInteger(scanId) && scanId > 0
      ? { id: scanId, date: typeof scanDate === "string" ? scanDate : "" }
      : null,
  };
}

function buildExpectationDrift(current, profile) {
  if (!current.reliable) {
    return unavailableSection(
      "indeterminate",
      `Expectation drift cannot be determined reliably. ${current.reason}`,
    );
  }

  const categories = PROJECT_EXPECTATION_FIELDS.map(({ field, label }) => (
    compareCategory(field, label, profile[field], current.values[field])
  ));
  const counts = aggregateCounts(categories);
  const approvedCount = PROJECT_EXPECTATION_FIELDS.reduce(
    (total, { field }) => total + profile[field].length,
    0,
  );
  const driftDetected = counts.added + counts.removed + counts.changed > 0;

  return {
    status: approvedCount === 0 ? "unconfigured" : driftDetected ? "drift" : "unchanged",
    message: approvedCount === 0
      ? "No Project Expectations values are approved. Reliable observations remain unapproved context."
      : driftDetected
        ? "Reliable observations differ from the approved Project Expectations. Approved values were not changed."
        : "Reliable observations match the approved Project Expectations across the supported categories.",
    approvedCount,
    counts,
    categories,
  };
}

function snapshotForScan(scan) {
  if (!scan || typeof scan !== "object" || Array.isArray(scan)) {
    return unreliableSnapshot("Scan data is unavailable or malformed, so drift cannot be determined reliably.");
  }

  const completeness = scan.scanCompleteness;
  if (!completeness || typeof completeness !== "object" || Array.isArray(completeness)) {
    return unreliableSnapshot("The selected scan lacks reliable coverage metadata, so drift cannot be determined.");
  }
  const malformedCount = SCAN_COUNT_FIELDS.some((field) => (
    !Number.isInteger(completeness[field]) || completeness[field] < 0
  ));
  if (malformedCount) {
    return unreliableSnapshot("The selected scan has malformed coverage metadata, so drift cannot be determined reliably.");
  }
  const issueCount = SCAN_COUNT_FIELDS.reduce(
    (total, field) => total + completeness[field],
    0,
  );
  if (!Number.isInteger(completeness.issueCount) || completeness.issueCount !== issueCount) {
    return unreliableSnapshot("The selected scan has malformed coverage metadata, so drift cannot be determined reliably.");
  }
  if (completeness.complete !== true || issueCount > 0) {
    return unreliableSnapshot("The selected scan has incomplete coverage, so drift cannot be determined reliably.");
  }
  if (scan.scanMetadataReliable === false) {
    return unreliableSnapshot("The selected scan contains malformed persisted project metadata, so drift cannot be determined reliably.");
  }

  const values = {};
  for (const { field } of PROJECT_EXPECTATION_FIELDS) {
    const result = observedValues(scan, field);
    if (!result.reliable) {
      const source = CATEGORY_SOURCES[field] === "dependency" ? "dependency" : "scan";
      return unreliableSnapshot(
        `The selected scan has unavailable or malformed ${source} metadata, so drift cannot be determined reliably.`,
      );
    }
    values[field] = result.values;
  }
  return { reliable: true, reason: "", values };
}

function observedValues(scan, field) {
  if (CATEGORY_SOURCES[field] === "dependency") {
    const trust = scan.dependencyTrust;
    if (dependencyTrustHasNoSupportedMetadata(trust)) {
      return { reliable: true, values: [] };
    }
    if (
      !trust
      || typeof trust !== "object"
      || Array.isArray(trust)
      || trust.schemaVersion !== 1
      || trust.status !== "complete"
    ) {
      return { reliable: false, values: [] };
    }
    const key = field === "trustedPackageManagers" ? "packageManagers" : "ecosystems";
    return normalizedStringValues(trust[key], field);
  }

  if (field === "allowedLifecycleScripts") {
    if (!Array.isArray(scan.lifecycleScripts)) return { reliable: false, values: [] };
    const scripts = [];
    for (const item of scan.lifecycleScripts) {
      if (!item || typeof item !== "object" || Array.isArray(item) || typeof item.script !== "string") {
        return { reliable: false, values: [] };
      }
      scripts.push(item.script);
    }
    return normalizedStringValues(scripts, field);
  }

  const key = {
    expectedManifestFiles: "manifests",
    expectedLockfiles: "lockfiles",
    reviewedPaths: "reviewedFiles",
    ignoredPaths: "ignoredFiles",
  }[field];
  return normalizedStringValues(scan[key], field);
}

function normalizedStringValues(value, field) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    return { reliable: false, values: [] };
  }
  const normalized = normalizeProjectExpectations({ [field]: value })[field];
  return { reliable: true, values: normalized.sort((left, right) => left.localeCompare(right)) };
}

function compareCategory(field, label, previous, current) {
  const previousSet = new Set(previous);
  const currentSet = new Set(current);
  const unchanged = current.filter((value) => previousSet.has(value));
  const removedCandidates = previous.filter((value) => !currentSet.has(value));
  const addedCandidates = current.filter((value) => !previousSet.has(value));
  const changedCount = Math.min(removedCandidates.length, addedCandidates.length);
  const changed = Array.from({ length: changedCount }, (_, index) => ({
    before: removedCandidates[index],
    after: addedCandidates[index],
  }));
  const removed = removedCandidates.slice(changedCount);
  const added = addedCandidates.slice(changedCount);
  const status = changed.length || removed.length || added.length ? "changed" : "unchanged";
  const counts = {
    unchanged: unchanged.length,
    added: added.length,
    removed: removed.length,
    changed: changed.length,
  };
  return {
    field,
    label,
    status,
    counts,
    unchanged: unchanged.slice(0, MAX_DRIFT_DETAILS_PER_CATEGORY),
    added: added.slice(0, MAX_DRIFT_DETAILS_PER_CATEGORY),
    removed: removed.slice(0, MAX_DRIFT_DETAILS_PER_CATEGORY),
    changed: changed.slice(0, MAX_DRIFT_DETAILS_PER_CATEGORY),
    omittedDetailCount: Math.max(
      0,
      counts.unchanged + counts.added + counts.removed + counts.changed
        - Math.min(counts.unchanged, MAX_DRIFT_DETAILS_PER_CATEGORY)
        - Math.min(counts.added, MAX_DRIFT_DETAILS_PER_CATEGORY)
        - Math.min(counts.removed, MAX_DRIFT_DETAILS_PER_CATEGORY)
        - Math.min(counts.changed, MAX_DRIFT_DETAILS_PER_CATEGORY),
    ),
  };
}

function aggregateCounts(categories) {
  return categories.reduce((counts, category) => ({
    unchanged: counts.unchanged + category.counts.unchanged,
    added: counts.added + category.counts.added,
    removed: counts.removed + category.counts.removed,
    changed: counts.changed + category.counts.changed,
    unavailable: counts.unavailable,
  }), {
    unchanged: 0,
    added: 0,
    removed: 0,
    changed: 0,
    unavailable: 0,
  });
}

function unavailableSection(status, message) {
  return {
    status,
    message,
    counts: {
      unchanged: 0,
      added: 0,
      removed: 0,
      changed: 0,
      unavailable: PROJECT_EXPECTATION_FIELDS.length,
    },
    categories: [],
  };
}

function unreliableSnapshot(reason) {
  return { reliable: false, reason, values: {} };
}

function scanIdentity(scan) {
  return {
    id: scan?.id ?? null,
    date: typeof scan?.scan_date === "string" ? scan.scan_date : "",
  };
}

function pluralize(count, singular, plural) {
  return count === 1 ? singular : plural;
}
