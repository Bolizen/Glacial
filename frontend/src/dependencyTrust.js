export const DEPENDENCY_TRUST_SCHEMA_VERSION = 1;
export const DEPENDENCY_ENTRY_DISPLAY_LIMIT = 50;
export const DEPENDENCY_CHANGE_DISPLAY_LIMIT = 50;

const VALID_STATUSES = new Set(["complete", "incomplete", "unsupported", "malformed"]);

export function normalizeDependencyTrust(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || value.schemaVersion !== DEPENDENCY_TRUST_SCHEMA_VERSION) {
    return unavailableDependencyTrust();
  }
  const entries = arrayOfObjects(value.entries).map(normalizeEntry).sort(compareEntries);
  const changes = arrayOfObjects(value.comparison?.changes).map(normalizeChange).sort(compareChanges);
  const limitations = arrayOfObjects(value.limitations).map((item) => ({
    reason: text(item.reason) || "analysis limitation",
    explanation: text(item.explanation),
    path: text(item.path),
  })).sort((left, right) => `${left.path}\0${left.reason}`.localeCompare(`${right.path}\0${right.reason}`));
  const status = VALID_STATUSES.has(value.status) ? value.status : "incomplete";
  return {
    available: true,
    schemaVersion: DEPENDENCY_TRUST_SCHEMA_VERSION,
    status,
    ecosystems: stringArray(value.ecosystems),
    manifests: stringArray(value.manifests),
    lockfiles: stringArray(value.lockfiles),
    packageManagers: stringArray(value.packageManagers),
    directDependencyCount: count(value.directDependencyCount),
    lockedDependencyCount: count(value.lockedDependencyCount),
    integrityCoverage: {
      total: count(value.integrityCoverage?.total),
      present: count(value.integrityCoverage?.present),
      missing: count(value.integrityCoverage?.missing),
    },
    unusualSourceCount: count(value.unusualSourceCount),
    installScriptIndicatorCount: count(value.installScriptIndicatorCount),
    consistencyIssueCount: count(value.consistencyIssueCount),
    changeCount: count(value.changeCount),
    highestFindingSeverity: text(value.highestFindingSeverity) || "none",
    entries: entries.slice(0, DEPENDENCY_ENTRY_DISPLAY_LIMIT),
    hiddenEntryCount: Math.max(0, entries.length - DEPENDENCY_ENTRY_DISPLAY_LIMIT),
    comparison: {
      baselineStatus: text(value.comparison?.baselineStatus) || "unavailable",
      changeCount: count(value.comparison?.changeCount),
      changes: changes.slice(0, DEPENDENCY_CHANGE_DISPLAY_LIMIT),
      hiddenChangeCount: Math.max(0, changes.length - DEPENDENCY_CHANGE_DISPLAY_LIMIT),
      explanation: text(value.comparison?.explanation),
      fileChanges: normalizeFileChanges(value.comparison?.fileChanges),
    },
    limitations,
    offlineOnly: value.offlineOnly !== false,
  };
}

export function dependencyStatusLabel(trust) {
  if (!trust?.available) return "Analysis unavailable";
  if (trust.status === "complete") return "Checks complete";
  if (trust.status === "malformed") return "Malformed metadata";
  if (dependencyTrustHasNoSupportedMetadata(trust)) return "No metadata detected";
  if (trust.status === "unsupported") return "Unsupported metadata";
  return "Incomplete";
}

export function dependencyReportStatusLabel(trust) {
  if (!trust?.available) return "Analysis unavailable";
  if (trust.status === "complete") return "Supported checks complete";
  if (trust.status === "malformed") return "Malformed dependency metadata";
  if (dependencyTrustHasNoSupportedMetadata(trust)) return "No supported dependency metadata detected";
  if (trust.status === "unsupported") return "Unsupported dependency metadata";
  return "Analysis incomplete";
}

export function dependencyStatusDescription(trust) {
  if (!trust?.available) return "This scan predates dependency analysis, so no dependency-trust assessment is available.";
  if (dependencyTrustHasNoSupportedMetadata(trust)) {
    return "No supported Node or Python dependency graph was analyzed. This does not verify that the project has no dependencies or dependency risk.";
  }
  if (trust.status === "unsupported") return "Dependency metadata was detected, but its format is not supported for offline analysis.";
  if (trust.status === "malformed") return "Dependency metadata could not be parsed reliably, so no complete dependency assessment is available.";
  if (trust.status === "incomplete") return "Some detected dependency metadata could not be analyzed completely.";
  return "Supported local dependency metadata checks completed. Offline analysis does not establish package reputation or safety.";
}

export function dependencyTrustHasNoSupportedMetadata(trust) {
  return Boolean(trust?.available)
    && trust.status === "unsupported"
    && (trust.ecosystems?.length || 0) === 0
    && (trust.manifests?.length || 0) === 0
    && (trust.lockfiles?.length || 0) === 0
    && (trust.packageManagers?.length || 0) === 0
    && (trust.entries?.length || 0) === 0;
}

function unavailableDependencyTrust() {
  return {
    available: false,
    schemaVersion: 0,
    status: "unavailable",
    ecosystems: [],
    manifests: [],
    lockfiles: [],
    packageManagers: [],
    directDependencyCount: 0,
    lockedDependencyCount: 0,
    integrityCoverage: { total: 0, present: 0, missing: 0 },
    unusualSourceCount: 0,
    installScriptIndicatorCount: 0,
    consistencyIssueCount: 0,
    changeCount: 0,
    highestFindingSeverity: "none",
    entries: [],
    hiddenEntryCount: 0,
    comparison: {
      baselineStatus: "unavailable",
      changeCount: 0,
      changes: [],
      hiddenChangeCount: 0,
      explanation: "This scan predates offline dependency analysis.",
      fileChanges: { manifestsAdded: [], manifestsRemoved: [], lockfilesAdded: [], lockfilesRemoved: [] },
    },
    limitations: [],
    offlineOnly: true,
  };
}

function normalizeEntry(entry) {
  return {
    ecosystem: text(entry.ecosystem) || "unknown",
    name: text(entry.name) || "unknown package",
    group: text(entry.group) || "unknown",
    requestedSpecification: text(entry.requestedSpecification),
    lockedVersion: text(entry.lockedVersion),
    sourceType: text(entry.sourceType) || "unknown",
    sourceIdentifier: text(entry.sourceIdentifier),
    integrityPresent: entry.integrityPresent === true,
    direct: entry.direct === true,
    optional: entry.optional === true,
    dev: entry.dev === true,
    peer: entry.peer === true,
    installScriptIndicator: entry.installScriptIndicator === true,
    manifestPath: text(entry.manifestPath),
    lockfilePath: text(entry.lockfilePath),
  };
}

function normalizeChange(change) {
  return {
    changeType: text(change.changeType) || "changed",
    ecosystem: text(change.ecosystem),
    name: text(change.name),
    group: text(change.group),
    requestedSpecification: text(change.requestedSpecification),
    lockedVersion: text(change.lockedVersion),
    sourceType: text(change.sourceType),
    sourceIdentifier: text(change.sourceIdentifier),
    previousValue: text(change.previousValue),
    currentValue: text(change.currentValue),
  };
}

function normalizeFileChanges(value) {
  return {
    manifestsAdded: stringArray(value?.manifestsAdded),
    manifestsRemoved: stringArray(value?.manifestsRemoved),
    lockfilesAdded: stringArray(value?.lockfilesAdded),
    lockfilesRemoved: stringArray(value?.lockfilesRemoved),
  };
}

function arrayOfObjects(value) {
  return Array.isArray(value) ? value.filter((item) => item && typeof item === "object" && !Array.isArray(item)) : [];
}

function stringArray(value) {
  return Array.isArray(value) ? [...new Set(value.map(text).filter(Boolean))].sort() : [];
}

function count(value) {
  const number = Number(value);
  return Number.isInteger(number) && number >= 0 ? number : 0;
}

function text(value) {
  return value === undefined || value === null ? "" : String(value).replaceAll(/\s+/g, " ").trim();
}

function compareEntries(left, right) {
  return [left.direct ? "0" : "1", left.ecosystem, left.name, left.group, left.lockedVersion]
    .join("\0").localeCompare([right.direct ? "0" : "1", right.ecosystem, right.name, right.group, right.lockedVersion].join("\0"));
}

function compareChanges(left, right) {
  return [left.changeType, left.ecosystem, left.name, left.group]
    .join("\0").localeCompare([right.changeType, right.ecosystem, right.name, right.group].join("\0"));
}
