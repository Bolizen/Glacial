export const PROJECT_EXPECTATION_FIELDS = [
  {
    field: "trustedPackageManagers",
    label: "Package managers",
    description: "Package managers explicitly approved for review context.",
    suggestionSource: "dependency",
  },
  {
    field: "expectedManifestFiles",
    label: "Dependency manifests",
    description: "Manifest paths expected to appear in scans.",
    suggestionSource: "scan",
  },
  {
    field: "expectedLockfiles",
    label: "Lockfiles",
    description: "Lockfile paths expected to appear in scans.",
    suggestionSource: "scan",
  },
  {
    field: "allowedLifecycleScripts",
    label: "Lifecycle scripts",
    description: "Package script names approved as expected review context.",
    suggestionSource: "scan",
  },
  {
    field: "expectedEcosystems",
    label: "Ecosystems",
    description: "Language or package ecosystems explicitly approved for this project.",
    suggestionSource: "dependency",
  },
  {
    field: "reviewedPaths",
    label: "Reviewed paths",
    description: "Broad user-maintained path context. It never reviews a scanner finding.",
    suggestionSource: "none",
  },
  {
    field: "ignoredPaths",
    label: "Expected ignored paths",
    description: "User-maintained ignore context. Glacial never suggests ignoring files.",
    suggestionSource: "none",
  },
];

export const EMPTY_PROJECT_EXPECTATIONS = {
  project_path: "",
  trustedPackageManagers: [],
  expectedManifestFiles: [],
  expectedLockfiles: [],
  allowedLifecycleScripts: [],
  expectedEcosystems: [],
  reviewedPaths: [],
  ignoredPaths: [],
  expectationProvenance: {},
  dismissedSuggestions: {},
  riskTolerance: "normal",
  notes: "",
};

const FIELD_MAP = new Map(PROJECT_EXPECTATION_FIELDS.map((field) => [field.field, field]));
const PATH_FIELDS = new Set(["expectedManifestFiles", "expectedLockfiles", "reviewedPaths", "ignoredPaths"]);
const LOWERCASE_FIELDS = new Set(["trustedPackageManagers", "allowedLifecycleScripts", "expectedEcosystems"]);
const VALID_PROVENANCE = new Set(["accepted-suggestion", "manual"]);
const VALID_RISK_TOLERANCE = new Set(["cautious", "normal", "permissive"]);
const MAX_SUGGESTIONS_PER_FIELD = 50;
const MAX_DISMISSED_SUGGESTIONS_PER_FIELD = 200;

export function normalizeProjectExpectations(value) {
  const source = objectValue(value);
  const profile = { ...EMPTY_PROJECT_EXPECTATIONS, ...source };
  for (const { field } of PROJECT_EXPECTATION_FIELDS) {
    profile[field] = normalizeFieldValues(field, source[field]);
  }
  profile.expectationProvenance = normalizeProvenance(source.expectationProvenance, profile);
  profile.dismissedSuggestions = normalizeDismissedSuggestions(source.dismissedSuggestions, profile);
  const riskTolerance = normalizedText(source.riskTolerance).toLowerCase();
  profile.riskTolerance = VALID_RISK_TOLERANCE.has(riskTolerance) ? riskTolerance : "normal";
  profile.notes = typeof source.notes === "string" ? source.notes.trim() : "";
  return profile;
}

export function buildProjectExpectationsViewModel({ profile, report, scan }) {
  const normalizedProfile = normalizeProjectExpectations(profile);
  const completeness = normalizeCompleteness(report?.completeness);
  const dependencyTrust = objectValue(report?.dependencyTrust);
  const trustedBaseline = objectValue(dependencyTrust.trustedBaseline);
  const dependencyReliable = completeness.reliable
    && dependencyTrust.available === true
    && dependencyTrust.status === "complete";
  const observations = observationMap(report);

  return {
    fields: PROJECT_EXPECTATION_FIELDS.map((definition) => {
      const approved = normalizedProfile[definition.field];
      const observation = observations[definition.field];
      const observed = observation.items;
      const reliable = definition.suggestionSource === "dependency"
        ? dependencyReliable
        : definition.suggestionSource === "scan"
          ? completeness.reliable
          : false;
      const dismissed = normalizedProfile.dismissedSuggestions[definition.field] || [];
      const suggestions = reliable && definition.suggestionSource !== "none"
        ? observed
          .map((item) => item.value)
          .filter((item) => !includesFieldValue(definition.field, approved, item))
          .filter((item) => !includesFieldValue(definition.field, dismissed, item))
          .sort((left, right) => left.localeCompare(right))
          .slice(0, MAX_SUGGESTIONS_PER_FIELD)
        : [];
      const state = expectationState(definition.field, approved, observed, suggestions, reliable);
      return {
        ...definition,
        state,
        approved: approved.map((value) => ({
          value,
          provenance: normalizedProfile.expectationProvenance[definition.field]?.[value] || "legacy-approved",
        })),
        observed,
        observedOmittedCount: observation.omittedCount,
        suggestions,
        dismissedCount: dismissed.length,
        reliable,
        reliabilityMessage: reliabilityMessage({
          scan,
          completeness,
          dependencyTrust,
          source: definition.suggestionSource,
        }),
      };
    }),
    dependency: {
      trust: dependencyTrust,
      configured: trustedBaseline.configured === true,
      valid: trustedBaseline.valid === true,
      status: normalizedText(trustedBaseline.status) || "not-configured",
      label: trustedBaseline.configured === true && trustedBaseline.valid === true
        ? "Separate approval configured"
        : trustedBaseline.configured === true
          ? "Configured snapshot cannot be verified"
          : "No approved dependency snapshot",
    },
    riskTolerance: normalizedProfile.riskTolerance,
    notes: normalizedProfile.notes,
  };
}

export function acceptExpectationSuggestion(profile, field, value) {
  const next = normalizeProjectExpectations(profile);
  if (!FIELD_MAP.has(field)) return next;
  const normalizedValue = normalizeFieldValue(field, value);
  if (!normalizedValue) return next;

  next[field] = appendFieldValue(field, next[field], normalizedValue);
  next.expectationProvenance = {
    ...next.expectationProvenance,
    [field]: {
      ...(next.expectationProvenance[field] || {}),
      [normalizedValue]: "accepted-suggestion",
    },
  };
  next.dismissedSuggestions = updateDismissed(
    next.dismissedSuggestions,
    field,
    (next.dismissedSuggestions[field] || []).filter(
      (item) => comparisonValue(field, item) !== comparisonValue(field, normalizedValue),
    ),
  );
  return next;
}

export function dismissExpectationSuggestion(profile, field, value) {
  const next = normalizeProjectExpectations(profile);
  if (!FIELD_MAP.has(field)) return next;
  const normalizedValue = normalizeFieldValue(field, value);
  if (!normalizedValue || includesFieldValue(field, next[field], normalizedValue)) return next;
  next.dismissedSuggestions = updateDismissed(
    next.dismissedSuggestions,
    field,
    appendFieldValue(field, next.dismissedSuggestions[field] || [], normalizedValue),
  );
  return next;
}

export function editApprovedExpectations(profile, field, values) {
  const next = normalizeProjectExpectations(profile);
  if (!FIELD_MAP.has(field)) return next;
  const approved = normalizeFieldValues(field, values);
  const existingProvenance = next.expectationProvenance[field] || {};
  const fieldProvenance = Object.fromEntries(approved.map((value) => [
    value,
    existingProvenance[value] || "manual",
  ]));
  next[field] = approved;
  next.expectationProvenance = updateFieldObject(next.expectationProvenance, field, fieldProvenance);
  next.dismissedSuggestions = updateDismissed(
    next.dismissedSuggestions,
    field,
    (next.dismissedSuggestions[field] || []).filter(
      (item) => !includesFieldValue(field, approved, item),
    ),
  );
  return next;
}

export function removeApprovedExpectation(profile, field, value) {
  const next = normalizeProjectExpectations(profile);
  if (!FIELD_MAP.has(field)) return next;
  const comparable = comparisonValue(field, value);
  next[field] = next[field].filter((item) => comparisonValue(field, item) !== comparable);
  const fieldProvenance = Object.fromEntries(
    Object.entries(next.expectationProvenance[field] || {})
      .filter(([item]) => comparisonValue(field, item) !== comparable),
  );
  next.expectationProvenance = updateFieldObject(next.expectationProvenance, field, fieldProvenance);
  return next;
}

// Stable, pure seam for a later guarded AGENTS.md preview integration. Nothing in
// this slice writes AGENTS.md or automatically imports these values.
export function buildAgentsProjectContext({ profile, dependencyTrust }) {
  const normalized = normalizeProjectExpectations(profile);
  const approvedExpectations = Object.fromEntries(
    PROJECT_EXPECTATION_FIELDS
      .map(({ field }) => [field, [...normalized[field]]])
      .filter(([, values]) => values.length > 0),
  );
  const trustedBaseline = objectValue(dependencyTrust?.trustedBaseline);
  return {
    schemaVersion: 1,
    approvedExpectations,
    approvedDependencyContext: trustedBaseline.configured === true && trustedBaseline.valid === true
      ? {
          fingerprint: normalizedText(trustedBaseline.fingerprint),
          status: normalizedText(trustedBaseline.status),
          note: normalizedText(trustedBaseline.note),
        }
      : null,
    reviewedSafetyNotes: normalized.notes,
  };
}

export function provenanceLabel(value) {
  if (value === "accepted-suggestion") return "Accepted suggestion";
  if (value === "manual") return "Manual";
  return "Legacy approved";
}

function observationMap(report) {
  const dependencyTrust = objectValue(report?.dependencyTrust);
  return {
    trustedPackageManagers: observedStrings("trustedPackageManagers", dependencyTrust.packageManagers),
    expectedManifestFiles: observedStrings("expectedManifestFiles", report?.manifests),
    expectedLockfiles: observedStrings("expectedLockfiles", report?.lockfiles),
    allowedLifecycleScripts: observedLifecycleScripts(report?.lifecycleScripts),
    expectedEcosystems: observedStrings("expectedEcosystems", dependencyTrust.ecosystems),
    reviewedPaths: observedStrings("reviewedPaths", report?.reviewedFiles),
    ignoredPaths: observedStrings("ignoredPaths", report?.ignoredFiles),
  };
}

function observedStrings(field, values) {
  const normalized = normalizeFieldValues(field, values);
  return {
    items: normalized
      .slice(0, MAX_SUGGESTIONS_PER_FIELD)
      .map((value) => ({ value, detail: "" })),
    omittedCount: Math.max(0, normalized.length - MAX_SUGGESTIONS_PER_FIELD),
  };
}

function observedLifecycleScripts(values) {
  if (!Array.isArray(values)) return { items: [], omittedCount: 0 };
  const normalized = [];
  const seen = new Set();
  for (const item of values) {
    const value = normalizeFieldValue("allowedLifecycleScripts", item?.script);
    if (!value || seen.has(value)) continue;
    seen.add(value);
    normalized.push({
      value,
      detail: normalizedText(item?.path),
    });
  }
  return {
    items: normalized.slice(0, MAX_SUGGESTIONS_PER_FIELD),
    omittedCount: Math.max(0, normalized.length - MAX_SUGGESTIONS_PER_FIELD),
  };
}

function expectationState(field, approved, observed, suggestions, reliable) {
  if (approved.length > 0) {
    if (reliable && !sameFieldValues(field, approved, observed.map((item) => item.value))) return "changed";
    return "approved";
  }
  if (suggestions.length > 0) return "suggested";
  if (observed.length > 0) return "observed";
  return "missing";
}

function reliabilityMessage({ scan, completeness, dependencyTrust, source }) {
  if (source === "none") return "Glacial does not generate automatic suggestions for this field.";
  if (!scan) return "Run a scan before Glacial can derive suggestions.";
  if (!completeness.known) return "This historical scan lacks coverage metadata, so suggestions are withheld.";
  if (!completeness.complete) return "Scan coverage is incomplete, so observations are shown but suggestions are withheld.";
  if (source === "dependency") {
    if (dependencyTrust.available !== true) return "Dependency analysis is unavailable, so suggestions are withheld.";
    if (dependencyTrust.status !== "complete") {
      return "Dependency analysis is not complete, so suggestions are withheld.";
    }
  }
  return "Suggestions are derived only from the displayed scan and remain inert until accepted.";
}

function normalizeCompleteness(value) {
  const source = objectValue(value);
  return {
    known: source.known === true,
    complete: source.complete === true,
    reliable: source.known === true && source.complete === true,
  };
}

function normalizeProvenance(value, profile) {
  const source = objectValue(value);
  const normalized = {};
  for (const { field } of PROJECT_EXPECTATION_FIELDS) {
    const fieldSource = objectValue(source[field]);
    const entries = {};
    for (const approved of profile[field]) {
      const provenance = normalizedText(fieldSource[approved]).toLowerCase();
      if (VALID_PROVENANCE.has(provenance)) entries[approved] = provenance;
    }
    if (Object.keys(entries).length > 0) normalized[field] = entries;
  }
  return normalized;
}

function normalizeDismissedSuggestions(value, profile) {
  const source = objectValue(value);
  const normalized = {};
  for (const { field } of PROJECT_EXPECTATION_FIELDS) {
    const dismissed = normalizeFieldValues(field, source[field])
      .filter((item) => !includesFieldValue(field, profile[field], item))
      .slice(0, MAX_DISMISSED_SUGGESTIONS_PER_FIELD);
    if (dismissed.length > 0) normalized[field] = dismissed;
  }
  return normalized;
}

function normalizeFieldValues(field, values) {
  if (!Array.isArray(values)) return [];
  const normalized = [];
  const seen = new Set();
  for (const item of values) {
    const value = normalizeFieldValue(field, item);
    const comparable = comparisonValue(field, value);
    if (!value || seen.has(comparable)) continue;
    seen.add(comparable);
    normalized.push(value);
  }
  return normalized;
}

function normalizeFieldValue(field, value) {
  if (typeof value !== "string") return "";
  let normalized = normalizedText(value);
  if (!normalized) return "";
  if (PATH_FIELDS.has(field)) {
    normalized = normalized.replaceAll("\\", "/").replace(/^\.\/+/, "");
  }
  if (LOWERCASE_FIELDS.has(field)) normalized = normalized.toLowerCase();
  return normalized;
}

function comparisonValue(field, value) {
  const normalized = normalizeFieldValue(field, value);
  return LOWERCASE_FIELDS.has(field) ? normalized.toLowerCase() : normalized;
}

function appendFieldValue(field, values, value) {
  return normalizeFieldValues(field, [...values, value]);
}

function includesFieldValue(field, values, value) {
  const comparable = comparisonValue(field, value);
  return values.some((item) => comparisonValue(field, item) === comparable);
}

function sameFieldValues(field, left, right) {
  const leftSet = new Set(left.map((item) => comparisonValue(field, item)));
  const rightSet = new Set(right.map((item) => comparisonValue(field, item)));
  return leftSet.size === rightSet.size && [...leftSet].every((item) => rightSet.has(item));
}

function updateDismissed(source, field, values) {
  return updateFieldObject(source, field, values);
}

function updateFieldObject(source, field, value) {
  const next = { ...source };
  if (Array.isArray(value) ? value.length > 0 : Object.keys(value).length > 0) next[field] = value;
  else delete next[field];
  return next;
}

function objectValue(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function normalizedText(value) {
  return value === undefined || value === null
    ? ""
    : String(value).replaceAll(/\s+/g, " ").trim();
}
