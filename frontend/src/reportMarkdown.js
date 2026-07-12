export const SCAN_GUIDANCE = {
  manifests: {
    why: "Manifest files define dependencies, scripts, and package metadata for the project.",
    check: "Review dependency sources, scripts, and unexpected package changes before trusting the project.",
  },
  lockfiles: {
    why: "Lockfiles pin exact dependency versions and can reveal supply-chain drift.",
    check: "Look for unexpected version changes, new transitive dependencies, or lockfile churn.",
  },
  lifecycleScripts: {
    why: "Lifecycle scripts can execute automatically during install or build steps.",
    check: "Inspect scripts before running install commands or generated project tooling.",
  },
  secretFiles: {
    why: "Secret-looking files may contain credentials, tokens, or local environment values.",
    check: "Confirm they are not committed or exposed, and rotate anything accidentally shared.",
  },
  ignoredFiles: {
    why: "Ignored files can hide local configuration, build output, or sensitive files from Git.",
    check: "Confirm ignored paths are intentional and not masking important project state.",
  },
  reviewedFiles: {
    why: "Reviewed files help separate known project files from files that still need attention.",
    check: "Re-review them after major dependency, script, or configuration changes.",
  },
  zone: {
    why: "Zone classification helps separate normal project areas from files needing closer inspection.",
    check: "Pay attention to files outside expected source, config, dependency, or documentation areas.",
  },
};

const FINDING_DETAILS = {
  manifest: {
    category: "manifest",
    title: "Dependency manifest found",
    why: "Dependency manifests declare packages, scripts, or tooling that can affect install and build behavior.",
    action: "Review declared dependencies and scripts before running package commands.",
  },
  lockfile: {
    category: "lockfile",
    title: "Dependency lockfile found",
    why: "Lockfiles pin resolved dependency versions and can show dependency changes.",
    action: "Review dependency changes before installing.",
  },
  "package-lifecycle-script": {
    category: "lifecycle script",
    title: "Package lifecycle script found",
    why: "Package lifecycle scripts can run during install or build commands.",
    action: "Review the script before running package commands.",
  },
  "secret-looking-file": {
    category: "secret-looking file",
    title: "Secret-looking file name found",
    why: "The file name suggests it may contain sensitive material.",
    action: "Confirm it does not contain secrets before sharing or committing.",
  },
  "executable-or-script-file": {
    category: "executable file",
    title: "Executable or script file found",
    why: "Executable files and scripts can run commands on this machine.",
    action: "Review before running.",
  },
  "suspicious-text-pattern": {
    category: "zone/metadata",
    title: "Text pattern may require review",
    why: "Scanner metadata or text patterns may indicate commands that fetch content, launch processes, or decode data.",
    action: "Review the source and context before trusting or running it.",
  },
  "package-json-read-error": {
    category: "manifest",
    title: "package.json could not be parsed",
    why: "The manifest could not be read as valid JSON, so dependency and script review may be incomplete.",
    action: "Open and review package.json manually before installing dependencies.",
  },
};

const FINDING_STANDARD_FIELDS = new Set([
  "action",
  "category",
  "explanation",
  "file_path",
  "finding_type",
  "message",
  "path",
  "recommended_action",
  "severity",
  "title",
  "type",
]);

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2, none: 3 };

export function normalizeScanCompleteness(result) {
  const value = result?.scanCompleteness;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {
      known: false,
      complete: false,
      traversalFailureCount: 0,
      fileInspectionFailureCount: 0,
      oversizedFileCount: 0,
      unsafePathCount: 0,
      issueCount: 0,
    };
  }
  const counts = {
    traversalFailureCount: nonNegativeCount(value.traversalFailureCount),
    fileInspectionFailureCount: nonNegativeCount(value.fileInspectionFailureCount),
    oversizedFileCount: nonNegativeCount(value.oversizedFileCount),
    unsafePathCount: nonNegativeCount(value.unsafePathCount),
  };
  const issueCount = Object.values(counts).reduce((total, count) => total + count, 0);
  return {
    known: true,
    complete: value.complete === true && issueCount === 0,
    ...counts,
    issueCount,
  };
}

export function normalizeFinding(finding = {}) {
  const type = presentText(finding.type) || presentText(finding.finding_type) || "unknown";
  const severity = presentText(finding.severity) || "low";
  const path = presentText(finding.path) || presentText(finding.file_path) || "Unknown path";
  const explanation = presentText(finding.explanation) || presentText(finding.message);
  const mapped = FINDING_DETAILS[type] || {};
  return {
    category: presentText(finding.category) || mapped.category || humanizeFindingType(type),
    severity,
    path,
    title: presentText(finding.title) || mapped.title || humanizeFindingType(type),
    why: mapped.why || explanation || "This item may require attention during review.",
    action: presentText(finding.action)
      || presentText(finding.recommended_action)
      || mapped.action
      || "Review this item before running, sharing, or committing the project.",
  };
}

export function buildScanReportMarkdown(result, report, comparison, trustContext) {
  const findings = Array.isArray(result?.findings) ? [...result.findings].sort(compareFindings) : [];
  const completeness = normalizeScanCompleteness(result);
  const summaryLines = ["## Summary"];
  appendOptionalLine(summaryLines, "Project", inlineCode(result?.project_path));
  appendOptionalLine(summaryLines, "Scan date", formatReportDate(result?.scan_date));
  summaryLines.push(`Findings: ${findings.length}`);
  summaryLines.push(`Reviewed files: ${numberOrZero(report?.reviewedFileCount)}`);
  summaryLines.push(`Ignored files: ${numberOrZero(report?.ignoredFileCount)}`);

  return [
    "# Scan Report",
    "",
    ...summaryLines,
    "",
    "## Risk score",
    escapeMarkdownText(formatRiskLabel(result?.overall_risk)),
    "",
    "## Scan completeness",
    formatScanCompleteness(completeness),
    "",
    "## Findings",
    formatFindings(findings),
    "",
    "## Manifests",
    formatMarkdownGuidance(SCAN_GUIDANCE.manifests),
    "",
    formatMarkdownList(report?.manifests, "No manifests found."),
    "",
    "## Lockfiles",
    formatMarkdownGuidance(SCAN_GUIDANCE.lockfiles),
    "",
    formatMarkdownList(report?.lockfiles, "No lockfiles found."),
    "",
    "## Lifecycle scripts",
    formatMarkdownGuidance(SCAN_GUIDANCE.lifecycleScripts),
    "",
    formatLifecycleScripts(report?.lifecycleScripts),
    "",
    "## Secrets",
    formatMarkdownGuidance(SCAN_GUIDANCE.secretFiles),
    "",
    formatMarkdownList(report?.secretFiles, "No secret-looking files found."),
    "",
    "## Ignored files",
    formatMarkdownGuidance(SCAN_GUIDANCE.ignoredFiles),
    "",
    formatPathMetadataList(report?.ignoredFiles, report?.ignoredFileCount, "No files ignored by .codexforgeignore."),
    "",
    "## Reviewed files",
    formatMarkdownGuidance(SCAN_GUIDANCE.reviewedFiles),
    "",
    formatPathMetadataList(report?.reviewedFiles, report?.reviewedFileCount, "No reviewed files recorded for this scan."),
    "",
    "## Zone",
    formatMarkdownGuidance(SCAN_GUIDANCE.zone),
    "",
    escapeMarkdownText(presentText(report?.zone) || "Unknown"),
    "",
    "## Trust Profile Context",
    formatMarkdownTrustContext(trustContext),
    "",
    "## Comparison with previous scan",
    formatMarkdownComparison(comparison),
    "",
  ].join("\n");
}

function formatScanCompleteness(completeness) {
  if (!completeness.known) {
    return "Status: Coverage unknown. This older scan does not contain completeness metadata.";
  }
  return [
    `Status: ${completeness.complete ? "Complete" : "Incomplete"}`,
    `- Directory traversal failures: ${completeness.traversalFailureCount}`,
    `- File inspection/read failures: ${completeness.fileInspectionFailureCount}`,
    `- Oversized files skipped: ${completeness.oversizedFileCount}`,
    `- Unsafe linked or hardlinked paths skipped: ${completeness.unsafePathCount}`,
    `- Total inspection issues: ${completeness.issueCount}`,
  ].join("\n");
}

function formatFindings(findings) {
  if (!findings.length) return "No scanner findings.";

  return findings.map((finding, index) => {
    const detail = normalizeFinding(finding);
    const type = presentText(finding.type) || presentText(finding.finding_type) || "unknown";
    const category = detail.category;
    const path = presentText(finding.path) || presentText(finding.file_path);
    const explanation = presentText(finding.explanation);
    const message = presentText(finding.message);
    const action = detail.action;
    const lines = [`### Finding ${index + 1}: ${escapeMarkdownText(detail.title)}`];

    appendOptionalListItem(lines, "Severity", inlineCode(presentText(finding.severity) || detail.severity));
    appendOptionalListItem(lines, "Type", inlineCode(type));
    appendOptionalListItem(lines, "Category", escapeMarkdownText(category));
    appendOptionalListItem(lines, "Path", inlineCode(path));
    appendOptionalListItem(lines, "Explanation", escapeMarkdownText(explanation));
    if (message && message !== explanation) {
      appendOptionalListItem(lines, "Message", escapeMarkdownText(message));
    }
    appendOptionalListItem(lines, "Recommended action", escapeMarkdownText(action));

    const metadata = findingMetadata(finding);
    if (metadata.length) {
      lines.push("- Metadata:");
      metadata.forEach(([key, value]) => {
        lines.push(`  - ${escapeMarkdownText(formatMetadataLabel(key))}: ${inlineCode(value)}`);
      });
    }
    return lines.join("\n");
  }).join("\n\n");
}

function findingMetadata(finding) {
  return Object.keys(finding || {})
    .filter((key) => !FINDING_STANDARD_FIELDS.has(key) && !isInternalMetadataKey(key))
    .sort((left, right) => left.localeCompare(right))
    .map((key) => [key, serializeMetadata(finding[key])])
    .filter(([, value]) => value);
}

function serializeMetadata(value) {
  const sanitized = sanitizeMetadata(value);
  if (sanitized === undefined) return "";
  if (typeof value === "object") {
    try {
      return JSON.stringify(sanitized);
    } catch {
      return "";
    }
  }
  return presentText(sanitized);
}

function sanitizeMetadata(value, seen = new Set()) {
  if (value === undefined || value === null || value === "") return undefined;
  if (!value || typeof value !== "object") return value;
  if (seen.has(value)) return undefined;

  seen.add(value);
  if (Array.isArray(value)) {
    const result = value.map((item) => sanitizeMetadata(item, seen)).filter((item) => item !== undefined);
    seen.delete(value);
    return result;
  }

  const entries = Object.keys(value)
    .filter((key) => !isInternalMetadataKey(key))
    .sort((left, right) => left.localeCompare(right))
    .map((key) => [key, sanitizeMetadata(value[key], seen)])
    .filter(([, item]) => item !== undefined);
  seen.delete(value);
  return Object.fromEntries(entries);
}

function isInternalMetadataKey(key) {
  return String(key).startsWith("_");
}

function compareFindings(left, right) {
  const leftSeverity = presentText(left?.severity)?.toLowerCase() || "none";
  const rightSeverity = presentText(right?.severity)?.toLowerCase() || "none";
  const severityDifference = (SEVERITY_ORDER[leftSeverity] ?? 4) - (SEVERITY_ORDER[rightSeverity] ?? 4);
  if (severityDifference) return severityDifference;

  return findingSortKey(left).localeCompare(findingSortKey(right));
}

function findingSortKey(finding) {
  return [
    presentText(finding?.type) || presentText(finding?.finding_type),
    presentText(finding?.path) || presentText(finding?.file_path),
    presentText(finding?.explanation) || presentText(finding?.message),
    serializeMetadata(finding),
  ].join("\u0000");
}

function formatMarkdownList(items, emptyText) {
  const lines = Array.isArray(items)
    ? items.map(inlineCode).filter(Boolean).map((item) => `- ${item}`)
    : [];
  return lines.length ? lines.join("\n") : emptyText;
}

function formatMarkdownGuidance(guidance) {
  if (!guidance) return "";
  return [
    `Why this matters: ${escapeMarkdownText(guidance.why)}`,
    `What to check: ${escapeMarkdownText(guidance.check)}`,
  ].join("\n");
}

function formatLifecycleScripts(items) {
  if (!Array.isArray(items) || !items.length) return "No package lifecycle scripts found.";
  const lines = items.map((item) => {
    const path = inlineCode(item?.path);
    const script = escapeMarkdownText(item?.script);
    if (path && script) return `- ${path}: ${script}`;
    if (path) return `- ${path}`;
    if (script) return `- ${script}`;
    return "";
  }).filter(Boolean);
  return lines.length ? lines.join("\n") : "No package lifecycle scripts found.";
}

function formatPathMetadataList(items, recordedCount, emptyText) {
  if (Array.isArray(items) && items.length) return formatMarkdownList(items, emptyText);
  return numberOrZero(recordedCount) > 0
    ? `${numberOrZero(recordedCount)} paths recorded; path list unavailable for this older scan.`
    : emptyText;
}

function formatMarkdownComparison(comparison) {
  if (!comparison) return "No previous scan to compare yet.";
  return [
    ["Risk", comparison.riskChange],
    ["Findings", comparison.findingDelta],
    ["Reviewed files", comparison.reviewedDelta],
    ["Ignored files", comparison.ignoredDelta],
    ["Finding types", comparison.typeSummary],
  ].filter(([, value]) => presentText(value))
    .map(([label, value]) => `- ${label}: ${escapeMarkdownText(value)}`)
    .join("\n");
}

function formatMarkdownTrustContext(context) {
  if (!context?.configured) {
    return "No trust profile configured. Trust profile context is optional and does not hide scanner findings.";
  }

  const lines = [];
  if (context.packageManagers?.length) {
    const packageManagers = context.packageManagers.map(escapeMarkdownText).filter(Boolean);
    if (packageManagers.length) lines.push(`- Package managers: ${packageManagers.join(", ")}`);
  }
  appendOptionalListItem(lines, "Risk tolerance", escapeMarkdownText(context.riskTolerance));
  appendTrustContextLines(lines, "Manifests", context.manifests);
  appendTrustContextLines(lines, "Lockfiles", context.lockfiles);
  appendTrustContextLines(lines, "Lifecycle scripts", context.lifecycleScripts);
  appendTrustContextLines(lines, "Reviewed paths", context.reviewedPaths);
  appendTrustContextLines(lines, "Ignored paths", context.ignoredPaths);
  appendOptionalListItem(lines, "Notes", escapeMarkdownText(context.notes));
  return lines.join("\n");
}

function appendTrustContextLines(lines, title, items) {
  if (!items?.length) return;
  const itemLines = items.map((item) => {
    const status = escapeMarkdownText(item?.status);
    const path = inlineCode(item?.path);
    if (status && path) return `  - ${status}: ${path}`;
    if (status) return `  - ${status}`;
    if (path) return `  - ${path}`;
    return "";
  }).filter(Boolean);
  if (!itemLines.length) return;
  lines.push(`- ${title}:`, ...itemLines);
}

function appendOptionalLine(lines, label, value) {
  if (value) lines.push(`${label}: ${value}`);
}

function appendOptionalListItem(lines, label, value) {
  if (value) lines.push(`- ${label}: ${value}`);
}

function inlineCode(value) {
  const text = presentText(value);
  if (!text) return "";
  const longestFence = Math.max(0, ...Array.from(text.matchAll(/`+/g), (match) => match[0].length));
  const fence = "`".repeat(longestFence + 1);
  const padding = text.startsWith("`") || text.endsWith("`") ? " " : "";
  return `${fence}${padding}${text}${padding}${fence}`;
}

function escapeMarkdownText(value) {
  const text = presentText(value);
  if (!text) return "";
  return text.replace(/([\\`*_{}\[\]<>~])/g, "\\$1");
}

function presentText(value) {
  if (value === undefined || value === null) return "";
  return String(value).replaceAll(/\s+/g, " ").trim();
}

function humanizeFindingType(type) {
  return presentText(type).replaceAll("-", " ") || "unknown";
}

function formatMetadataLabel(key) {
  const label = presentText(key).replaceAll(/[-_]+/g, " ");
  return label ? `${label[0].toUpperCase()}${label.slice(1)}` : "Metadata";
}

function numberOrZero(value) {
  return Number.isFinite(Number(value)) ? Number(value) : 0;
}

function nonNegativeCount(value) {
  const count = Number(value);
  return Number.isInteger(count) && count >= 0 ? count : 0;
}

function formatRiskLabel(risk) {
  const value = presentText(risk);
  return value ? value.toUpperCase() : "NONE";
}

function formatReportDate(value) {
  if (!presentText(value)) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return presentText(value);
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}
