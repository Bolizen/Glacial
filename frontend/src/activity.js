const CATEGORY_LABELS = {
  trustedPackageManagers: "Package managers",
  expectedManifestFiles: "Dependency manifests",
  expectedLockfiles: "Lockfiles",
  allowedLifecycleScripts: "Lifecycle scripts",
  expectedEcosystems: "Ecosystems",
  reviewedPaths: "Reviewed paths",
  ignoredPaths: "Ignored paths",
};

const EVENT_TITLES = {
  project_registered: "Project registered",
  scan_completed: "Scan completed",
  project_expectations_updated: "Project Expectations updated",
  observed_drift_adopted: "Observed drift adopted",
  finding_review_completed: "Finding review completed",
  dependency_review_completed: "Dependency review completed",
};

export function normalizeActivityPage(value) {
  if (!isRecord(value)) return emptyPage();
  const events = Array.isArray(value.events)
    ? value.events.map(normalizeActivityEvent).filter(Boolean)
    : [];
  const hasMore = value.has_more === true;
  const nextOffset = hasMore && Number.isSafeInteger(value.next_offset) && value.next_offset >= 0
    ? value.next_offset
    : null;
  return { events, hasMore: hasMore && nextOffset !== null, nextOffset };
}

export function activityTitle(event) {
  if (event?.malformed && !EVENT_TITLES[event.eventType]) return "Project activity";
  return EVENT_TITLES[event?.eventType] || "Project activity";
}

export function activityDetail(event) {
  if (!event || event.malformed) {
    return "Stored activity details are unavailable. The underlying project data was not changed.";
  }
  const details = event.details;
  if (event.eventType === "project_registered") {
    return details.projectName ? `${details.projectName} was added to this workspace.` : "Project added to this workspace.";
  }
  if (event.eventType === "scan_completed") {
    const status = {
      completed: "Completed",
      incomplete: "Incomplete",
      failed: "Failed",
      unknown: "Status unavailable",
    }[details.status] || "Status unavailable";
    return `${status} · ${countLabel(details.findingCount, "finding")} · ${countLabel(details.reviewedCount, "reviewed finding")} · Coverage ${details.coverageStatus || "unknown"} · Dependencies ${details.dependencyStatus || "unavailable"}.`;
  }
  if (event.eventType === "project_expectations_updated") {
    const labels = details.changedCategories.map((field) => CATEGORY_LABELS[field] || "Other expectation");
    if (details.reviewContextChanged) labels.push("Review context");
    return labels.length > 0 ? `Changed: ${labels.join(", ")}.` : "Approved expectation context changed.";
  }
  if (event.eventType === "observed_drift_adopted") {
    const category = CATEGORY_LABELS[details.category] || "Project expectation";
    const replacement = details.replacedValue ? `, replacing ${details.replacedValue}` : "";
    return `${category}: adopted ${details.adoptedValue}${replacement}.`;
  }
  if (event.eventType === "finding_review_completed") {
    return `${details.reviewedCount} of ${details.totalFindingCount} findings have review decisions.`;
  }
  if (event.eventType === "dependency_review_completed") {
    return details.status === "approved"
      ? "The current dependency snapshot was explicitly approved."
      : "Dependency review state changed.";
  }
  return "Stored activity details are unavailable. The underlying project data was not changed.";
}

export function groupActivityByDate(events) {
  const groups = [];
  for (const event of events) {
    const label = dateLabel(event.timestamp);
    const current = groups[groups.length - 1];
    if (current?.label === label) {
      current.events.push(event);
    } else {
      groups.push({ label, events: [event] });
    }
  }
  return groups;
}

export function activityTimeLabel(value) {
  const date = validDate(value);
  return date
    ? new Intl.DateTimeFormat(undefined, { timeStyle: "short" }).format(date)
    : "Time unavailable";
}

function normalizeActivityEvent(value) {
  if (!isRecord(value)) return null;
  const eventId = boundedText(value.eventId, 100);
  if (!eventId) return null;
  const details = isRecord(value.details) ? value.details : {};
  return {
    eventId,
    projectId: boundedText(value.projectId, 1000),
    eventType: boundedText(value.eventType, 80) || "unknown",
    timestamp: boundedText(value.timestamp, 100),
    relatedScanId: Number.isSafeInteger(value.relatedScanId) && value.relatedScanId > 0
      ? value.relatedScanId
      : null,
    details: boundedDetails(details),
    malformed: value.malformed === true || !isRecord(value.details),
  };
}

function boundedDetails(value) {
  const details = {};
  for (const [key, item] of Object.entries(value).slice(0, 20)) {
    if (typeof item === "string") details[key] = boundedText(item, 500);
    else if (typeof item === "boolean") details[key] = item;
    else if (Number.isSafeInteger(item)) details[key] = item;
    else if (Array.isArray(item)) details[key] = item.filter((entry) => typeof entry === "string").slice(0, 20).map((entry) => boundedText(entry, 500));
  }
  if (!Array.isArray(details.changedCategories)) details.changedCategories = [];
  return details;
}

function dateLabel(value) {
  const date = validDate(value);
  return date
    ? new Intl.DateTimeFormat(undefined, { dateStyle: "long" }).format(date)
    : "Date unavailable";
}

function validDate(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function countLabel(value, noun) {
  const count = Number.isSafeInteger(value) && value >= 0 ? value : 0;
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

function boundedText(value, limit) {
  return typeof value === "string" ? value.trim().slice(0, limit) : "";
}

function emptyPage() {
  return { events: [], hasMore: false, nextOffset: null };
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
