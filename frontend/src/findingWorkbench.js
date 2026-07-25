import { normalizeFinding } from "./reportMarkdown.js";


const SEVERITY_RANK = new Map([
  ["critical", 0],
  ["high", 1],
  ["medium", 2],
  ["low", 3],
  ["none", 4],
]);


export function buildFindingWorkbenchItems(findings = []) {
  if (!Array.isArray(findings)) return [];

  return findings
    .map((finding, originalIndex) => {
      const detail = normalizeFinding(finding);
      return {
        detail,
        finding,
        key: findingWorkbenchKey(finding, originalIndex),
        originalIndex,
        reviewed: Boolean(finding?.review),
      };
    })
    .sort(compareWorkbenchItems);
}


export function filterFindingWorkbenchItems(items, filters = {}) {
  const reviewStatus = filters.reviewStatus || "all";
  const severity = filters.severity || "all";
  const category = filters.category || "all";
  const query = String(filters.query || "").trim().toLocaleLowerCase();

  return items.filter((item) => {
    if (reviewStatus === "unresolved" && item.reviewed) return false;
    if (reviewStatus === "reviewed" && !item.reviewed) return false;
    if (severity === "critical-high" && !["critical", "high"].includes(item.detail.severity)) return false;
    if (!["all", "critical-high"].includes(severity) && item.detail.severity !== severity) return false;
    if (category !== "all" && item.detail.category !== category) return false;
    if (!query) return true;
    return item.detail.title.toLocaleLowerCase().includes(query)
      || item.detail.path.toLocaleLowerCase().includes(query);
  });
}


export function findingWorkbenchProgress(items) {
  const reviewed = items.reduce((count, item) => count + Number(item.reviewed), 0);
  return { reviewed, total: items.length, unresolved: items.length - reviewed };
}


export function findingWorkbenchFilterOptions(items) {
  return {
    categories: uniqueSorted(items.map((item) => item.detail.category)),
    severities: uniqueSorted(
      items.map((item) => item.detail.severity),
      (left, right) => severityRank(left) - severityRank(right) || left.localeCompare(right),
    ),
  };
}


export function nextUnresolvedFindingKey(items, currentKey = "") {
  const unresolved = items.filter((item) => !item.reviewed);
  if (unresolved.length === 0) return "";
  const currentIndex = unresolved.findIndex((item) => item.key === currentKey);
  return unresolved[(currentIndex + 1) % unresolved.length].key;
}


function compareWorkbenchItems(left, right) {
  return Number(left.reviewed) - Number(right.reviewed)
    || severityRank(left.detail.severity) - severityRank(right.detail.severity)
    || left.originalIndex - right.originalIndex;
}


function severityRank(severity) {
  return SEVERITY_RANK.get(severity) ?? SEVERITY_RANK.size;
}


function findingWorkbenchKey(finding, index) {
  return finding?.fingerprint || [
    finding?.type || "unknown",
    finding?.severity || "low",
    finding?.path || "unknown-path",
    finding?.explanation || "",
    index,
  ].join("|");
}


function uniqueSorted(values, compare = (left, right) => left.localeCompare(right)) {
  return [...new Set(values.filter(Boolean))].sort(compare);
}
