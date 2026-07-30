import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..", "..");
const contractPath = resolve(root, "docs", "release", "v1.0-readiness-contract.md");
const auditPath = resolve(root, "docs", "release", "v1.0-gap-audit.md");
const jsonPath = resolve(root, "docs", "release", "v1.0-gap-audit.json");
const sequencePath = resolve(root, "docs", "release", "v1.0-remediation-sequence.md");

const contract = readFileSync(contractPath, "utf8");
const audit = readFileSync(auditPath, "utf8");
const snapshot = JSON.parse(readFileSync(jsonPath, "utf8"));
const sequence = readFileSync(sequencePath, "utf8");

const idPattern = /^V1-(VER|SCAN|FS|DATA|AGENT|DESKTOP|SEC|REL|DOC|UX)-\d{3}$/;
const allowedStatuses = new Set(["PASS", "PARTIAL", "FAIL", "UNKNOWN", "NOT_APPLICABLE"]);
const allowedPriorities = new Set(["P0", "P1", "P2", "P3"]);
const expectedSequenceHeadings = ["G047", "G048", "G049", "G050", "G051", "G052", "G053", "G054", "G055", "G056", "G057", "G058"];
const installedOnlyDecision = "Glacial v1 does not provide or support a portable binary edition. The supported Windows product is the installed NSIS edition.";

function fail(message) {
  throw new Error(`v1 readiness audit validation failed: ${message}`);
}

function tableRows(markdown) {
  return markdown
    .split(/\r?\n/)
    .filter((line) => /^\|\s*V1-[A-Z]+-\d{3}\s*\|/.test(line))
    .map((line) => line.split("|").slice(1, -1).map((cell) => cell.trim()));
}

function requireUnique(values, label) {
  const duplicates = values.filter((value, index) => values.indexOf(value) !== index);
  if (duplicates.length) fail(`${label} contains duplicate IDs: ${[...new Set(duplicates)].join(", ")}`);
}

function requireSameIds(expected, actual, label) {
  const expectedSet = new Set(expected);
  const actualSet = new Set(actual);
  const missing = expected.filter((id) => !actualSet.has(id));
  const unexpected = actual.filter((id) => !expectedSet.has(id));
  if (missing.length || unexpected.length) {
    fail(`${label} ID mismatch; missing=[${missing.join(", ")}] unexpected=[${unexpected.join(", ")}]`);
  }
}

const contractRows = tableRows(contract);
const auditRows = tableRows(audit);
const contractIds = contractRows.map(([id]) => id);
const auditIds = auditRows.map(([id]) => id);
const jsonIds = snapshot.requirements.map(({ id }) => id);

if (contractIds.length === 0) fail("contract contains no requirements");
if (auditIds.length === 0) fail("Markdown audit contains no requirement records");
if (jsonIds.length === 0) fail("JSON audit contains no requirements");

for (const id of contractIds) if (!idPattern.test(id)) fail(`malformed contract ID ${id}`);
for (const row of contractRows) {
  if (row.length !== 7 || row.some((cell) => !cell)) fail(`${row[0]} has an incomplete contract row`);
  if (!new Set(["Yes", "No"]).has(row[4])) fail(`${row[0]} has invalid release-blocking value ${row[4]}`);
  if (!new Set(["Yes", "No"]).has(row[5])) fail(`${row[0]} has invalid owner-waiver value ${row[5]}`);
}
for (const row of auditRows) {
  if (row.length !== 7 || row.some((cell) => !cell)) fail(`${row[0]} has an incomplete Markdown audit row`);
}
requireUnique(contractIds, "Contract");
requireUnique(auditIds, "Markdown audit");
requireUnique(jsonIds, "JSON audit");
requireSameIds(contractIds, auditIds, "Markdown audit");
requireSameIds(contractIds, jsonIds, "JSON audit");
for (const id of contractIds) {
  const appearances = contract.match(new RegExp(`\\b${id}\\b`, "g"))?.length ?? 0;
  if (appearances !== 1) fail(`${id} must appear exactly once in the contract; found ${appearances}`);
}

const markdownById = new Map(auditRows.map(([id, status, priority]) => [
  id,
  { status, priority: priority === "—" ? null : priority },
]));
const contractWaivers = new Map(contractRows.map(([id, , , , , waiver]) => [id, waiver === "Yes"]));
const calculatedStatusCounts = Object.fromEntries([...allowedStatuses].map((status) => [status, 0]));
const calculatedPriorityCounts = Object.fromEntries([...allowedPriorities].map((priority) => [priority, 0]));

for (const requirement of snapshot.requirements) {
  if (!allowedStatuses.has(requirement.status)) fail(`${requirement.id} has invalid status ${requirement.status}`);
  if (!String(requirement.area).trim() || !String(requirement.summary).trim()) {
    fail(`${requirement.id} lacks area or summary`);
  }
  if (!Array.isArray(requirement.evidence) || requirement.evidence.length === 0) {
    fail(`${requirement.id} lacks evidence`);
  }
  if (!Array.isArray(requirement.closure_evidence) || requirement.closure_evidence.length === 0) {
    fail(`${requirement.id} lacks closure evidence`);
  }
  if (requirement.waiver_permitted !== contractWaivers.get(requirement.id)) {
    fail(`${requirement.id} contract/JSON waiver mismatch`);
  }
  const markdown = markdownById.get(requirement.id);
  if (markdown.status !== requirement.status || markdown.priority !== requirement.priority) {
    fail(`${requirement.id} Markdown/JSON status or priority mismatch`);
  }

  calculatedStatusCounts[requirement.status] += 1;
  if (requirement.status === "PASS" || requirement.status === "NOT_APPLICABLE") {
    if (requirement.priority !== null) fail(`${requirement.id} must use null priority`);
    if (requirement.status === "NOT_APPLICABLE" && !requirement.evidence.some((item) => /installed-only product decision/i.test(String(item)))) {
      fail(`${requirement.id} NOT_APPLICABLE lacks explicit installed-only product-decision evidence`);
    }
  } else {
    if (!allowedPriorities.has(requirement.priority)) fail(`${requirement.id} lacks a valid priority`);
    calculatedPriorityCounts[requirement.priority] += 1;
    if (!String(requirement.gap).trim()) fail(`${requirement.id} lacks a gap description`);
    if (!String(requirement.recommended_remediation).trim()) fail(`${requirement.id} lacks recommended remediation`);
  }
}

for (const prefix of ["VER", "SCAN", "FS", "DATA", "AGENT", "DESKTOP", "SEC", "REL", "DOC", "UX"]) {
  const count = contractIds.filter((id) => id.startsWith(`V1-${prefix}-`)).length;
  if (count === 0) fail(`contract contains no ${prefix} requirements`);
}

if (JSON.stringify(calculatedStatusCounts) !== JSON.stringify(snapshot.status_counts)) {
  fail("JSON status counts do not match requirements");
}
if (JSON.stringify(calculatedPriorityCounts) !== JSON.stringify(snapshot.priority_counts)) {
  fail("JSON priority counts do not match requirements");
}

for (const [label, count] of Object.entries(snapshot.status_counts)) {
  if (!audit.includes(`| ${label} | ${count} |`)) fail(`Markdown summary count is wrong for ${label}`);
}
for (const [label, count] of Object.entries(snapshot.priority_counts)) {
  if (!audit.includes(`| ${label} | ${count} |`)) fail(`Markdown priority count is wrong for ${label}`);
}

const verdictMatches = [...audit.matchAll(/\*\*Overall verdict: (READY|CONDITIONALLY READY|NOT READY|INSUFFICIENT EVIDENCE)\*\*/g)];
if (verdictMatches.length !== 1) fail(`expected exactly one Markdown overall verdict, found ${verdictMatches.length}`);
if (verdictMatches[0][1] !== snapshot.overall_verdict) fail("Markdown and JSON verdicts differ");
if (snapshot.overall_verdict !== "NOT READY") fail("current evidence requires NOT READY");
const expectedClassificationChanges = [
  ["V1-DATA-005", "PARTIAL", "PASS"],
  ["V1-DESKTOP-002", "PARTIAL", "PASS"],
  ["V1-DESKTOP-003", "PARTIAL", "PASS"],
  ["V1-DESKTOP-005", "PARTIAL", "PASS"],
  ["V1-SEC-006", "FAIL", "PASS"],
  ["V1-DOC-002", "PARTIAL", "PASS"],
  ["V1-DOC-003", "PARTIAL", "PASS"],
  ["V1-DOC-004", "UNKNOWN", "PARTIAL"],
  ["V1-DOC-006", "FAIL", "PASS"],
  ["V1-DESKTOP-006", "PARTIAL", "PASS"],
  ["V1-UX-001", "PARTIAL", "PASS"],
  ["V1-UX-004", "UNKNOWN", "PASS"],
  ["V1-UX-005", "PARTIAL", "PASS"],
  ["V1-REL-001", "PARTIAL", "PASS"],
  ["V1-FS-006", "PARTIAL", "PASS"],
  ["V1-DESKTOP-004", "PARTIAL", "PASS"],
];
const actualClassificationChanges = (snapshot.classification_changes ?? []).map(({ id, from, to }) => [id, from, to]);
if (JSON.stringify(actualClassificationChanges) !== JSON.stringify(expectedClassificationChanges)) {
  fail("readiness classification changes are missing or incorrect");
}

const versionMatches = [...audit.matchAll(/^- Audited product version: `([^`]+)`$/gm)];
if (versionMatches.length !== 1) fail(`expected one Markdown audited version, found ${versionMatches.length}`);
if (versionMatches[0][1] !== snapshot.audited_version) fail("Markdown and JSON audited versions differ");
if (snapshot.audited_version !== "0.9.11") fail(`expected audited version 0.9.11, found ${snapshot.audited_version}`);

const commitMatches = [...audit.matchAll(/^- Audited behavioral baseline commit: `([0-9a-f]{40})`$/gm)];
if (commitMatches.length !== 1) fail(`expected one Markdown audited commit, found ${commitMatches.length}`);
if (commitMatches[0][1] !== snapshot.audited_commit) fail("Markdown and JSON audited commits differ");

if (!contract.includes(installedOnlyDecision)) fail("readiness contract lacks the permanent installed-only product decision");
const sequenceHeadings = [...sequence.matchAll(/^## (G\d{3}) —/gm)].map((match) => match[1]);
if (JSON.stringify(sequenceHeadings) !== JSON.stringify(expectedSequenceHeadings)) {
  fail(`remediation heading sequence is ${sequenceHeadings.join(", ")}; expected ${expectedSequenceHeadings.join(", ")}`);
}

const sequenceIds = new Set(sequence.match(/V1-[A-Z]+-\d{3}/g) ?? []);
const uncoveredBlockers = snapshot.requirements
  .filter(({ priority }) => priority === "P0" || priority === "P1")
  .map(({ id }) => id)
  .filter((id) => !sequenceIds.has(id));
if (uncoveredBlockers.length) fail(`remediation sequence omits blockers: ${uncoveredBlockers.join(", ")}`);

console.log(
  `Validated ${contractIds.length} unique v1 contract requirements; Markdown/JSON verdict, statuses, priorities, counts, and P0/P1 sequence coverage agree.`,
);
