import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, afterEach, before, beforeEach, test } from "node:test";

import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { JSDOM } from "jsdom";
import { createServer } from "vite";
import { GUIDED_REVIEW_DISMISSALS_KEY } from "./guidedReview.js";
import { SESSION_STATE_KEY } from "./sessionState.js";

const PROJECT_A_PATH = "C:/workspace/project-a";
const PROJECT_B_PATH = "C:/workspace/project-b";
const PROJECT_A = project("Project A", PROJECT_A_PATH);
const PROJECT_B = project("Project B", PROJECT_B_PATH);
const GLOBAL_NAMES = [
  "window",
  "document",
  "navigator",
  "HTMLElement",
  "Node",
  "Event",
  "MouseEvent",
  "MutationObserver",
  "getComputedStyle",
  "requestAnimationFrame",
  "cancelAnimationFrame",
  "fetch",
  "IS_REACT_ACT_ENVIRONMENT",
];

let viteServer;
let App;
let dom;
let root;
let fetchHarness;
let originalGlobals;

before(async () => {
  viteServer = await createServer({
    root: process.cwd(),
    appType: "custom",
    logLevel: "silent",
    server: { middlewareMode: true },
  });
  ({ App } = await viteServer.ssrLoadModule("/src/main.jsx"));
});

after(async () => {
  await viteServer.close();
});

beforeEach(() => {
  dom = new JSDOM("<!doctype html><html><body><div id=\"root\"></div></body></html>", {
    pretendToBeVisual: true,
    url: "http://127.0.0.1:5173/",
  });
  originalGlobals = captureGlobals();
  installDomGlobals(dom.window);
  fetchHarness = createFetchHarness();
  globalThis.fetch = fetchHarness.fetch;
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  root = createRoot(document.getElementById("root"));
});

afterEach(async () => {
  try {
    if (fetchHarness) {
      await fetchHarness.settleAll();
    }
  } finally {
    try {
      if (root) {
        await act(async () => root.unmount());
      }
    } finally {
      dom?.window.close();
      restoreGlobals(originalGlobals);
      fetchHarness = null;
      root = null;
      dom = null;
    }
  }
});

test("restores a valid project, section, historical scan, and panel state once", async () => {
  storeSession({
    selectedProjectPath: PROJECT_B_PATH,
    activeSection: "reports",
    selectedScanId: 22,
    panels: { scanReport: false, history: true },
  });
  await renderApp();
  const restoredScan = { ...scan(22, "medium", "2026-07-11T09:30:00Z"), project_path: PROJECT_B_PATH };
  await resolveDetails(await takeDetailRequests(PROJECT_B_PATH), { scans: [restoredScan] });

  assert.match(selectedProjectText(), /Project B/);
  assert.equal(document.querySelector(".topbar h1").textContent, "Reports");
  assert.equal(document.querySelector("#reports").open, false);
  assert.ok(document.querySelector(".history-row.selected-history-row"));
  assert.equal(fetchHarness.count("/api/scans/history"), 1);
  assert.equal(fetchHarness.count("/api/notes"), 1);
});

test("missing and unavailable stored projects fall back through normal selection", async () => {
  storeSession({ selectedProjectPath: "C:/workspace/missing", activeSection: "reports" });
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH));
  assert.match(selectedProjectText(), /Project A/);
  assert.equal(document.querySelector(".topbar h1").textContent, "Workspace Overview");
});

test("an unavailable stored registration is not restored", async () => {
  storeSession({ selectedProjectPath: PROJECT_B_PATH, activeSection: "reports" });
  await renderApp([PROJECT_A, { ...PROJECT_B, available: false, availability: "missing" }]);
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH));
  assert.match(selectedProjectText(), /Project A/);
  assert.equal(fetchHarness.count("/api/scans/history"), 1);
});

test("workspace mismatch ignores all stored workspace state", async () => {
  storeSession({
    workspaceRoot: "D:/other",
    selectedProjectPath: PROJECT_B_PATH,
    activeSection: "reports",
    selectedScanId: 22,
    panels: { scanReport: false },
  });
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH));
  assert.match(selectedProjectText(), /Project A/);
  assert.equal(document.querySelector(".topbar h1").textContent, "Workspace Overview");
});

test("manual project selection wins while restored history is pending", async () => {
  storeSession({ selectedProjectPath: PROJECT_A_PATH, activeSection: "reports", selectedScanId: 31 });
  await renderApp();
  const restoredA = await takeDetailRequests(PROJECT_A_PATH);
  await resolveDetails(restoredA, { skip: ["scanHistory"] });

  await selectProject("Project B");
  await resolveDetails(await takeDetailRequests(PROJECT_B_PATH), {
    scans: [{ ...scan(31, "high", "2026-07-11T09:31:00Z"), project_path: PROJECT_B_PATH }],
  });
  await respond(restoredA.scanHistory, { scans: [scan(31, "low", "2026-07-11T09:30:00Z")] });

  assert.match(selectedProjectText(), /Project B/);
  assert.equal(document.querySelectorAll(".history-row.selected-history-row").length, 0);
});

test("a missing stored historical scan falls back to latest view", async () => {
  storeSession({ selectedProjectPath: PROJECT_A_PATH, activeSection: "reports", selectedScanId: 999 });
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), {
    scans: [scan(32, "low", "2026-07-11T09:32:00Z")],
  });
  assert.equal(document.querySelectorAll(".history-row.selected-history-row").length, 0);
  assert.equal(document.querySelector(".scan-summary .risk").textContent, "low");
});

test("reset clears only saved UI state and returns to defaults without reload", async () => {
  window.localStorage.setItem("unrelated", "keep");
  storeSession({
    selectedProjectPath: PROJECT_A_PATH,
    activeSection: "settings",
    selectedScanId: 44,
    panels: { scanReport: false, history: false, notes: false },
  });
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), {
    scans: [scan(44, "low", "2026-07-11T09:44:00Z")],
  });

  await click(buttonWithText("Reset saved UI state"));
  assert.equal(document.querySelector(".topbar h1").textContent, "Workspace Overview");
  assert.equal(window.localStorage.getItem(SESSION_STATE_KEY), null);
  assert.equal(window.localStorage.getItem("unrelated"), "keep");
  const detailsA = await takeDetailRequests(PROJECT_A_PATH);
  await resolveDetails(detailsA, { scans: [scan(44, "low", "2026-07-11T09:44:00Z")] });
  assert.match(selectedProjectText(), /Project A/);
  assert.match(messageText(), /Backend data and workspace configuration were not changed/);

  await openReports();
  assert.equal(document.querySelector("#reports").open, true);
  const historyPanel = [...document.querySelectorAll("details.section-toggle")]
    .find((panel) => panel.querySelector("h2")?.textContent === "Scan History");
  assert.equal(historyPanel.open, true);
  assert.equal(document.querySelectorAll(".history-row.selected-history-row").length, 0);
  assert.doesNotMatch(messageText(), /Saved UI state reset/);
  assert.equal(fetchHarness.count("/api/scans/history"), 2);
});

test("transient drafts and mutation state are never restored", async () => {
  storeSession({
    selectedProjectPath: PROJECT_A_PATH,
    activeSection: "settings",
    agentPreview: "sensitive preview",
    noteBody: "draft note",
    isScanning: true,
    error: "old failure",
  });
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH));

  assert.equal(document.querySelector('textarea[placeholder="Project purpose"]').value, "");
  assert.equal(document.querySelector('textarea[placeholder="Add a note"]').value, "");
  assert.doesNotMatch(document.body.textContent, /sensitive preview|draft note|old failure/);
  assert.equal(runScanButton().textContent, "Run Scan");
});

test("late project A details cannot overwrite selected project B", async () => {
  await renderApp();
  const firstA = await takeDetailRequests(PROJECT_A_PATH);
  await resolveDetails(firstA, { skip: ["notes"] });

  await selectProject("Project B");
  assert.equal(firstA.notes.signal.aborted, true);

  const detailsB = await takeDetailRequests(PROJECT_B_PATH);
  await resolveDetails(detailsB, {
    notes: [note(2, "Current B note")],
  });
  await openSettings();
  assert.match(document.body.textContent, /Current B note/);

  await respond(firstA.notes, { notes: [note(1, "Obsolete A note")] });
  assert.match(document.body.textContent, /Current B note/);
  assert.doesNotMatch(document.body.textContent, /Obsolete A note/);
  assert.match(selectedProjectText(), /Project B/);
});

test("A to B to A uses the fresh A detail response", async () => {
  await renderApp();
  const obsoleteA = await takeDetailRequests(PROJECT_A_PATH);
  await resolveDetails(obsoleteA, { skip: ["notes"] });

  await selectProject("Project B");
  await resolveDetails(await takeDetailRequests(PROJECT_B_PATH));
  await selectProject("Project A");

  const freshA = await takeDetailRequests(PROJECT_A_PATH);
  await resolveDetails(freshA, {
    notes: [note(3, "Fresh A note")],
  });
  await openSettings();
  assert.match(document.body.textContent, /Fresh A note/);

  await respond(obsoleteA.notes, { notes: [note(1, "Obsolete first A note")] });
  assert.equal(obsoleteA.notes.signal.aborted, true);
  assert.match(document.body.textContent, /Fresh A note/);
  assert.doesNotMatch(document.body.textContent, /Obsolete first A note/);
});

test("loading and errors stay scoped to the selected project during aborts", async () => {
  await renderApp();
  const detailsA = await takeDetailRequests(PROJECT_A_PATH);

  await selectProject("Project B");
  Object.values(detailsA).forEach((request) => assert.equal(request.signal.aborted, true));
  const detailsB = await takeDetailRequests(PROJECT_B_PATH);
  assert.match(document.body.textContent, /Loading project details/);

  await reject(detailsA.notes, new Error("Obsolete A detail failed"));
  assert.doesNotMatch(messageText(), /Obsolete A detail failed/);
  assert.match(document.body.textContent, /Loading project details/);

  await resolveDetails(detailsB, {
    reject: { notes: new Error("Current B detail failed") },
  });
  assert.doesNotMatch(document.body.textContent, /Loading project details/);
  assert.match(messageText(), /Current B detail failed/);
  assert.match(selectedProjectText(), /Project B/);
});

test("incomplete scan with no findings remains explicitly unverified", async () => {
  const completeness = {
    complete: false,
    traversalFailureCount: 1,
    fileInspectionFailureCount: 2,
    oversizedFileCount: 1,
    unsafePathCount: 0,
    policyExcludedFileCount: 1,
    resourceBudgetExceededCount: 1,
  };
  await renderApp([{
    ...PROJECT_A,
    last_risk_level: "none",
    last_scan_time: "2026-07-11T12:00:00Z",
    last_scan_completeness: withCompleteness({}, completeness).scanCompleteness,
    scan_state: "scanned",
  }, PROJECT_B]);
  const incomplete = withCompleteness(scan(7, "none", "2026-07-11T12:00:00Z"), completeness);
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [incomplete] });

  assert.match(document.body.textContent, /Incomplete scan/);
  assert.match(document.body.textContent, /No findings recorded; scan incomplete/);
  assert.doesNotMatch(document.body.textContent, /No findings detected/);
  assert.deepEqual(categoryStatuses().slice(0, 6), Array(6).fill("Not verified"));
  assert.equal(document.querySelectorAll(".findings-overview .status-clean").length, 0);
  assert.match(document.querySelector(".recent-activity").textContent, /Incomplete scan recorded/);
  assertProjectSummary(document.querySelector(".project-item"), "Findings: None recorded", "Coverage: Incomplete");
  await click(document.querySelector('a[href="#projects"]'));
  assertProjectSummary(document.querySelector(".projects-table-row"), "Findings: None recorded", "Coverage: Incomplete");
  await openReports();
  assert.equal(document.querySelector(".contextual-scan-button").textContent, "Run Current Scan");
  assertReportHeader("0 findings", "Incomplete coverage");
  assert.match(document.body.textContent, /Traversal failures: 1/);
  assert.match(document.body.textContent, /File inspection failures: 2/);
  assert.match(document.body.textContent, /Oversized files: 1/);
  assert.match(document.body.textContent, /Repository policy exclusions: 1/);
  assert.match(document.body.textContent, /Scanner resource budgets exceeded: 1/);
  assertHistorySummary("0 findings", "Coverage: Incomplete");
});

test("complete scan with no findings retains verified clean presentation", async () => {
  const clean = withCompleteness(scan(8, "none", "2026-07-11T12:01:00Z"), {
    complete: true,
    traversalFailureCount: 0,
    fileInspectionFailureCount: 0,
    oversizedFileCount: 0,
    unsafePathCount: 0,
  });
  await renderApp([{
    ...PROJECT_A,
    last_risk_level: "none",
    last_scan_time: clean.scan_date,
    last_scan_completeness: clean.scanCompleteness,
    scan_state: "scanned",
  }, PROJECT_B]);
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [clean] });

  assert.match(document.body.textContent, /Complete scan with no findings detected/);
  assert.deepEqual(categoryStatuses().slice(0, 6), Array(6).fill("Clean"));
  assert.deepEqual(categoryStatuses().slice(6), ["Count", "Count"]);
  assert.ok(document.querySelector(".overall-risk-panel .risk-ring-none"));
  const cleanRiskItems = [...document.querySelectorAll(".overall-risk-panel .risk-reasons li")];
  assert.ok(cleanRiskItems[0].classList.contains("risk-indicator-success"));
  assert.ok(cleanRiskItems.at(-1).classList.contains("risk-indicator-neutral"));
  assert.match(cleanRiskItems.at(-1).textContent, /Risk tolerance: normal/);
  assert.doesNotMatch(document.body.textContent, /coverage unknown/i);
  assert.match(document.querySelector(".recent-activity").textContent, /Scan completed/);
  assertProjectSummary(document.querySelector(".project-item"), "Findings: None recorded", "Coverage: Complete");
  await click(document.querySelector('a[href="#projects"]'));
  assertProjectSummary(document.querySelector(".projects-table-row"), "Findings: None recorded", "Coverage: Complete");
  await openReports();
  assert.equal(document.querySelector(".contextual-scan-button"), null);
  assertReportHeader("0 findings", "Complete coverage", { verified: true });
  assertHistorySummary("0 findings", "Coverage: Complete");
});

test("new project guidance leads to the first scan and dismissal changes only local UI state", async () => {
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [] });

  const checklist = document.querySelector(".guided-review");
  assert.ok(checklist, "Expected the guided review checklist");
  assert.match(checklist.textContent, /1 of 5 steps complete/);
  assert.match(checklist.textContent, /Project registered/);
  assert.match(checklist.textContent, /Run first scan/);
  assert.ok(document.querySelector(".first-scan-prompt"));
  assert.match(document.querySelector(".first-scan-prompt").textContent, /Run this project’s first scan/);

  const scanPostsBefore = fetchHarness.count("/api/scans", "POST");
  const reviewPutsBefore = fetchHarness.count("/api/finding-reviews", "PUT");
  await click([...checklist.querySelectorAll("button")].find((button) => button.textContent === "Dismiss"));

  assert.equal(document.querySelector(".guided-review"), null);
  assert.ok(document.querySelector(".first-scan-prompt"));
  assert.equal(fetchHarness.count("/api/scans", "POST"), scanPostsBefore);
  assert.equal(fetchHarness.count("/api/finding-reviews", "PUT"), reviewPutsBefore);
  assert.deepEqual(JSON.parse(window.localStorage.getItem(GUIDED_REVIEW_DISMISSALS_KEY)), [PROJECT_A_PATH]);
});

test("Reports completion summary keeps unresolved findings and the workbench primary", async () => {
  const current = {
    ...scanWithFindings(86, [reviewableFinding("6")]),
    dependencyTrust: emptyDependencyTrustFixture(),
  };
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [current] });
  await openReports();

  const summary = document.querySelector(".review-completion");
  const workbench = document.querySelector(".finding-workbench");
  assert.match(summary.textContent, /Finding review in progress/);
  assert.match(summary.textContent, /1 of 1 finding remains unresolved/);
  assert.match(workbench.querySelector("h3").textContent, /Finding review workbench/);
  assert.ok(summary.compareDocumentPosition(workbench) & Node.DOCUMENT_POSITION_FOLLOWING);
  assert.equal(document.querySelector(".category-detail-views").open, false);
});

test("reviewed findings do not conceal incomplete coverage or immutable scanner context", async () => {
  const reviewed = reviewableFinding("7", { review: findingReview(`cf1_${"7".repeat(64)}`) });
  const current = {
    ...withCompleteness(scanWithFindings(87, [reviewed]), {
      complete: false,
      fileInspectionFailureCount: 1,
    }),
    dependencyTrust: emptyDependencyTrustFixture(),
  };
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [current] });
  await openReports();

  const summary = document.querySelector(".review-completion");
  assert.match(summary.textContent, /Finding review complete; coverage remains unresolved/);
  assert.match(summary.textContent, /1 scan-coverage gap remains/);
  assert.doesNotMatch(summary.textContent, /^Review complete for this scan$/);
  assert.equal(document.querySelector(".report-supporting-details").open, false);
  assert.match(document.querySelector(".report-supporting-details").textContent, /Scanner context and raw metrics/);
});

test("applicable dependency state stays actionable until the approved snapshot matches", async () => {
  const needsApproval = trustedBaselineScan(110, trustedBaselineFixture({
    approval: { eligible: true, fingerprint: `cfdb2_${"d".repeat(64)}`, reason: "" },
  }));
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [needsApproval] });
  await openReports();

  assert.match(document.querySelector(".review-completion").textContent, /Finding review complete; dependency review remains/);
  assert.match(document.querySelector(".review-completion").textContent, /Approval required/);
  assert.ok(document.querySelector(".dependency-trust.dependency-review-attention"));
  assert.match(document.querySelector(".dependency-trust.dependency-review-attention").textContent, /Trust this dependency snapshot/);
});

test("genuinely complete current and historical reviews remain explicit and conservative", async () => {
  const current = trustedBaselineScan(111, configuredTrustedBaseline("identical"));
  const historical = {
    ...withCompleteness(scan(109, "none", "2026-07-10T11:00:00Z"), { complete: false, traversalFailureCount: 1 }),
    dependencyTrust: undefined,
  };
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [current, historical] });
  await openReports();

  let summary = document.querySelector(".review-completion");
  assert.match(summary.querySelector("h3").textContent, /^Review complete for this scan$/);
  assert.match(summary.textContent, /Available workflow complete/);
  assert.match(summary.textContent, /Approved snapshot/);
  assert.match(summary.textContent, /does not prove that the project is safe, secure, or fully verified/);

  const historicalRow = [...document.querySelectorAll(".history-row")]
    .find((row) => row.textContent.includes("Jul 10"));
  assert.ok(historicalRow, "Expected the Jul 10 historical scan");
  await click(historicalRow.querySelector(".history-view-button"));
  summary = document.querySelector(".review-completion");
  assert.match(summary.textContent, /Historical scan review/);
  assert.doesNotMatch(summary.querySelector("h3").textContent, /^Review complete for this scan$/);
  assert.match(summary.textContent, /coverage remains unresolved/i);
  assert.match(summary.textContent, /Dependency state unavailable/);
});

test("unresolved high contributors and risk tolerance never use success indicators", async () => {
  const highFinding = {
    type: "suspicious-text-pattern",
    severity: "high",
    path: "src/runtime.js",
    pattern: "eval(",
    explanation: "A suspicious text pattern was recorded.",
    action: "Review the call before running this code.",
  };
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), {
    scans: [scanWithFindings(10, [highFinding])],
  });

  const riskItems = [...document.querySelectorAll(".overall-risk-panel .risk-reasons li")];
  const contributor = riskItems.find((item) => item.textContent.includes("Main contributors"));
  const tolerance = riskItems.find((item) => item.textContent.includes("Risk tolerance"));
  assert.ok(contributor, "Expected an unresolved contributor summary");
  assert.ok(contributor.classList.contains("risk-indicator-high"));
  assert.equal(contributor.querySelector(".risk-indicator-symbol").textContent, "!");
  assert.equal(contributor.classList.contains("risk-indicator-success"), false);
  assert.ok(tolerance.classList.contains("risk-indicator-neutral"));
  assert.equal(tolerance.querySelector(".risk-indicator-symbol").textContent, "•");
  assert.equal(tolerance.classList.contains("risk-indicator-success"), false);
});

test("legacy scan with unknown coverage never presents verified clean", async () => {
  const legacy = scan(9, "none", "2026-07-11T12:02:00Z");
  await renderApp([{
    ...PROJECT_A,
    last_risk_level: "none",
    last_scan_time: legacy.scan_date,
    last_scan_completeness: null,
    scan_state: "scanned",
  }, PROJECT_B]);
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [legacy] });

  assert.match(document.body.textContent, /Coverage unknown/);
  assert.match(document.body.textContent, /No findings recorded; coverage unknown/);
  assert.match(document.body.textContent, /Run a new scan to verify current coverage/);
  assert.doesNotMatch(document.body.textContent, /No findings detected/);
  assert.doesNotMatch(document.body.textContent, /Complete scan/);
  assert.deepEqual(categoryStatuses().slice(0, 6), Array(6).fill("Unknown"));
  assert.deepEqual(categoryStatuses().slice(6), ["Count", "Count"]);
  assert.equal(document.querySelectorAll(".findings-overview .status-clean").length, 0);
  assert.ok(document.querySelector(".overall-risk-panel.coverage-unknown .risk-ring-unknown"));
  assert.match(document.querySelector(".recent-activity").textContent, /Legacy scan recorded/);
  assert.doesNotMatch(document.querySelector(".recent-activity").textContent, /Scan completed/);
  assertProjectSummary(document.querySelector(".project-item"), "Findings: None recorded", "Coverage: Unknown");

  await click(document.querySelector('a[href="#projects"]'));
  assertProjectSummary(document.querySelector(".projects-table-row"), "Findings: None recorded", "Coverage: Unknown");
  await openReports();
  assert.equal(document.querySelector(".contextual-scan-button").textContent, "Run Current Scan");
  assertReportHeader("0 findings", "Coverage unknown");
  assertHistorySummary("0 findings", "Coverage: Unknown");
});

test("unknown coverage comparison labels recorded risk and unavailable coverage", async () => {
  const legacy = scan(19, "none", "2026-07-11T12:12:00Z");
  const complete = withCompleteness(scan(18, "none", "2026-07-11T12:11:00Z"), { complete: true });
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [legacy, complete] });
  await openReports();

  const comparison = document.querySelector(".scan-comparison");
  assert.match(comparison.textContent, /Recorded risk unchanged; coverage comparison unavailable/);
  assert.match(comparison.textContent, /Unavailable because at least one scan lacks coverage metadata/);
});

test("contextual and primary scan controls share one guarded request and synchronized state", async () => {
  const legacy = scan(20, "none", "2026-07-11T12:20:00Z");
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [legacy] });
  await openReports();

  const historyButton = document.querySelector(".history-row .history-view-button");
  await click(historyButton);
  assert.match(document.querySelector(".scan-completeness-action").textContent, /new current scan and does not modify the historical scan/);

  const contextual = document.querySelector(".contextual-scan-button");
  await click(contextual);
  await click(contextual);
  assert.equal(fetchHarness.count("/api/scans", "POST"), 1);
  assert.equal(runScanButton().disabled, true);
  assert.equal(runScanButton().textContent, "Scanning...");
  assert.equal(contextual.disabled, true);
  assert.equal(contextual.textContent, "Scanning...");

  const request = await fetchHarness.next("/api/scans", { method: "POST" });
  const complete = withCompleteness(scan(21, "none", "2026-07-11T12:21:00Z"), { complete: true });
  await finishScan(request, complete, [complete, legacy]);
  assert.equal(runScanButton().disabled, false);
  assert.equal(document.querySelector(".contextual-scan-button"), null);
});

test("scan and copy success notices expire and are never persisted", async () => {
  await renderReadyProjectA();
  const originalSetTimeout = globalThis.setTimeout;
  const originalClearTimeout = globalThis.clearTimeout;
  const noticeTimers = [];
  globalThis.setTimeout = (callback, delay, ...args) => {
    if (delay === 4000) {
      const token = { callback, args, cleared: false };
      noticeTimers.push(token);
      return token;
    }
    return originalSetTimeout(callback, delay, ...args);
  };
  globalThis.clearTimeout = (token) => {
    if (noticeTimers.includes(token)) token.cleared = true;
    else originalClearTimeout(token);
  };
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: async () => undefined },
  });

  try {
    await click(runScanButton());
    const request = await fetchHarness.next("/api/scans", { method: "POST" });
    const complete = withCompleteness(scan(22, "none", "2026-07-11T12:22:00Z"), { complete: true });
    await finishScan(request, complete, [complete]);
    await click(buttonWithText("Copy Markdown"));
    const toastStack = document.querySelector(".notice-stack");
    assert.equal(toastStack.parentElement.classList.contains("workspace"), true);
    assert.equal(toastStack.closest(".topbar"), null);
    assert.equal(toastStack.querySelectorAll(".notice").length, 2);
    assert.match(toastStack.textContent, /Scan complete/);
    assert.match(toastStack.textContent, /Report Markdown copied/);
    assert.doesNotMatch(window.localStorage.getItem(SESSION_STATE_KEY) || "", /Scan complete|Report Markdown copied/);

    const activeTimers = noticeTimers.filter((timer) => !timer.cleared);
    assert.equal(activeTimers.length, 2);
    await act(async () => {
      activeTimers[0].callback(...activeTimers[0].args);
      await flushMicrotasks();
    });
    assert.equal(toastStack.querySelectorAll(".notice").length, 1);
    assert.match(toastStack.textContent, /Scan complete|Report Markdown copied/);
    await act(async () => {
      activeTimers[1].callback(...activeTimers[1].args);
      await flushMicrotasks();
    });
    assert.equal(toastStack.querySelectorAll(".notice").length, 0);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    globalThis.clearTimeout = originalClearTimeout;
  }
});

test("root layout reserves stable vertical scrollbar space", () => {
  const styles = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
  assert.match(styles, /html\s*\{[^}]*overflow-y:\s*scroll;[^}]*scrollbar-gutter:\s*stable;/s);
  assert.doesNotMatch(styles.match(/html\s*\{[^}]*\}/s)?.[0] || "", /overflow-x/);
  const toastRule = styles.match(/\.notice-stack\s*\{[^}]*\}/s)?.[0] || "";
  assert.match(toastRule, /position:\s*fixed/);
  assert.match(toastRule, /top:\s*var\(--toast-top, 112px\)/);
  assert.match(toastRule, /width:\s*min\(28rem, calc\(100vw - 376px\)\)/);
  assert.match(styles, /@media \(max-width: 620px\)[\s\S]*?\.notice-stack\s*\{[^}]*left:\s*14px;[^}]*right:\s*14px;[^}]*width:\s*auto;/);
});

test("selected and unselected history rows retain readable narrow-layout structure", async () => {
  Object.defineProperty(window, "innerWidth", { configurable: true, value: 680 });
  const current = withCompleteness({
    ...scan(89, "high", "2026-07-11T13:59:00Z"),
    findingCount: 2,
    findingSummary: { lockfile: 1, "suspicious-text-pattern": 1 },
  }, { complete: true });
  const previous = withCompleteness({
    ...scan(88, "low", "2026-07-10T13:59:00Z"),
    findingCount: 1,
    findingSummary: { "dependency-analysis-incomplete": 1 },
  }, { complete: false, dependencyAnalysisFailureCount: 1 });
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [current, previous] });
  await openReports();

  const rows = [...document.querySelectorAll(".history-row")];
  assert.equal(rows.length, 2);
  assert.equal(rows.some((row) => row.classList.contains("selected-history-row")), false);
  await click(rows[0].querySelector(".history-view-button"));
  assert.ok(rows[0].classList.contains("selected-history-row"));
  assert.equal(rows[1].classList.contains("selected-history-row"), false);
  assert.equal(rows[0].querySelector(".history-view-button").textContent, "Viewing");
  assert.equal(rows[1].querySelector(".history-view-button").textContent, "View");
  assert.match(rows[0].querySelector(".history-primary").textContent, /suspicious-text-pattern: 1/);
  assert.match(rows[0].querySelector(".history-counts").textContent, /Coverage: Complete/);

  const styles = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
  assert.doesNotMatch(styles, /\.selected-history-row\s*\{[^}]*background:\s*#f7f9fa/);
  assert.match(styles, /\.selected-history-row\s*\{[^}]*background:\s*var\(--color-surface-selected\);[^}]*border:\s*1px solid var\(--color-border\);[^}]*border-left:\s*3px solid var\(--color-accent\)/s);
  assert.match(styles, /\.history-row\s*\{[^}]*grid-template-columns:\s*minmax\(190px, 1fr\) max-content minmax\(260px, 1fr\) max-content;/s);
  assert.match(styles, /\.history-row\s*>\s*div:first-child span\s*\{[^}]*overflow-wrap:\s*break-word;[^}]*word-break:\s*normal;/s);
  assert.doesNotMatch(styles, /\.history-row\s*>\s*div:first-child span\s*\{[^}]*overflow-wrap:\s*anywhere;/s);
  assert.match(styles, /@media \(max-width: 1180px\)[\s\S]*?\.history-row\s*\{[^}]*grid-template-columns:\s*minmax\(0, 1fr\) max-content;[\s\S]*?\.history-primary\s*\{[^}]*grid-column:\s*1 \/ -1;[\s\S]*?\.history-counts\s*\{[^}]*grid-column:\s*1 \/ -1;/);
});

test("dependency status badges stay compact with a narrow-screen wrap fallback", () => {
  const styles = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
  const badgeRule = styles.match(/\.dependency-status\s*\{[^}]*\}/s)?.[0] || "";
  assert.match(badgeRule, /display:\s*inline-flex/);
  assert.match(badgeRule, /max-width:\s*100%/);
  assert.match(badgeRule, /white-space:\s*nowrap/);
  assert.match(styles, /@media \(max-width: 360px\)[\s\S]*?\.dependency-status\s*\{[^}]*overflow-wrap:\s*anywhere;[^}]*white-space:\s*normal;/);
});

test("complete Node and Python dependency analysis renders compact offline trust evidence", async () => {
  await renderApp();
  const result = {
    ...withCompleteness(scan(90, "low", "2026-07-11T14:00:00Z"), {
      complete: true,
      traversalFailureCount: 0,
      fileInspectionFailureCount: 0,
      oversizedFileCount: 0,
      unsafePathCount: 0,
      dependencyAnalysisFailureCount: 0,
    }),
    dependencyTrust: dependencyTrustFixture(),
  };
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), {
    scans: [result],
    trustProfile: { project_path: PROJECT_A_PATH, trustedPackageManagers: ["npm"] },
  });
  await openReports();

  const panel = document.querySelector(".dependency-trust");
  assert.match(panel.textContent, /Checks complete/);
  assert.match(panel.textContent, /Node and Python|node, python/i);
  assert.match(panel.textContent, /alpha/);
  assert.match(panel.textContent, /requests/);
  assert.match(panel.textContent, /npm \(expected\)/);
  assert.match(panel.textContent, /Offline-only/);
  assert.ok(panel.querySelectorAll(".dependency-entry").length <= 50);
});

test("complete empty project shows dependency trust without claiming a clean graph", async () => {
  const empty = {
    ...withCompleteness(scan(95, "none", "2026-07-11T14:05:00Z"), { complete: true }),
    dependencyTrust: emptyDependencyTrustFixture({
      trustedBaseline: trustedBaselineFixture({
        approval: { eligible: false, fingerprint: "", reason: "No supported dependency metadata was analyzed in this scan." },
      }),
    }),
  };
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [empty] });

  const overview = document.querySelector(".dependency-trust-overview");
  assert.ok(overview, "Expected Dependency Trust in the selected scan overview");
  assert.match(overview.textContent, /No metadata detected/);
  assert.match(overview.textContent, /No supported Node or Python dependency graph was analyzed/);
  assert.match(overview.textContent, /Approval unavailable:.*No supported dependency metadata/i);
  assert.doesNotMatch(overview.textContent, /Trust this snapshot/);
  assert.doesNotMatch(overview.textContent, /clean|verified|Integrity|Consistency issues/i);

  await openReports();
  const detailed = document.querySelector(".dependency-trust");
  assert.match(detailed.textContent, /No metadata detected/);
  assert.match(detailed.textContent, /no dependency graph/i);
  assert.equal(detailed.querySelector(".dependency-metrics"), null);
});

test("unsupported dependency metadata remains distinct from an empty modern scan", async () => {
  const unsupported = {
    ...withCompleteness(scan(96, "medium", "2026-07-11T14:06:00Z"), { complete: false, dependencyAnalysisFailureCount: 1 }),
    dependencyTrust: emptyDependencyTrustFixture({
      status: "unsupported",
      manifests: ["dependencies.custom"],
      limitations: [{ reason: "unsupported-format", explanation: "The detected dependency format is not supported.", path: "dependencies.custom" }],
    }),
  };
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [unsupported] });

  const overview = document.querySelector(".dependency-trust-overview");
  assert.match(overview.textContent, /Unsupported metadata/);
  assert.match(overview.textContent, /format is not supported/);
  assert.doesNotMatch(overview.textContent, /No metadata detected/);
});

test("historical modern scan with no dependency metadata keeps the explicit empty state", async () => {
  const current = {
    ...withCompleteness(scan(98, "low", "2026-07-11T14:08:00Z"), { complete: true }),
    dependencyTrust: dependencyTrustFixture(),
  };
  const historicalEmpty = {
    ...withCompleteness(scan(97, "none", "2026-07-11T14:07:00Z"), { complete: true }),
    dependencyTrust: emptyDependencyTrustFixture(),
  };
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [current, historicalEmpty] });
  await openReports();
  const historyRows = [...document.querySelectorAll(".history-row")];
  await click(historyRows[1].querySelector(".history-view-button"));

  const panel = document.querySelector(".dependency-trust");
  assert.match(panel.textContent, /No metadata detected/);
  assert.match(panel.textContent, /No supported Node or Python dependency graph was analyzed/);
  assert.match(document.querySelector(".scan-view-label").textContent, /Viewing history scan/);
});

test("dependency analysis distinguishes incomplete and legacy history states", async () => {
  await renderApp();
  const incomplete = {
    ...scan(91, "medium", "2026-07-11T14:01:00Z"),
    dependencyTrust: dependencyTrustFixture({
      status: "incomplete",
      limitations: [{ reason: "dependency-metadata-size-limit", explanation: "Lockfile exceeded the analysis limit.", path: "package-lock.json" }],
    }),
    findings: [{ type: "dependency-analysis-incomplete", severity: "medium", path: "package-lock.json", explanation: "Dependency analysis is incomplete.", action: "Review manually." }],
    findingCount: 1,
  };
  const legacy = { ...scan(92, "none", "2026-07-11T13:59:00Z"), dependencyTrust: undefined };
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [incomplete, legacy] });
  await openReports();
  assert.match(document.querySelector(".dependency-trust").textContent, /Incomplete/);
  assert.match(document.querySelector(".dependency-trust").textContent, /Lockfile exceeded/);
  const historyRows = [...document.querySelectorAll(".history-row")];
  assert.equal(historyRows.length, 2);
  await click(historyRows[1].querySelector(".history-view-button"));
  assert.match(document.querySelector(".dependency-trust").textContent, /Analysis unavailable/);
  assert.doesNotMatch(document.querySelector(".dependency-trust").textContent, /no dependency issues/i);
});

test("late dependency history cannot cross project selection", async () => {
  await renderApp();
  const detailsA = await takeDetailRequests(PROJECT_A_PATH);
  await resolveDetails(detailsA, { skip: ["scanHistory"] });
  await selectProject("Project B");
  const detailsB = await takeDetailRequests(PROJECT_B_PATH);
  await resolveDetails(detailsB, {
    scans: [{ ...scan(93, "low", "2026-07-11T14:02:00Z"), project_path: PROJECT_B_PATH, dependencyTrust: dependencyTrustFixture({ entries: [{ ecosystem: "node", name: "current-b", group: "dependencies", sourceType: "registry", direct: true }] }) }],
  });
  await openReports();
  assert.match(document.querySelector(".dependency-trust").textContent, /current-b/);

  await respond(detailsA.scanHistory, { scans: [{ ...scan(94, "high", "2026-07-11T14:03:00Z"), dependencyTrust: dependencyTrustFixture({ entries: [{ ecosystem: "node", name: "obsolete-a", group: "dependencies", sourceType: "registry", direct: true }] }) }] });
  assert.match(document.querySelector(".dependency-trust").textContent, /current-b/);
  assert.doesNotMatch(document.querySelector(".dependency-trust").textContent, /obsolete-a/);
});

test("Workspace Overview approves one eligible snapshot and stays synchronized with Reports", async () => {
  const fingerprint = `cfdb2_${"7".repeat(64)}`;
  const current = trustedBaselineScan(109, trustedBaselineFixture({
    approval: { eligible: true, fingerprint, reason: "" },
  }));
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [current] });

  const overviewBaseline = document.querySelector(".dependency-trust-overview .trusted-baseline");
  assert.match(overviewBaseline.textContent, /Not configured/);
  assert.match(overviewBaseline.textContent, /Approve this dependency snapshot to detect future drift/);
  assert.equal((overviewBaseline.textContent.match(/Not configured/g) || []).length, 1);
  const trustButton = [...overviewBaseline.querySelectorAll("button")]
    .find((button) => button.textContent === "Trust this snapshot");
  assert.ok(trustButton, "Expected the eligible Overview trust action");

  await click(trustButton);
  await click(trustButton);
  assert.equal(fetchHarness.count("/api/trusted-dependency-baseline", "PUT"), 1);
  const approval = await fetchHarness.next("/api/trusted-dependency-baseline", { method: "PUT", projectPath: PROJECT_A_PATH });
  assert.deepEqual(approval.body, {
    project_path: PROJECT_A_PATH,
    scan_id: 109,
    fingerprint,
    note: "",
    replace: false,
  });
  await respond(approval, { configured: true });
  await respond(await fetchHarness.next("/api/scans/history", { projectPath: PROJECT_A_PATH }), {
    scans: [trustedBaselineScan(109, configuredTrustedBaseline("identical", { fingerprint }))],
  });

  const configuredOverview = document.querySelector(".dependency-trust-overview .trusted-baseline");
  assert.match(configuredOverview.textContent, /Matches approved baseline/);
  assert.doesNotMatch(configuredOverview.textContent, /Trust this snapshot/);
  await click(buttonWithText("Manage baseline"));
  assert.equal(document.querySelector(".topbar h1").textContent, "Reports");
  assert.equal(document.querySelector("#reports").open, true);
  assert.match(document.querySelector("#reports .trusted-baseline").textContent, /Matches approved baseline/);
  assert.ok(buttonWithText("Replace trusted baseline"));
});

test("an obsolete Overview baseline failure cannot replace the newly selected project state", async () => {
  const eligibleA = trustedBaselineScan(108, trustedBaselineFixture({
    approval: { eligible: true, fingerprint: `cfdb2_${"6".repeat(64)}`, reason: "" },
  }));
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [eligibleA] });
  await click(buttonWithText("Trust this snapshot"));
  const obsolete = await fetchHarness.next("/api/trusted-dependency-baseline", { method: "PUT", projectPath: PROJECT_A_PATH });

  await selectProject("Project B");
  assert.equal(obsolete.signal.aborted, true);
  const configuredB = {
    ...trustedBaselineScan(107, configuredTrustedBaseline("identical")),
    project_path: PROJECT_B_PATH,
  };
  await resolveDetails(await takeDetailRequests(PROJECT_B_PATH), { scans: [configuredB] });
  await respond(obsolete, { detail: "Obsolete approval failure." }, 409);

  const overviewBaseline = document.querySelector(".dependency-trust-overview .trusted-baseline");
  assert.match(selectedProjectText(), /Project B/);
  assert.match(overviewBaseline.textContent, /Matches approved baseline/);
  assert.doesNotMatch(overviewBaseline.textContent, /Obsolete approval failure|Not configured/);
});

test("eligible dependency snapshot approval uses the real handler and refreshes active history", async () => {
  const current = trustedBaselineScan(110, trustedBaselineFixture({
    approval: { eligible: true, fingerprint: `cfdb2_${"a".repeat(64)}`, reason: "" },
  }));
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [current] });
  await openReports();

  const reportPanel = document.querySelector("#reports .trusted-baseline");
  assert.match(reportPanel.textContent, /Not configured/);
  assert.match(reportPanel.textContent, /Approve this dependency snapshot to detect future drift/);
  const approvalNote = reportPanel.querySelector("textarea");
  await input(approvalNote, "Approved after local review.");
  assert.equal(approvalNote.value, "Approved after local review.");
  assert.doesNotMatch(JSON.stringify(parseStoredSession()), /Approved after local review/);
  await click(buttonWithText("Trust this dependency snapshot"));

  const approvalRequest = await fetchHarness.next("/api/trusted-dependency-baseline", { method: "PUT", projectPath: PROJECT_A_PATH });
  assert.deepEqual(approvalRequest.body, {
    project_path: PROJECT_A_PATH,
    scan_id: 110,
    fingerprint: `cfdb2_${"a".repeat(64)}`,
    note: "Approved after local review.",
    replace: false,
  });
  assert.equal(Object.hasOwn(approvalRequest.body, "snapshot"), false);
  await respond(approvalRequest, { configured: true });
  const refreshedHistory = await fetchHarness.next("/api/scans/history", { projectPath: PROJECT_A_PATH });
  await respond(refreshedHistory, { scans: [trustedBaselineScan(110, configuredTrustedBaseline("identical", {
    note: "Approved after local review.",
  }))] });

  assert.match(document.querySelector("#reports .trusted-baseline").textContent, /Matches approved baseline/);
  assert.match(document.querySelector("#reports .trusted-baseline").textContent, /Approved after local review/);
  assert.match(document.querySelector("#reports .trusted-baseline-actions").textContent, /baseline replaced|snapshot approved/i);
});

test("legacy empty and incomplete dependency analyses cannot expose a trust action", async () => {
  const incomplete = trustedBaselineScan(113, trustedBaselineFixture({
    approval: { eligible: false, fingerprint: "", reason: "Dependency analysis is incomplete and cannot be approved as a trusted baseline." },
  }), { status: "incomplete" });
  const empty = {
    ...withCompleteness(scan(112, "none", "2026-07-11T14:12:00Z"), { complete: true }),
    dependencyTrust: emptyDependencyTrustFixture({
      trustedBaseline: trustedBaselineFixture({
        approval: { eligible: false, fingerprint: "", reason: "No supported dependency metadata was analyzed in this scan." },
      }),
    }),
  };
  const legacy = {
    ...scan(111, "none", "2026-07-11T14:11:00Z"),
    trustedDependencyBaseline: trustedBaselineFixture({
      approval: { eligible: false, fingerprint: "", reason: "This scan predates dependency analysis." },
    }),
  };
  const incompatible = trustedBaselineScan(110, trustedBaselineFixture({
    approval: { eligible: false, fingerprint: "", reason: "The dependency snapshot schema is incompatible." },
  }));
  const historicalEligible = trustedBaselineScan(109, trustedBaselineFixture({
    approval: { eligible: true, fingerprint: `cfdb2_${"8".repeat(64)}`, reason: "" },
  }));
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [incomplete, empty, legacy, incompatible, historicalEligible] });

  let overviewPanel = document.querySelector(".dependency-trust-overview .trusted-baseline");
  assert.match(overviewPanel.textContent, /Approval unavailable:.*analysis is incomplete/i);
  assert.doesNotMatch(overviewPanel.textContent, /Trust this snapshot/);
  await openReports();

  let reportPanel = document.querySelector("#reports .trusted-baseline");
  assert.match(reportPanel.textContent, /analysis is incomplete/i);
  assert.doesNotMatch(reportPanel.textContent, /Trust this dependency snapshot/);

  const historyRows = [...document.querySelectorAll(".history-row")];
  await click(historyRows[1].querySelector(".history-view-button"));
  reportPanel = document.querySelector("#reports .trusted-baseline");
  assert.match(reportPanel.textContent, /No supported dependency metadata/);
  assert.doesNotMatch(reportPanel.textContent, /Trust this dependency snapshot/);

  await click(historyRows[2].querySelector(".history-view-button"));
  reportPanel = document.querySelector("#reports .trusted-baseline");
  assert.match(reportPanel.textContent, /predates dependency analysis/);
  assert.doesNotMatch(reportPanel.textContent, /Trust this dependency snapshot/);

  await click(historyRows[3].querySelector(".history-view-button"));
  reportPanel = document.querySelector("#reports .trusted-baseline");
  assert.match(reportPanel.textContent, /Historical scans cannot replace the active baseline/);
  assert.doesNotMatch(reportPanel.textContent, /Trust this dependency snapshot/);

  await click(historyRows[4].querySelector(".history-view-button"));
  reportPanel = document.querySelector("#reports .trusted-baseline");
  assert.match(reportPanel.textContent, /Historical scans cannot replace the active baseline/);
  assert.doesNotMatch(reportPanel.textContent, /Trust this dependency snapshot/);
});

test("an incompatible current dependency snapshot explains why approval is unavailable", async () => {
  const incompatible = trustedBaselineScan(117, trustedBaselineFixture({
    approval: { eligible: false, fingerprint: "", reason: "The dependency snapshot schema is incompatible." },
  }));
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [incompatible] });

  const overviewPanel = document.querySelector(".dependency-trust-overview .trusted-baseline");
  assert.match(overviewPanel.textContent, /Approval unavailable:.*schema is incompatible/i);
  assert.doesNotMatch(overviewPanel.textContent, /Trust this snapshot/);
  await openReports();
  assert.match(document.querySelector("#reports .trusted-baseline").textContent, /schema is incompatible/i);
  assert.doesNotMatch(document.querySelector("#reports .trusted-baseline").textContent, /Trust this dependency snapshot/);
});

test("trusted baseline replacement and clearing require confirmation and refresh history", async () => {
  let current = trustedBaselineScan(114, configuredTrustedBaseline("drift"));
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [current] });
  await openReports();

  let confirmed = false;
  window.confirm = () => confirmed;
  await click(buttonWithText("Replace trusted baseline"));
  assert.equal(fetchHarness.count("/api/trusted-dependency-baseline", "PUT"), 0);

  confirmed = true;
  await click(buttonWithText("Replace trusted baseline"));
  const replaceRequest = await fetchHarness.next("/api/trusted-dependency-baseline", { method: "PUT" });
  assert.equal(replaceRequest.body.replace, true);
  assert.equal(Object.hasOwn(replaceRequest.body, "snapshot"), false);
  await respond(replaceRequest, { configured: true });
  current = trustedBaselineScan(114, configuredTrustedBaseline("identical", { fingerprint: `cfdb2_${"c".repeat(64)}` }));
  await respond(await fetchHarness.next("/api/scans/history", { projectPath: PROJECT_A_PATH }), { scans: [current] });

  confirmed = false;
  await click(buttonWithText("Clear trusted baseline"));
  assert.equal(fetchHarness.count("/api/trusted-dependency-baseline", "DELETE"), 0);
  confirmed = true;
  await click(buttonWithText("Clear trusted baseline"));
  const clearRequest = await fetchHarness.next("/api/trusted-dependency-baseline", { method: "DELETE" });
  assert.deepEqual(clearRequest.body, { project_path: PROJECT_A_PATH });
  await respond(clearRequest, { configured: false, cleared: true });
  await respond(await fetchHarness.next("/api/scans/history", { projectPath: PROJECT_A_PATH }), {
    scans: [trustedBaselineScan(114, trustedBaselineFixture({
      approval: { eligible: true, fingerprint: `cfdb2_${"c".repeat(64)}`, reason: "" },
    }))],
  });
  assert.match(document.querySelector("#reports .trusted-baseline").textContent, /Not configured/);
});

test("trusted baseline note editing preserves snapshot identity and uses the scoped mutation handler", async () => {
  const fingerprint = `cfdb2_${"9".repeat(64)}`;
  const current = trustedBaselineScan(123, configuredTrustedBaseline("identical", { fingerprint }));
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [current] });
  await openReports();

  await click(buttonWithText("Edit note"));
  const noteField = document.querySelector("#reports .trusted-baseline-note-form textarea");
  await input(noteField, "Updated project-scoped approval note.");
  assert.doesNotMatch(JSON.stringify(parseStoredSession()), /Updated project-scoped approval note/);
  await click(buttonWithText("Save note"));

  const request = await fetchHarness.next("/api/trusted-dependency-baseline", { method: "PATCH", projectPath: PROJECT_A_PATH });
  assert.deepEqual(request.body, {
    project_path: PROJECT_A_PATH,
    note: "Updated project-scoped approval note.",
  });
  assert.equal(Object.hasOwn(request.body, "fingerprint"), false);
  assert.equal(Object.hasOwn(request.body, "snapshot"), false);
  await respond(request, { configured: true, fingerprint, note: "Updated project-scoped approval note." });
  await respond(await fetchHarness.next("/api/scans/history", { projectPath: PROJECT_A_PATH }), {
    scans: [trustedBaselineScan(123, configuredTrustedBaseline("identical", {
      fingerprint,
      note: "Updated project-scoped approval note.",
    }))],
  });

  const panel = document.querySelector("#reports .trusted-baseline");
  assert.match(panel.textContent, /Updated project-scoped approval note/);
  assert.match(panel.textContent, /cfdb2_999999\.\.\.999999/);
});

test("obsolete trusted baseline responses and approval drafts cannot cross project selection", async () => {
  const eligibleA = trustedBaselineScan(115, trustedBaselineFixture({
    approval: { eligible: true, fingerprint: `cfdb2_${"d".repeat(64)}`, reason: "" },
  }));
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [eligibleA] });
  await openReports();
  const note = document.querySelector("#reports .trusted-baseline textarea");
  await input(note, "Project A draft must not cross projects.");
  await click(buttonWithText("Trust this dependency snapshot"));
  const obsolete = await fetchHarness.next("/api/trusted-dependency-baseline", { method: "PUT", projectPath: PROJECT_A_PATH });

  await selectProject("Project B");
  assert.equal(obsolete.signal.aborted, true);
  const eligibleB = {
    ...trustedBaselineScan(116, trustedBaselineFixture({
      approval: { eligible: true, fingerprint: `cfdb2_${"e".repeat(64)}`, reason: "" },
    })),
    project_path: PROJECT_B_PATH,
  };
  await resolveDetails(await takeDetailRequests(PROJECT_B_PATH), { scans: [eligibleB] });
  assert.equal(document.querySelector("#reports .trusted-baseline textarea").value, "");

  await respond(obsolete, { configured: true });
  assert.doesNotMatch(document.body.textContent, /snapshot approved/i);
  assert.match(selectedProjectText(), /Project B/);
  assert.equal(fetchHarness.count("/api/scans/history"), 2);
});

test("a current trusted baseline failure is scoped and does not trigger a success refresh", async () => {
  const eligible = trustedBaselineScan(122, trustedBaselineFixture({
    approval: { eligible: true, fingerprint: `cfdb2_${"1".repeat(64)}`, reason: "" },
  }));
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [eligible] });
  await openReports();
  await click(buttonWithText("Trust this dependency snapshot"));
  const failed = await fetchHarness.next("/api/trusted-dependency-baseline", { method: "PUT" });
  await respond(failed, { detail: "Baseline approval was rejected." }, 409);

  assert.match(document.querySelector("#reports .trusted-baseline-actions").textContent, /Baseline approval was rejected/);
  assert.equal(fetchHarness.count("/api/scans/history"), 1);
  assert.equal(buttonWithText("Trust this dependency snapshot").disabled, false);
});

test("unregistering aborts an in-flight trusted baseline mutation", async () => {
  const eligible = trustedBaselineScan(121, trustedBaselineFixture({
    approval: { eligible: true, fingerprint: `cfdb2_${"f".repeat(64)}`, reason: "" },
  }));
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [eligible] });
  await openReports();
  await click(buttonWithText("Trust this dependency snapshot"));
  const obsolete = await fetchHarness.next("/api/trusted-dependency-baseline", { method: "PUT" });

  window.confirm = () => true;
  await click(document.querySelector('a[href="#projects"]'));
  const selectedRow = [...document.querySelectorAll(".projects-table-row")]
    .find((row) => row.textContent.includes("Project A"));
  await click([...selectedRow.querySelectorAll("button")].find((button) => button.textContent.includes("Unregister")));
  const unregister = await fetchHarness.next("/api/projects", { method: "DELETE", projectPath: PROJECT_A_PATH });
  await respond(unregister, { unregistered: true, path: PROJECT_A_PATH, message: "Project unregistered. Project files were not changed." });
  assert.equal(obsolete.signal.aborted, true);
  await respond(await fetchHarness.next("/api/projects"), { project_root: "C:/workspace", message: "", projects: [PROJECT_B] });
  await respond(obsolete, { detail: "Obsolete baseline error." }, 500);

  assert.doesNotMatch(document.body.textContent, /Obsolete baseline error|snapshot approved/i);
  assert.doesNotMatch(document.querySelector(".projects-table").textContent, /Project A/);
});

test("trusted and previous-scan comparisons remain distinct across history statuses", async () => {
  const drift = trustedBaselineScan(120, configuredTrustedBaseline("drift", {
    comparison: {
      status: "drift",
      explanation: "Drift detected from approved baseline.",
      changeCount: 1,
      highestSeverity: "medium",
      changes: [{ changeType: "version-changed", name: "alpha", currentValue: "2.0.0" }],
      findings: [{ type: "trusted-baseline-version-changed", severity: "medium" }],
    },
  }), { comparison: { baselineStatus: "available", changeCount: 1, changes: [{ changeType: "version-changed", name: "alpha" }], explanation: "Changed from previous scan." } });
  const identical = trustedBaselineScan(119, configuredTrustedBaseline("identical"));
  const incomplete = trustedBaselineScan(118, configuredTrustedBaseline("incomplete", {
    comparison: { status: "incomplete", explanation: "Comparison incomplete; removals were not inferred.", highestSeverity: "medium" },
  }));
  const incompatible = trustedBaselineScan(117, configuredTrustedBaseline("incompatible", {
    comparison: { status: "incompatible", explanation: "Dependency analysis schema is incompatible.", highestSeverity: "medium" },
  }));
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [drift, identical, incomplete, incompatible] });
  await openReports();

  assert.match(document.querySelector("#reports").textContent, /Trusted Dependency Baseline/);
  assert.match(document.querySelector("#reports").textContent, /Drift detected/);
  assert.match(document.querySelector("#reports").textContent, /Changes since previous scan/);

  const rows = [...document.querySelectorAll(".history-row")];
  await click(rows[1].querySelector(".history-view-button"));
  assert.match(document.querySelector("#reports .trusted-baseline").textContent, /Matches approved baseline/);
  await click(rows[2].querySelector(".history-view-button"));
  assert.match(document.querySelector("#reports .trusted-baseline").textContent, /Comparison incomplete/);
  await click(rows[3].querySelector(".history-view-button"));
  assert.match(document.querySelector("#reports .trusted-baseline").textContent, /Incompatible/);
  assert.match(document.querySelector("#reports .trusted-baseline").textContent, /historical evidence is unchanged/i);
});

test("scan button gates duplicate submissions and shows progress", async () => {
  await renderReadyProjectA();
  await click(runScanButton());
  await click(runScanButton());

  assert.equal(fetchHarness.count("/api/scans", "POST"), 1);
  assert.equal(runScanButton().disabled, true);
  assert.equal(runScanButton().textContent, "Scanning...");

  const request = await fetchHarness.next("/api/scans", { method: "POST" });
  await finishScan(request, scan(10, "low", "2026-07-11T13:00:00Z"), []);
  assert.equal(runScanButton().disabled, false);
});

test("scan remains active through follow-up loading", async () => {
  await renderReadyProjectA();
  await click(runScanButton());
  const request = await fetchHarness.next("/api/scans", { method: "POST" });

  await respond(request, scan(11, "low", "2026-07-11T13:01:00Z"));
  const historyRequest = await fetchHarness.next("/api/scans/history", { projectPath: PROJECT_A_PATH });
  assert.equal(runScanButton().disabled, true);
  assert.equal(runScanButton().textContent, "Scanning...");

  await respond(historyRequest, { scans: [] });
  const projectsRequest = await fetchHarness.next("/api/projects");
  await respond(projectsRequest, { project_root: "C:/workspace", message: "", projects: [PROJECT_A, PROJECT_B] });
  assert.equal(runScanButton().disabled, false);
});

test("switching projects releases scan loading ownership", async () => {
  await renderReadyProjectA();
  await click(runScanButton());
  const request = await fetchHarness.next("/api/scans", { method: "POST" });

  await selectProject("Project B");
  await resolveDetails(await takeDetailRequests(PROJECT_B_PATH));
  assert.equal(runScanButton().disabled, false);
  assert.equal(runScanButton().textContent, "Run first scan");

  await respond(request, { ...scan(12, "low", "2026-07-11T13:02:00Z"), project_path: PROJECT_A_PATH });
  const projectsRequest = await fetchHarness.next("/api/projects");
  await respond(projectsRequest, { project_root: "C:/workspace", message: "", projects: [PROJECT_A, PROJECT_B] });
  assert.equal(runScanButton().disabled, false);
});

test("switching projects releases metadata loading ownership", async () => {
  await renderReadyProjectA();
  await click(document.querySelector('a[href="#projects"]'));
  await click(buttonWithText("Save Metadata"));
  const request = await fetchHarness.next("/api/projects/metadata", { method: "PUT" });

  const projectBRow = [...document.querySelectorAll(".projects-table-row")]
    .find((row) => row.textContent.includes("Project B"));
  await click(projectBRow.querySelector(".project-select-target"));
  await resolveDetails(await takeDetailRequests(PROJECT_B_PATH));
  assert.equal(buttonWithText("Save Metadata").disabled, false);

  await respond(request, PROJECT_A);
  assert.equal(buttonWithText("Save Metadata").disabled, false);
});

test("workspace root failure preserves selection and success invalidates it", async () => {
  await renderReadyProjectA();
  window.confirm = () => true;
  await openSettings();
  await click(buttonWithText("Change"));
  const rootInput = document.querySelector('.settings-section input');
  await input(rootInput, "C:/missing");
  await click(buttonWithText("Apply Workspace Root"));
  assert.equal(fetchHarness.count("/api/config/project-root", "PUT"), 1);
  const failed = await fetchHarness.next("/api/config/project-root", { method: "PUT" });
  await respond(failed, { detail: "Workspace root does not exist." }, 404);
  assert.match(selectedProjectText(), /Project A/);
  assert.match(document.body.textContent, /Workspace root does not exist/);

  await input(rootInput, "C:/new-workspace");
  await click(buttonWithText("Apply Workspace Root"));
  assert.equal(fetchHarness.count("/api/config/project-root", "PUT"), 2);
  const changed = await fetchHarness.next("/api/config/project-root", { method: "PUT" });
  await respond(changed, { project_root: "C:/new-workspace" });
  const stateAfterRootChange = parseStoredSession();
  assert.ok(stateAfterRootChange === null || stateAfterRootChange.workspaceRoot === "C:/new-workspace");
  assert.notEqual(stateAfterRootChange?.selectedProjectPath, PROJECT_A_PATH);
  assert.ok(fetchHarness.count("/api/projects") >= 2);
  const projectsRequest = await fetchHarness.next("/api/projects");
  await respond(projectsRequest, { project_root: "C:/new-workspace", message: "", projects: [] });
  assert.doesNotMatch(selectedProjectText(), /Project A/);
  assert.match(document.body.textContent, /C:\/new-workspace/);
});

test("health status is backed by the health endpoint", async () => {
  await renderApp();
  assert.match(document.querySelector(".scanner-status").textContent, /Backend reachable/);
  assert.doesNotMatch(document.body.textContent, /All systems operational/);
});

test("health failure does not claim systems are operational", async () => {
  await renderApp([PROJECT_A, PROJECT_B], new Error("Backend offline"));
  assert.match(document.querySelector(".scanner-status").textContent, /Backend unavailable/);
  assert.match(document.querySelector(".scanner-status").textContent, /Scanner unavailable/);
  assert.doesNotMatch(document.querySelector(".scanner-status").textContent, /Scanner ready/);
  assert.doesNotMatch(document.body.textContent, /All systems operational/);
});

test("project metadata and unregister lifecycle update the real UI flow", async () => {
  const availableA = { ...PROJECT_A, available: true, availability: "available", scan_state: "not_scanned", description: "Old description", project_type: "Python" };
  const missingB = { ...PROJECT_B, available: false, availability: "missing", scan_state: "not_scanned", description: "Missing project" };
  await renderApp([availableA, missingB]);
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH));
  window.confirm = () => true;
  await click(document.querySelector('a[href="#projects"]'));
  assert.match(document.body.textContent, /Python/);
  assert.match(document.body.textContent, /Unavailable: missing/);
  assert.match(document.body.textContent, /Not scanned/);
  const projectsSection = document.querySelector(".projects-section");
  assert.ok(projectsSection.querySelector(":scope > .panel-heading .new-project-button"));
  assert.ok(projectsSection.querySelector(".projects-table-scroll > .projects-table"));
  assert.equal(projectsSection.querySelectorAll(".projects-table-row").length, 2);
  assert.equal(projectsSection.querySelector(".project-row-actions").querySelectorAll("button").length, 1);
  const selectedEntry = projectsSection.querySelector(".projects-table-row.selected");
  assert.match(selectedEntry.querySelector(".selected-project-marker").textContent, /Selected project/);
  assert.equal(selectedEntry.querySelector(".project-select-target").disabled, false);

  const editor = document.querySelector(".projects-section .project-metadata-editor");
  assert.ok(editor, "Expected separate project metadata editor");
  assert.match(editor.textContent, /Edit project details/);
  assert.match(editor.textContent, /Project A/);
  const form = editor.querySelector("form");
  assert.ok(form.classList.contains("project-action-form"));
  assert.equal(form.querySelectorAll("input, textarea, button").length, 3);
  assert.equal(form.querySelector("textarea").value, "Old description");
  await input(form.querySelector("input"), "TypeScript");
  await input(form.querySelector("textarea"), "New description");
  await click(buttonWithText("Save Metadata"));
  const save = await fetchHarness.next("/api/projects/metadata", { method: "PUT" });
  await respond(save, { ...availableA, description: "New description", project_type: "TypeScript" });
  const refreshed = await fetchHarness.next("/api/projects");
  await respond(refreshed, { project_root: "C:/workspace", message: "", projects: [{ ...availableA, description: "New description", project_type: "TypeScript" }, missingB] });
  assert.match(document.body.textContent, /New description/);

  const selectedRow = [...document.querySelectorAll(".projects-table-row")].find((row) => row.textContent.includes("Project A"));
  await click([...selectedRow.querySelectorAll("button")].find((button) => button.textContent.includes("Unregister")));
  const unregister = await fetchHarness.next("/api/projects", { method: "DELETE" });
  await respond(unregister, { unregistered: true, path: PROJECT_A_PATH, message: "Project unregistered. Project files were not changed." });
  assert.equal(parseStoredSession().selectedProjectPath, "");
  assert.equal(parseStoredSession().selectedScanId, null);
  const afterUnregister = await fetchHarness.next("/api/projects");
  await respond(afterUnregister, { project_root: "C:/workspace", message: "", projects: [missingB] });
  assert.match(messageText(), /files were not changed/);
  assert.doesNotMatch(document.querySelector(".projects-table").textContent, /Project A/);
});

test("same-project AGENTS previews and trust saves keep the newest response", async () => {
  await renderReadyProjectA();
  await openSettings();
  const purpose = document.querySelector('textarea[placeholder="Project purpose"]');
  await input(purpose, "First purpose");
  await click(buttonWithText("Preview"));
  const firstPreview = await fetchHarness.next("/api/agents/preview", { method: "POST" });
  await input(purpose, "Second purpose");
  await click(buttonWithText("Preview"));
  const secondPreview = await fetchHarness.next("/api/agents/preview", { method: "POST" });
  await respond(secondPreview, { content: "# New preview" });
  await respond(firstPreview, { content: "# Obsolete preview" });
  assert.match(document.body.textContent, /New preview/);
  assert.doesNotMatch(document.body.textContent, /Obsolete preview/);

  await click(document.querySelector('a[href="#trust-profiles"]'));
  const trustNotes = document.querySelector('.trust-profile-form textarea[placeholder="Local review notes for this project"]');
  await input(trustNotes, "First trust save");
  await click(buttonWithText("Save Trust Profile"));
  const firstSave = await fetchHarness.next("/api/trust-profile", { method: "PUT" });
  await input(trustNotes, "Second trust save");
  await click(buttonWithText("Save Trust Profile"));
  const secondSave = await fetchHarness.next("/api/trust-profile", { method: "PUT" });
  await respond(secondSave, { project_path: PROJECT_A_PATH, notes: "Second trust save" });
  await respond(firstSave, { project_path: PROJECT_A_PATH, notes: "First trust save" });
  assert.equal(trustNotes.value, "Second trust save");
});

test("finding review and reopen update the real scan, history, and Markdown workflow", async () => {
  const finding = reviewableFinding("a");
  const current = scanWithFindings(81, [finding]);
  const historical = { ...scanWithFindings(80, [finding]), scan_date: "2026-07-10T12:00:00Z" };
  let copiedMarkdown = "";
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: async (value) => { copiedMarkdown = value; } },
  });

  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [current, historical] });
  await openReports();
  let card = findingCard("tests/eval_fixture.py");
  assert.match(card.textContent, /Unreviewed/);
  assert.match(card.textContent, /eval regression fixture/);

  await click([...card.querySelectorAll("button")].find((button) => button.textContent.includes("Mark reviewed")));
  const reviewTextarea = findingCard("tests/eval_fixture.py").querySelector("textarea");
  await input(reviewTextarea, "Expected scanner regression fixture.");
  assert.equal(reviewTextarea.value, "Expected scanner regression fixture.");
  card = findingCard("tests/eval_fixture.py");
  await click([...card.querySelectorAll("button")].find((button) => button.textContent.includes("Save review")));
  const save = await fetchHarness.next("/api/finding-reviews", { method: "PUT" });
  assert.deepEqual(save.body, {
    project_path: PROJECT_A_PATH,
    fingerprint: finding.fingerprint,
    status: "expected",
    note: "Expected scanner regression fixture.",
  });
  await respond(save, { review: findingReview(finding.fingerprint) });

  card = findingCard("tests/eval_fixture.py");
  assert.match(card.textContent, /Reviewed as expected/);
  assert.match(card.textContent, /Expected scanner regression fixture/);
  assert.match(document.body.textContent, /Raw risk\s*high/i);
  assert.match(document.body.textContent, /Unreviewed risk\s*none/i);
  assert.match(card.textContent, /eval regression fixture/);

  const historicalRow = [...document.querySelectorAll(".history-row")]
    .find((row) => row.textContent.includes("Jul 10"));
  assert.ok(historicalRow, "Expected historical scan row");
  await click(historicalRow.querySelector(".history-view-button"));
  assert.match(findingCard("tests/eval_fixture.py").textContent, /Reviewed as expected/);
  await click(buttonWithText("Copy Markdown"));
  assert.match(copiedMarkdown, /## Raw risk\nHIGH/);
  assert.match(copiedMarkdown, /- Reviewed findings: 1/);
  assert.match(copiedMarkdown, /- Unresolved findings: 0/);
  assert.match(copiedMarkdown, /- Review reason: Expected scanner regression fixture\./);
  assert.match(copiedMarkdown, /eval regression fixture/);

  card = findingCard("tests/eval_fixture.py");
  await click([...card.querySelectorAll("button")].find((button) => button.textContent.includes("Reopen")));
  const reopen = await fetchHarness.next("/api/finding-reviews", { method: "DELETE" });
  assert.equal(reopen.body.fingerprint, finding.fingerprint);
  await respond(reopen, { reopened: true, fingerprint: finding.fingerprint });
  assert.match(findingCard("tests/eval_fixture.py").textContent, /Unreviewed/);
  assert.doesNotMatch(findingCard("tests/eval_fixture.py").textContent, /Expected scanner regression fixture/);
});

test("unified finding workbench filters, navigates, reports progress, and reuses review persistence", async () => {
  const reviewed = reviewableFinding("1", {
    path: "src/already-reviewed.js",
    review: findingReview(`cf1_${"1".repeat(64)}`),
  });
  const low = reviewableFinding("2", { path: "src/low.js", severity: "low" });
  const high = reviewableFinding("3", { path: "scripts/setup.ps1", type: "executable-or-script-file" });
  const medium = reviewableFinding("4", {
    path: "src/network.js",
    severity: "medium",
    evidence: {
      line: 12,
      matchCount: 2,
      pattern: "eval(",
      excerpt: "const result = eval(networkInput);",
      additionalMatchesOmitted: true,
    },
  });

  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), {
    scans: [scanWithFindings(84, [reviewed, low, high, medium])],
  });
  await openReports();

  const workbench = document.querySelector(".finding-workbench");
  assert.ok(workbench, "Expected unified finding workbench");
  assert.match(workbench.querySelector(".finding-workbench-progress").textContent, /1 \/ 4\s*reviewed/);
  assert.deepEqual(workbenchPaths(), ["scripts/setup.ps1", "src/network.js", "src/low.js", "src/already-reviewed.js"]);
  assert.equal(document.querySelector(".category-detail-views").open, false);
  const evidence = findingCard("src/network.js").querySelector(".finding-evidence");
  assert.ok(evidence, "Expected bounded scanner context in the workbench");
  assert.match(evidence.textContent, /Context only; not proof of malicious behavior/);
  assert.match(evidence.textContent, /Line 12/);
  assert.match(evidence.textContent, /Rule\/pattern eval\(/);
  assert.match(evidence.textContent, /2 matches/);
  assert.match(evidence.textContent, /Additional matches omitted/);
  assert.match(evidence.textContent, /const result = eval\(networkInput\);/);

  await input(controlWithLabel(workbench, "Review status"), "unresolved");
  assert.deepEqual(workbenchPaths(), ["scripts/setup.ps1", "src/network.js", "src/low.js"]);
  await input(controlWithLabel(workbench, "Severity"), "medium");
  assert.deepEqual(workbenchPaths(), ["src/network.js"]);
  await input(controlWithLabel(workbench, "Severity"), "all");
  await input(controlWithLabel(workbench, "Category"), "executable file");
  assert.deepEqual(workbenchPaths(), ["scripts/setup.ps1"]);
  await input(controlWithLabel(workbench, "Category"), "all");
  await input(controlWithLabel(workbench, "Search findings"), "NETWORK.JS");
  assert.deepEqual(workbenchPaths(), ["src/network.js"]);
  await input(controlWithLabel(workbench, "Search findings"), "");

  await click([...workbench.querySelectorAll("button")].find((button) => button.textContent === "Next unresolved"));
  assert.equal(workbench.querySelector(".finding-workbench-item.active code").textContent, "scripts/setup.ps1");
  await click([...workbench.querySelectorAll("button")].find((button) => button.textContent === "Next unresolved"));
  assert.equal(workbench.querySelector(".finding-workbench-item.active code").textContent, "src/network.js");

  const highCard = [...workbench.querySelectorAll(".finding")]
    .find((card) => card.querySelector("code")?.textContent === "scripts/setup.ps1");
  await click([...highCard.querySelectorAll("button")].find((button) => button.textContent === "Mark reviewed"));
  await click([...highCard.querySelectorAll("button")].find((button) => button.textContent === "Save review"));
  const save = await fetchHarness.next("/api/finding-reviews", { method: "PUT" });
  assert.equal(save.body.fingerprint, high.fingerprint);
  await respond(save, { review: findingReview(high.fingerprint) });

  assert.match(workbench.querySelector(".finding-workbench-progress").textContent, /2 \/ 4\s*reviewed/);
  assert.deepEqual(workbenchPaths(), ["src/network.js", "src/low.js"]);
});

test("failed and stale finding-review saves remain scoped to the exact project finding", async () => {
  const findingA = reviewableFinding("c");
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [scanWithFindings(82, [findingA])] });
  await openReports();
  let card = findingCard("tests/eval_fixture.py");
  await click([...card.querySelectorAll("button")].find((button) => button.textContent.includes("Mark reviewed")));
  await click([...card.querySelectorAll("button")].find((button) => button.textContent.includes("Save review")));
  const failed = await fetchHarness.next("/api/finding-reviews", { method: "PUT" });
  await respond(failed, { detail: "Review could not be saved." }, 500);
  card = findingCard("tests/eval_fixture.py");
  assert.match(card.textContent, /Review could not be saved/);
  assert.match(card.textContent, /Unreviewed/);

  await click([...card.querySelectorAll("button")].find((button) => button.textContent.includes("Save review")));
  const obsolete = await fetchHarness.next("/api/finding-reviews", { method: "PUT" });
  await selectProject("Project B");
  const findingB = { ...reviewableFinding("d"), path: "src/current.js", pattern: "child_process" };
  const projectBScan = { ...scanWithFindings(83, [findingB]), project_path: PROJECT_B_PATH };
  await resolveDetails(await takeDetailRequests(PROJECT_B_PATH), { scans: [projectBScan] });
  await openReports();
  await respond(obsolete, { review: findingReview(findingA.fingerprint) });
  const currentCard = findingCard("src/current.js");
  assert.match(currentCard.textContent, /Unreviewed/);
  assert.doesNotMatch(currentCard.textContent, /Review saved|Review could not be saved/);
});

test("changed finding identity stays unresolved while matching history uses current reviews", async () => {
  const oldFinding = {
    ...reviewableFinding("e"),
    review: findingReview(`cf1_${"e".repeat(64)}`),
  };
  const changedFinding = {
    ...reviewableFinding("f"),
    pattern: "Function(",
    explanation: "A changed suspicious pattern was found.",
  };
  const current = scanWithFindings(85, [changedFinding]);
  const historical = { ...scanWithFindings(84, [oldFinding]), scan_date: "2026-07-09T12:00:00Z" };
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [current, historical] });
  await openReports();

  assert.match(findingCard("tests/eval_fixture.py").textContent, /Unreviewed/);
  assert.match(document.body.textContent, /Unreviewed risk\s*high/i);
  const historicalRow = [...document.querySelectorAll(".history-row")]
    .find((row) => row.textContent.includes("Jul 9"));
  assert.ok(historicalRow, "Expected matching historical scan");
  await click(historicalRow.querySelector(".history-view-button"));
  assert.match(findingCard("tests/eval_fixture.py").textContent, /Reviewed as expected/);
});

async function renderApp(projects = [PROJECT_A, PROJECT_B], healthError = null) {
  await act(async () => {
    root.render(React.createElement(App));
  });
  const projectsRequest = await fetchHarness.next("/api/projects");
  const changelogRequest = await fetchHarness.next("/api/changelog");
  const healthRequest = await fetchHarness.next("/api/health");
  await act(async () => {
    projectsRequest.respond({
      project_root: "C:/workspace",
      message: "",
      projects,
    });
    changelogRequest.respond({ entries: [] });
    if (healthError) healthRequest.reject(healthError);
    else healthRequest.respond({ status: "ok" });
    await flushMicrotasks();
  });
}

async function renderReadyProjectA() {
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH));
  assert.match(selectedProjectText(), /Project A/);
}

async function takeDetailRequests(projectPath) {
  const options = { projectPath };
  const [notes, scanHistory, trustProfile, agentsExists] = await Promise.all([
    fetchHarness.next("/api/notes", options),
    fetchHarness.next("/api/scans/history", options),
    fetchHarness.next("/api/trust-profile", options),
    fetchHarness.next("/api/agents/exists", options),
  ]);
  return { notes, scanHistory, trustProfile, agentsExists };
}

async function resolveDetails(requests, options = {}) {
  const skipped = new Set(options.skip || []);
  const rejected = options.reject || {};
  const responses = {
    notes: { notes: options.notes || [] },
    scanHistory: { scans: options.scans || [] },
    trustProfile: options.trustProfile || { project_path: requestProjectPath(requests.trustProfile) },
    agentsExists: { exists: Boolean(options.agentsExists) },
  };
  await act(async () => {
    for (const [name, request] of Object.entries(requests)) {
      if (skipped.has(name)) continue;
      if (rejected[name]) {
        request.reject(rejected[name]);
      } else {
        request.respond(responses[name]);
      }
    }
    await flushMicrotasks();
  });
}

async function finishScan(request, result, history) {
  await respond(request, result);
  const historyRequest = await fetchHarness.next("/api/scans/history", {
    projectPath: PROJECT_A_PATH,
  });
  await respond(historyRequest, { scans: history });
  const projectsRequest = await fetchHarness.next("/api/projects");
  await respond(projectsRequest, {
    project_root: "C:/workspace",
    message: "",
    projects: [
      {
        ...PROJECT_A,
        last_risk_level: result.overall_risk,
        last_scan_time: result.scan_date,
      },
      PROJECT_B,
    ],
  });
}

async function selectProject(name) {
  const button = [...document.querySelectorAll(".project-item")]
    .find((item) => item.textContent.includes(name));
  assert.ok(button, `Expected project button for ${name}`);
  await click(button);
}

async function openSettings() {
  const link = [...document.querySelectorAll(".sidebar-nav a")]
    .find((item) => item.textContent.includes("Settings"));
  assert.ok(link, "Expected Settings navigation link");
  await click(link);
}

async function openReports() {
  const link = [...document.querySelectorAll(".sidebar-nav a")]
    .find((item) => item.textContent.includes("Reports"));
  assert.ok(link, "Expected Reports navigation link");
  await click(link);
}

async function selectHistoryScan(risk) {
  const row = [...document.querySelectorAll(".history-row")]
    .find((item) => item.querySelector(".risk")?.textContent === risk);
  assert.ok(row, `Expected ${risk} history row`);
  await click(row.querySelector(".history-view-button"));
  assert.ok(row.classList.contains("selected-history-row"));
}

async function click(element) {
  await act(async () => {
    element.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
    await flushMicrotasks();
  });
}

async function input(element, value) {
  assert.ok(element, "Expected input element");
  await act(async () => {
    const setter = Object.getOwnPropertyDescriptor(element.constructor.prototype, "value").set;
    setter.call(element, value);
    element.dispatchEvent(new Event("input", { bubbles: true }));
    element.dispatchEvent(new Event("change", { bubbles: true }));
    await flushMicrotasks();
  });
}

function buttonWithText(text) {
  const button = [...document.querySelectorAll("button")].find((item) => item.textContent.includes(text));
  assert.ok(button, `Expected button containing ${text}`);
  return button;
}

async function respond(request, data, status = 200) {
  await act(async () => {
    request.respond(data, status);
    await flushMicrotasks();
  });
}

async function reject(request, error) {
  await act(async () => {
    request.reject(error);
    await flushMicrotasks();
  });
}

function runScanButton() {
  const button = [...document.querySelectorAll(".run-scan-button")]
    .find((item) => ["Run Scan", "Run first scan", "Scanning..."].includes(item.textContent));
  assert.ok(button, "Expected Run Scan button");
  return button;
}

function selectedProjectText() {
  return document.querySelector(".workspace-root-line")?.textContent || "";
}

function messageText() {
  return [...document.querySelectorAll(".notice:not(.subtle-notice)")]
    .map((notice) => notice.textContent)
    .join(" ");
}

function visibleRisk() {
  const label = [...document.querySelectorAll(".summary-label")]
    .find((item) => item.textContent === "Risk Level");
  assert.ok(label, "Expected Risk Level summary card");
  return label.parentElement.querySelector(".summary-value").textContent;
}

function categoryStatuses() {
  return [...document.querySelectorAll(".findings-overview .category-row")]
    .map((row) => row.lastElementChild.textContent);
}

function assertProjectSummary(element, findings, coverage) {
  assert.ok(element, "Expected project summary");
  assert.match(element.textContent, new RegExp(findings));
  assert.match(element.textContent, new RegExp(coverage));
  assert.doesNotMatch(element.textContent, /unknown\s*[—-]\s*coverage unknown/i);
}

function assertReportHeader(findings, coverage, options = {}) {
  const header = document.querySelector("#reports > .section-summary .scan-header-status");
  assert.ok(header, "Expected Scan Report header status");
  assert.match(header.textContent, new RegExp(findings));
  assert.match(header.textContent, new RegExp(coverage));
  assert.doesNotMatch(header.textContent, /\bnone\b/i);
  assert.equal(Boolean(header.querySelector(".scan-header-finding-count.verified")), Boolean(options.verified));
}

function assertHistorySummary(findings, coverage) {
  const row = document.querySelector(".history-row");
  assert.ok(row, "Expected scan history row");
  assert.match(row.querySelector(".risk").textContent, new RegExp(findings));
  assert.match(row.textContent, new RegExp(coverage));
  assert.doesNotMatch(row.querySelector(".risk").textContent, /\bnone\b/i);
}

function storeSession(overrides = {}) {
  window.localStorage.setItem(SESSION_STATE_KEY, JSON.stringify({
    version: 1,
    workspaceRoot: "C:/workspace",
    selectedProjectPath: "",
    activeSection: "workspace",
    selectedScanId: null,
    panels: {},
    ...overrides,
  }));
}

function parseStoredSession() {
  const value = window.localStorage.getItem(SESSION_STATE_KEY);
  return value ? JSON.parse(value) : null;
}

function createFetchHarness() {
  const requests = [];
  const waiters = [];

  function fetch(input, init = {}) {
    const url = new URL(String(input));
    let resolvePromise;
    let rejectPromise;
    const promise = new Promise((resolve, rejectPromiseValue) => {
      resolvePromise = resolve;
      rejectPromise = rejectPromiseValue;
    });
    const request = {
      url,
      method: init.method || "GET",
      body: init.body ? JSON.parse(init.body) : null,
      signal: init.signal || null,
      claimed: false,
      settled: false,
      respond(data, status = 200) {
        if (request.settled) return;
        request.settled = true;
        resolvePromise(response(data, status));
      },
      reject(error) {
        if (request.settled) return;
        request.settled = true;
        rejectPromise(error);
      },
    };
    requests.push(request);
    notifyWaiter(request);
    return promise;
  }

  function next(path, options = {}) {
    const predicate = requestPredicate(path, options);
    const existing = requests.find((request) => !request.claimed && predicate(request));
    if (existing) {
      existing.claimed = true;
      return Promise.resolve(existing);
    }
    return new Promise((resolve) => waiters.push({ predicate, resolve }));
  }

  function notifyWaiter(request) {
    const index = waiters.findIndex((waiter) => waiter.predicate(request));
    if (index < 0) return;
    const [waiter] = waiters.splice(index, 1);
    request.claimed = true;
    waiter.resolve(request);
  }

  async function settleAll() {
    for (let pass = 0; pass < 10; pass += 1) {
      const pending = requests.filter((request) => !request.settled);
      if (!pending.length) break;
      await act(async () => {
        pending.forEach((request) => request.respond(defaultResponse(request)));
        await flushMicrotasks();
      });
    }
    assert.equal(requests.some((request) => !request.settled), false, "Pending fetches leaked from a test");
    assert.equal(waiters.length, 0, "Pending fetch waiters leaked from a test");
  }

  function count(path, method = "GET") {
    return requests.filter((request) => request.url.pathname === path && request.method === method).length;
  }

  return { fetch, next, settleAll, count };
}

function requestPredicate(path, options) {
  return (request) => {
    if (request.url.pathname !== path) return false;
    if (options.method && request.method !== options.method) return false;
    if (options.projectPath && requestProjectPath(request) !== options.projectPath) return false;
    return true;
  };
}

function requestProjectPath(request) {
  return request.url.searchParams.get("project_path") || request.body?.project_path || "";
}

function response(data, status) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return data;
    },
  };
}

function defaultResponse(request) {
  switch (request.url.pathname) {
    case "/api/projects":
      return { project_root: "C:/workspace", message: "", projects: [PROJECT_A, PROJECT_B] };
    case "/api/changelog":
      return { entries: [] };
    case "/api/health":
      return { status: "ok" };
    case "/api/notes":
      return request.method === "POST" ? note(99, "Cleanup note") : { notes: [] };
    case "/api/scans/history":
      return { scans: [] };
    case "/api/trust-profile":
      return { project_path: requestProjectPath(request) };
    case "/api/agents/exists":
      return { exists: false };
    case "/api/scans":
      return scan(99, "low", "2026-07-11T11:00:00Z");
    default:
      return {};
  }
}

function project(name, path) {
  return {
    name,
    path,
    description: "",
    project_type: "",
    last_risk_level: "none",
    last_scan_time: null,
    notes_count: 0,
  };
}

function note(id, body) {
  return {
    id,
    body,
    project_path: body.includes("B") ? PROJECT_B_PATH : PROJECT_A_PATH,
    created_at: "2026-07-11T09:00:00Z",
  };
}

function scan(id, risk, date) {
  return {
    id,
    project_path: PROJECT_A_PATH,
    scan_date: date,
    overall_risk: risk,
    findings: [],
    findingCount: 0,
    reviewedFileCount: 0,
    ignoredFileCount: 0,
    findingSummary: {},
    manifests: [],
    lockfiles: [],
    lifecycleScripts: [],
    secretFiles: [],
    ignoredFiles: [],
    reviewedFiles: [],
    zone: "Source",
  };
}

function reviewableFinding(hex, overrides = {}) {
  return {
    fingerprint: `cf1_${hex.repeat(64)}`,
    review: null,
    type: "suspicious-text-pattern",
    severity: "high",
    path: "tests/eval_fixture.py",
    pattern: "eval(",
    explanation: "Expected eval regression fixture. Pattern: eval(",
    action: "Review the exact test fixture before accepting it.",
    ...overrides,
  };
}

function findingReview(fingerprint) {
  return {
    fingerprint,
    status: "expected",
    note: "Expected scanner regression fixture.",
    created_at: "2026-07-12T10:00:00Z",
    updated_at: "2026-07-12T10:00:00Z",
  };
}

function scanWithFindings(id, findings) {
  return withCompleteness({
    ...scan(id, "high", "2026-07-12T12:00:00Z"),
    findings,
    findingCount: findings.length,
    findingSummary: findings.reduce((summary, finding) => ({
      ...summary,
      [finding.type]: (summary[finding.type] || 0) + 1,
    }), {}),
  }, { complete: true });
}

function findingCard(path) {
  const card = [...document.querySelectorAll(".finding")]
    .find((item) => item.querySelector(".finding-heading > code")?.textContent === path);
  assert.ok(card, `Expected finding card for ${path}`);
  return card;
}

function workbenchPaths() {
  return [...document.querySelectorAll(".finding-workbench-item .finding-heading > code")]
    .map((element) => element.textContent);
}

function controlWithLabel(scope, labelText) {
  const label = [...scope.querySelectorAll("label")].find((item) => item.textContent.includes(labelText));
  assert.ok(label, `Expected ${labelText} control`);
  return label.querySelector("input, select");
}

function withCompleteness(value, completeness) {
  const counts = {
    traversalFailureCount: completeness.traversalFailureCount || 0,
    fileInspectionFailureCount: completeness.fileInspectionFailureCount || 0,
    oversizedFileCount: completeness.oversizedFileCount || 0,
    unsafePathCount: completeness.unsafePathCount || 0,
    dependencyAnalysisFailureCount: completeness.dependencyAnalysisFailureCount || 0,
    policyExcludedFileCount: completeness.policyExcludedFileCount || 0,
    resourceBudgetExceededCount: completeness.resourceBudgetExceededCount || 0,
  };
  return {
    ...value,
    scanCompleteness: {
      complete: completeness.complete,
      ...counts,
      issueCount: Object.values(counts).reduce((total, count) => total + count, 0),
    },
  };
}

function dependencyTrustFixture(overrides = {}) {
  return {
    schemaVersion: 1,
    status: "complete",
    ecosystems: ["node", "python"],
    manifests: ["package.json", "requirements.txt"],
    lockfiles: ["package-lock.json"],
    packageManagers: ["npm", "pip"],
    directDependencyCount: 2,
    lockedDependencyCount: 2,
    integrityCoverage: { total: 2, present: 1, missing: 1 },
    unusualSourceCount: 0,
    installScriptIndicatorCount: 0,
    consistencyIssueCount: 0,
    changeCount: 0,
    highestFindingSeverity: "none",
    entries: [
      { ecosystem: "node", name: "alpha", group: "dependencies", requestedSpecification: "^1", lockedVersion: "1.2.0", sourceType: "registry", integrityPresent: true, direct: true },
      { ecosystem: "python", name: "requests", group: "requirements", requestedSpecification: "==2.31.0", lockedVersion: "2.31.0", sourceType: "registry", integrityPresent: false, direct: true },
    ],
    comparison: { baselineStatus: "unavailable", changeCount: 0, changes: [], explanation: "No previous dependency analysis is available." },
    limitations: [],
    offlineOnly: true,
    ...overrides,
  };
}

function emptyDependencyTrustFixture(overrides = {}) {
  return dependencyTrustFixture({
    status: "unsupported",
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
    entries: [],
    limitations: [],
    ...overrides,
  });
}

function trustedBaselineFixture(overrides = {}) {
  const comparison = overrides.comparison || {};
  const approval = overrides.approval || {};
  return {
    configured: false,
    valid: false,
    status: "not-configured",
    approval: { eligible: false, fingerprint: "", reason: "This scan is not eligible.", ...approval },
    comparison: {
      status: "not-configured",
      explanation: "No trusted dependency baseline is configured.",
      changeCount: 0,
      changes: [],
      findings: [],
      highestSeverity: "none",
      truncated: false,
      ...comparison,
    },
    ...overrides,
    approval: { eligible: false, fingerprint: "", reason: "This scan is not eligible.", ...approval },
    comparison: {
      status: "not-configured",
      explanation: "No trusted dependency baseline is configured.",
      changeCount: 0,
      changes: [],
      findings: [],
      highestSeverity: "none",
      truncated: false,
      ...comparison,
    },
  };
}

function configuredTrustedBaseline(status, overrides = {}) {
  return trustedBaselineFixture({
    configured: true,
    valid: true,
    status: "configured",
    fingerprint: `cfdb2_${"b".repeat(64)}`,
    sourceScanId: 100,
    sourceScanDate: "2026-07-10T12:00:00Z",
    createdAt: "2026-07-10T12:00:00Z",
    updatedAt: "2026-07-10T12:00:00Z",
    note: "Reviewed baseline.",
    approval: { eligible: true, fingerprint: `cfdb2_${"c".repeat(64)}`, reason: "" },
    comparison: {
      status,
      explanation: status === "identical" ? "Matches approved baseline." : `${status} trusted baseline comparison.`,
      changeCount: status === "drift" ? 1 : 0,
      highestSeverity: status === "drift" ? "medium" : "none",
      changes: status === "drift" ? [{ changeType: "version-changed", name: "alpha", currentValue: "2.0.0" }] : [],
      findings: status === "drift" ? [{ type: "trusted-baseline-version-changed", severity: "medium" }] : [],
    },
    ...overrides,
  });
}

function trustedBaselineScan(id, baseline, dependencyOverrides = {}) {
  return {
    ...withCompleteness(scan(id, "low", `2026-07-11T14:${String(id - 100).padStart(2, "0")}:00Z`), { complete: true }),
    dependencyTrust: dependencyTrustFixture({ trustedBaseline: baseline, ...dependencyOverrides }),
  };
}

async function flushMicrotasks() {
  await Promise.resolve();
  await Promise.resolve();
}

function captureGlobals() {
  return new Map(GLOBAL_NAMES.map((name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
}

function installDomGlobals(window) {
  const values = {
    window,
    document: window.document,
    navigator: window.navigator,
    HTMLElement: window.HTMLElement,
    Node: window.Node,
    Event: window.Event,
    MouseEvent: window.MouseEvent,
    MutationObserver: window.MutationObserver,
    getComputedStyle: window.getComputedStyle.bind(window),
    requestAnimationFrame: window.requestAnimationFrame.bind(window),
    cancelAnimationFrame: window.cancelAnimationFrame.bind(window),
  };
  Object.entries(values).forEach(([name, value]) => {
    Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
  });
}

function restoreGlobals(originals) {
  for (const [name, descriptor] of originals) {
    if (descriptor) {
      Object.defineProperty(globalThis, name, descriptor);
    } else {
      delete globalThis[name];
    }
  }
}
