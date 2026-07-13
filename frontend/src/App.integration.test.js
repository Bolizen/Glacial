import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, afterEach, before, beforeEach, test } from "node:test";

import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { JSDOM } from "jsdom";
import { createServer } from "vite";
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
    dependencyTrust: emptyDependencyTrustFixture(),
  };
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), { scans: [empty] });

  const overview = document.querySelector(".dependency-trust-overview");
  assert.ok(overview, "Expected Dependency Trust in the selected scan overview");
  assert.match(overview.textContent, /No metadata detected/);
  assert.match(overview.textContent, /No supported Node or Python dependency graph was analyzed/);
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
  assert.equal(runScanButton().textContent, "Run Scan");

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
  await click([...projectBRow.querySelectorAll("button")].find((button) => button.textContent === "Select"));
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
  assert.match(document.body.textContent, /Old description/);
  assert.match(document.body.textContent, /Python/);
  assert.match(document.body.textContent, /Unavailable: missing/);
  assert.match(document.body.textContent, /Not scanned/);
  const projectsSection = document.querySelector(".projects-section");
  assert.ok(projectsSection.querySelector(":scope > .panel-heading .new-project-button"));
  assert.ok(projectsSection.querySelector(".projects-table-scroll > .projects-table"));
  assert.equal(projectsSection.querySelector(".projects-table-header span:nth-child(2)").textContent, "Scan Status");
  assert.equal(projectsSection.querySelector(".project-row-actions").querySelectorAll("button").length, 2);

  const form = document.querySelector(".projects-section form");
  assert.ok(form.classList.contains("project-action-form"));
  assert.equal(form.querySelectorAll("input, textarea, button").length, 3);
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
  const button = document.querySelector(".run-scan-button");
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

function withCompleteness(value, completeness) {
  const counts = {
    traversalFailureCount: completeness.traversalFailureCount || 0,
    fileInspectionFailureCount: completeness.fileInspectionFailureCount || 0,
    oversizedFileCount: completeness.oversizedFileCount || 0,
    unsafePathCount: completeness.unsafePathCount || 0,
    dependencyAnalysisFailureCount: completeness.dependencyAnalysisFailureCount || 0,
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
