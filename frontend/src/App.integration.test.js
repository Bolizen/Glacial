import assert from "node:assert/strict";
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
  storeSession({ selectedProjectPath: PROJECT_B_PATH, activeSection: "settings", panels: { notes: false } });
  await renderApp();
  await resolveDetails(await takeDetailRequests(PROJECT_B_PATH));

  await click(buttonWithText("Reset saved UI state"));
  const detailsA = await takeDetailRequests(PROJECT_A_PATH);
  await resolveDetails(detailsA);
  assert.equal(window.localStorage.getItem(SESSION_STATE_KEY), null);
  assert.equal(window.localStorage.getItem("unrelated"), "keep");
  assert.match(selectedProjectText(), /Project A/);
  assert.equal(document.querySelector(".topbar h1").textContent, "Workspace Overview");
  assert.match(messageText(), /Backend data and workspace configuration were not changed/);
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
  await click(document.querySelector('a[href="#projects"]'));
  assert.match(document.querySelector(".projects-table-row").textContent, /Incomplete scan/);
  await openReports();
  assert.match(document.body.textContent, /Traversal failures: 1/);
  assert.match(document.body.textContent, /File inspection failures: 2/);
  assert.match(document.body.textContent, /Oversized files: 1/);
  assert.match(document.querySelector(".history-row").textContent, /Incomplete scan/);
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
  assert.match(document.querySelector(".project-item").textContent, /No findings recorded; coverage unknown/);

  await click(document.querySelector('a[href="#projects"]'));
  assert.match(document.querySelector(".projects-table-row").textContent, /No findings recorded; coverage unknown/);
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

  const form = document.querySelector(".projects-section form");
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
    trustProfile: { project_path: requestProjectPath(requests.trustProfile) },
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
