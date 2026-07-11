import assert from "node:assert/strict";
import { after, afterEach, before, beforeEach, test } from "node:test";

import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { JSDOM } from "jsdom";
import { createServer } from "vite";

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

test("two scans resolving out of order keep the newest requested scan visible", async () => {
  await renderReadyProjectA();
  await click(runScanButton());
  const firstScanRequest = await fetchHarness.next("/api/scans", { method: "POST" });
  await click(runScanButton());
  const secondScanRequest = await fetchHarness.next("/api/scans", { method: "POST" });

  const firstScan = scan(1, "low", "2026-07-11T10:00:00Z");
  const secondScan = scan(2, "high", "2026-07-11T10:01:00Z");
  await finishScan(secondScanRequest, secondScan, [secondScan, firstScan]);
  assert.equal(visibleRisk(), "HIGH");

  await finishScan(firstScanRequest, firstScan, [firstScan, secondScan]);
  assert.equal(visibleRisk(), "HIGH");
  assert.doesNotMatch(messageText(), /obsolete|failed/i);
});

test("an obsolete scan response cannot clear a selected history scan", async () => {
  await renderApp();
  const baselineScan = scan(0, "medium", "2026-07-11T09:59:00Z");
  await resolveDetails(await takeDetailRequests(PROJECT_A_PATH), {
    scans: [baselineScan],
  });
  await click(runScanButton());
  const firstScanRequest = await fetchHarness.next("/api/scans", { method: "POST" });
  await click(runScanButton());
  const secondScanRequest = await fetchHarness.next("/api/scans", { method: "POST" });

  const firstScan = scan(1, "low", "2026-07-11T10:00:00Z");
  const secondScan = scan(2, "high", "2026-07-11T10:01:00Z");
  await finishScan(secondScanRequest, secondScan, [secondScan, baselineScan]);
  await openReports();
  await selectHistoryScan("medium");

  await finishScan(firstScanRequest, firstScan, [firstScan, secondScan, baselineScan]);
  const selectedRow = document.querySelector(".history-row.selected-history-row");
  assert.ok(selectedRow, "Expected the selected history row to remain selected");
  assert.equal(selectedRow.querySelector(".risk").textContent, "medium");
  assert.match(selectedRow.textContent, /Viewing/);
});

test("an older failed scan cannot replace a newer success with an error", async () => {
  await renderReadyProjectA();
  await click(runScanButton());
  const firstScanRequest = await fetchHarness.next("/api/scans", { method: "POST" });
  await click(runScanButton());
  const secondScanRequest = await fetchHarness.next("/api/scans", { method: "POST" });

  const secondScan = scan(2, "high", "2026-07-11T10:01:00Z");
  await finishScan(secondScanRequest, secondScan, [secondScan]);
  await reject(firstScanRequest, new Error("Obsolete scan failed"));

  assert.equal(visibleRisk(), "HIGH");
  assert.doesNotMatch(messageText(), /Obsolete scan failed/);
  assert.match(messageText(), /Scan complete/);
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

async function renderApp() {
  await act(async () => {
    root.render(React.createElement(App));
  });
  const projectsRequest = await fetchHarness.next("/api/projects");
  const changelogRequest = await fetchHarness.next("/api/changelog");
  await act(async () => {
    projectsRequest.respond({
      project_root: "C:/workspace",
      message: "",
      projects: [PROJECT_A, PROJECT_B],
    });
    changelogRequest.respond({ entries: [] });
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

async function respond(request, data) {
  await act(async () => {
    request.respond(data);
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

  return { fetch, next, settleAll };
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
