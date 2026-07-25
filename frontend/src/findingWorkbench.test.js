import assert from "node:assert/strict";
import test from "node:test";

import {
  buildFindingWorkbenchItems,
  filterFindingWorkbenchItems,
  findingWorkbenchFilterOptions,
  findingWorkbenchProgress,
  nextUnresolvedFindingKey,
} from "./findingWorkbench.js";


test("orders unresolved findings first, then severity, then existing order", () => {
  const items = buildFindingWorkbenchItems([
    finding("reviewed-high", "high", "src/reviewed.js", { status: "reviewed" }),
    finding("low-first", "low", "src/low-first.js"),
    finding("high", "high", "src/high.js"),
    finding("low-second", "low", "src/low-second.js"),
    finding("medium", "medium", "src/medium.js"),
    finding("reviewed-low", "low", "src/reviewed-low.js", { status: "expected" }),
  ]);

  assert.deepEqual(items.map((item) => item.finding.id), [
    "high",
    "medium",
    "low-first",
    "low-second",
    "reviewed-high",
    "reviewed-low",
  ]);
});


test("filters by review status, severity, category, title, and path", () => {
  const items = buildFindingWorkbenchItems([
    finding("critical", "critical", "src/critical.js"),
    finding("script", "high", "scripts/setup.ps1", null, "executable-or-script-file"),
    finding("pattern", "medium", "src/network.js", { status: "reviewed" }, "suspicious-text-pattern"),
    finding("secret", "high", ".env.local", null, "secret-looking-file"),
  ]);

  assert.deepEqual(filterFindingWorkbenchItems(items, { reviewStatus: "unresolved" }).map(id), ["critical", "script", "secret"]);
  assert.deepEqual(filterFindingWorkbenchItems(items, { reviewStatus: "reviewed" }).map(id), ["pattern"]);
  assert.deepEqual(filterFindingWorkbenchItems(items, { severity: "medium" }).map(id), ["pattern"]);
  assert.deepEqual(filterFindingWorkbenchItems(items, { severity: "critical-high" }).map(id), ["critical", "script", "secret"]);
  assert.deepEqual(filterFindingWorkbenchItems(items, { category: "secret-looking file" }).map(id), ["secret"]);
  assert.deepEqual(filterFindingWorkbenchItems(items, { query: "EXECUTABLE" }).map(id), ["script"]);
  assert.deepEqual(filterFindingWorkbenchItems(items, { query: "NETWORK.JS" }).map(id), ["pattern"]);
});


test("reports progress and stable filter options", () => {
  const items = buildFindingWorkbenchItems([
    finding("high", "high", "src/high.js"),
    finding("medium", "medium", "src/medium.js", { status: "reviewed" }, "lockfile"),
    finding("low", "low", "src/low.js", { status: "expected" }, "lockfile"),
  ]);

  assert.deepEqual(findingWorkbenchProgress(items), { reviewed: 2, total: 3, unresolved: 1 });
  assert.deepEqual(findingWorkbenchFilterOptions(items), {
    categories: ["lockfile", "zone/metadata"],
    severities: ["high", "medium", "low"],
  });
});


test("next unresolved navigation advances, wraps, and ignores reviewed findings", () => {
  const items = buildFindingWorkbenchItems([
    finding("first", "high", "src/first.js"),
    finding("reviewed", "high", "src/reviewed.js", { status: "reviewed" }),
    finding("second", "medium", "src/second.js"),
  ]);
  const [first, second] = items.filter((item) => !item.reviewed);

  assert.equal(nextUnresolvedFindingKey(items), first.key);
  assert.equal(nextUnresolvedFindingKey(items, first.key), second.key);
  assert.equal(nextUnresolvedFindingKey(items, second.key), first.key);
  assert.equal(nextUnresolvedFindingKey(items, items.find((item) => item.reviewed).key), first.key);
  assert.equal(nextUnresolvedFindingKey(items.map((item) => ({ ...item, reviewed: true }))), "");
});


function finding(idValue, severity, path, review = null, type = "suspicious-text-pattern") {
  return {
    id: idValue,
    fingerprint: `cf1_${idValue.padEnd(64, "0").slice(0, 64)}`,
    type,
    severity,
    path,
    review,
  };
}


function id(item) {
  return item.finding.id;
}
