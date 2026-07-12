import assert from "node:assert/strict";
import test from "node:test";

import { dependencyStatusLabel, normalizeDependencyTrust } from "./dependencyTrust.js";

test("legacy dependency analysis remains unavailable rather than clean", () => {
  const trust = normalizeDependencyTrust(undefined);
  assert.equal(trust.available, false);
  assert.equal(trust.status, "unavailable");
  assert.equal(dependencyStatusLabel(trust), "Analysis unavailable");
});

test("complete, incomplete, and malformed states preserve compact counts and false values", () => {
  const trust = normalizeDependencyTrust({
    schemaVersion: 1,
    status: "complete",
    ecosystems: ["python", "node", "node"],
    directDependencyCount: 0,
    lockedDependencyCount: 0,
    integrityCoverage: { total: 0, present: 0, missing: 0 },
    entries: [{ ecosystem: "node", name: "alpha", direct: true, integrityPresent: false, optional: false }],
    comparison: { baselineStatus: "available", changes: [] },
    offlineOnly: true,
  });
  assert.equal(dependencyStatusLabel(trust), "Supported checks complete");
  assert.deepEqual(trust.ecosystems, ["node", "python"]);
  assert.equal(trust.entries[0].integrityPresent, false);
  assert.equal(trust.directDependencyCount, 0);
});

test("large inventories and changes are capped deterministically", () => {
  const entries = Array.from({ length: 70 }, (_, index) => ({ ecosystem: "node", name: `package-${String(index).padStart(2, "0")}`, direct: true }));
  const changes = Array.from({ length: 70 }, (_, index) => ({ changeType: "added", ecosystem: "node", name: `package-${String(index).padStart(2, "0")}` }));
  const trust = normalizeDependencyTrust({ schemaVersion: 1, status: "incomplete", entries: entries.reverse(), comparison: { changes: changes.reverse() } });
  assert.equal(trust.entries.length, 50);
  assert.equal(trust.hiddenEntryCount, 20);
  assert.equal(trust.entries[0].name, "package-00");
  assert.equal(trust.comparison.changes.length, 50);
  assert.equal(trust.comparison.hiddenChangeCount, 20);
});

test("direct dependencies remain visible when transitive inventory exceeds the UI cap", () => {
  const transitive = Array.from({ length: 80 }, (_, index) => ({ ecosystem: "node", name: `a-transitive-${index}`, direct: false }));
  const trust = normalizeDependencyTrust({
    schemaVersion: 1,
    status: "complete",
    entries: [...transitive, { ecosystem: "node", name: "react", direct: true }, { ecosystem: "python", name: "fastapi", direct: true }],
    comparison: { changes: [] },
  });

  assert.deepEqual(trust.entries.filter((entry) => entry.direct).map((entry) => entry.name), ["react", "fastapi"]);
  assert.equal(trust.entries.length, 50);
  assert.equal(trust.hiddenEntryCount, 32);
});
