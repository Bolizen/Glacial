import assert from "node:assert/strict";
import test from "node:test";

import {
  compareInstalledGraph,
  parseCleanEnvironmentArguments,
} from "./validate-clean-environment.mjs";

test("clean gate requires one explicit Python executable", () => {
  assert.throws(() => parseCleanEnvironmentArguments([]), /--python is required/);
  assert.throws(() => parseCleanEnvironmentArguments(["--python", "one", "--python", "two"]), /only once/);
  assert.match(parseCleanEnvironmentArguments(["--python", "python.exe"]).python, /python\.exe$/i);
});

test("build graph validation rejects unexpected and mislabeled installed state", () => {
  const scope = { id: "desktop-build", artifacts: [{ canonicalName: "alpha", version: "1.0" }] };
  assert.deepEqual(compareInstalledGraph(scope, [{ name: "alpha", version: "1.0" }, { name: "pip", version: "99" }]), {
    expectedCount: 1,
    installedCount: 1,
  });
  assert.throws(() => compareInstalledGraph(scope, [{ name: "alpha", version: "2.0" }]), /differs from its lock/);
  assert.throws(() => compareInstalledGraph(scope, [{ name: "beta", version: "1.0" }]), /differs from its lock/);
});
