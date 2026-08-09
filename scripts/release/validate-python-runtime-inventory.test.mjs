import assert from "node:assert/strict";
import test from "node:test";

import { resolve } from "node:path";

import {
  compareLockedRuntimeGraph,
  parseArguments,
} from "./validate-python-runtime-inventory.mjs";

const lock = "alpha==1.0.0\nbeta-package==2.0.0\n";

test("clean validation uses only the explicitly selected interpreter", () => {
  const selected = resolve("C:\\Selected Runtime\\python.exe");
  assert.equal(parseArguments(["--python", selected]).python, selected);
  assert.throws(() => parseArguments([]), /--python is required/);
});

test("locked runtime graph comparison excludes pip bootstrap tooling", () => {
  assert.deepEqual(compareLockedRuntimeGraph(lock, [
    { name: "alpha", version: "1.0.0" },
    { name: "beta_package", version: "2.0.0" },
    { name: "pip", version: "25.0.1" },
  ]), {
    expectedCount: 2,
    installedCount: 2,
    missing: [],
    unexpected: [],
    versionMismatches: [],
  });
});

test("locked runtime graph comparison reports missing, unexpected, and mismatched packages", () => {
  assert.deepEqual(compareLockedRuntimeGraph(lock, [
    { name: "alpha", version: "0.9.0" },
    { name: "gamma", version: "3.0.0" },
  ]), {
    expectedCount: 2,
    installedCount: 2,
    missing: ["beta-package"],
    unexpected: ["gamma"],
    versionMismatches: [{ name: "alpha", expected: "1.0.0", installed: "0.9.0" }],
  });
});
