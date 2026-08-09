import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  compareInstalledGraph,
  parseCleanEnvironmentArguments,
  removeDisposableTree,
} from "./validate-clean-environment.mjs";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

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

test("disposable cleanup is bounded to a verified repository child", () => {
  const fixture = join(repository, ".desktop-build", "g080-cleanup-test");
  mkdirSync(fixture, { recursive: true });
  writeFileSync(join(fixture, "fixture.txt"), "disposable");
  assert.equal(removeDisposableTree(repository, fixture), true);
  assert.equal(removeDisposableTree(repository, fixture), false);
  assert.throws(() => removeDisposableTree(repository, dirname(repository)), /Refusing a path outside/);
});
