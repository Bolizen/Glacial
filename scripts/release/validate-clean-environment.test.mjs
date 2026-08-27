import assert from "node:assert/strict";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  PINNED_PNPM,
  compareInstalledGraph,
  parseCleanEnvironmentArguments,
  prepareViteConfigScratch,
  removeDisposableTree,
} from "./validate-clean-environment.mjs";
import { assertReleaseInputTree, releaseInputTreeReceipt } from "./release-input-provenance.mjs";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

test("signed construction pins pnpm bytes and independently reconstructs prepared inputs", () => {
  assert.deepEqual(PINNED_PNPM, {
    version: "11.16.0",
    url: "https://registry.npmjs.org/pnpm/-/pnpm-11.16.0.tgz",
    integrity: "sha512-t2fpqY/IeuwPQtrvzQ6ElBws20XXPE4eaIYPsr39vgMqtZIQVHnl4Fwjf3QMil/9u7UjhXl93CKWdFobu4g+jQ==",
    shasum: "fc0b55d90c04ed8a7c3e37659cc72c188028f6f1",
  });
  const builder = readFileSync(join(repository, "scripts", "desktop", "Build-SignedWindowsRelease.mjs"), "utf8");
  assert.match(builder, /verifyPreparedInputsByReconstruction\(\{/);
  assert.match(builder, /const source = verifyReleaseSource\(gitPath, authority, preparedInputs\.source\);[\s\S]*verifyPreparedInputsByReconstruction\(\{[\s\S]*const started = new Date\(\);/);
  assert.match(builder, /runBrokeredTauriBuild\([\s\S]*assertAuthenticatedReleaseTool\(tools\.cargo\);[\s\S]*assertAuthenticatedReleaseTool\(tools\.rustc\);/);
});

test("clean gate requires one explicit Python executable", () => {
  assert.throws(() => parseCleanEnvironmentArguments([]), /--python is required/);
  assert.throws(() => parseCleanEnvironmentArguments(["--python", "one", "--python", "two"]), /only once/);
  assert.match(parseCleanEnvironmentArguments(["--python", "python.exe"]).python, /python\.exe$/i);
  assert.equal(parseCleanEnvironmentArguments(["--profile", "signed-preview", "--python", "python.exe"]).profile, "signed-preview");
  assert.throws(() => parseCleanEnvironmentArguments(["--profile", "development", "--python", "python.exe"]), /signed-preview or public-rc/);
});

test("Vite config scratch is authenticated without hiding executable leftovers", () => {
  const fixture = join(repository, ".desktop-build", "g116-vite-scratch-test", "node_modules");
  rmSync(dirname(fixture), { recursive: true, force: true });
  try {
    mkdirSync(join(fixture, "package"), { recursive: true });
    writeFileSync(join(fixture, "package", "index.js"), "export default 'authenticated';\n");
    const scratch = prepareViteConfigScratch(fixture);
    const receipt = releaseInputTreeReceipt(fixture, "node-modules");
    writeFileSync(join(scratch, "vite.config.timestamp-random.mjs"), "export default {};\n");
    assert.throws(() => assertReleaseInputTree(fixture, receipt), /changed after authenticated reconstruction/);
    assert.throws(() => prepareViteConfigScratch(fixture), /must be an empty normal directory/);
    rmSync(join(scratch, "vite.config.timestamp-random.mjs"));
    assertReleaseInputTree(fixture, receipt);
  } finally {
    rmSync(dirname(fixture), { recursive: true, force: true });
  }
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
