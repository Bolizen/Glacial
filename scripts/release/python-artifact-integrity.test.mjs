import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  loadPythonArtifactManifest,
  parseExactRequirements,
  renderHashedRequirements,
  verifyWheelhouse,
} from "./python-artifact-integrity.mjs";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

test("committed Python provenance exactly covers both locked environments", () => {
  const manifest = loadPythonArtifactManifest(repository);
  assert.equal(manifest.runtimeContract.version, "3.13.13");
  assert.equal(manifest.runtimeContract.bits, 64);
  assert.equal(manifest.scopes["backend-runtime"].artifacts.length, 14);
  assert.equal(manifest.scopes["desktop-build"].artifacts.length, 7);
  assert.match(renderHashedRequirements(manifest.scopes["backend-runtime"]), /pydantic_core==2\.46\.4 --hash=sha256:6b3ace/);
});

test("lock parser rejects ranges, missing versions, and duplicate normalized names", () => {
  assert.throws(() => parseExactRequirements("alpha>=1\n"), /exact name==version/);
  assert.throws(() => parseExactRequirements("alpha\n"), /exact name==version/);
  assert.throws(() => parseExactRequirements("alpha-beta==1\nalpha_beta==1\n"), /duplicate package/);
});

test("wheelhouse verification rejects matching package labels with tampered bytes", () => {
  const fixtureParent = join(repository, ".desktop-build");
  mkdirSync(fixtureParent, { recursive: true });
  const root = mkdtempSync(join(fixtureParent, "g080-integrity-test-"));
  try {
    const lockPath = join(root, "backend", "requirements.lock.txt");
    const buildLockPath = join(root, "backend", "desktop-build-requirements.lock");
    mkdirSync(dirname(lockPath), { recursive: true });
    writeFileSync(lockPath, readFileSync(join(repository, "backend", "requirements.lock.txt")));
    writeFileSync(buildLockPath, readFileSync(join(repository, "backend", "desktop-build-requirements.lock")));
    mkdirSync(join(root, "docs", "release"), { recursive: true });
    writeFileSync(join(root, "docs", "release", "python-artifact-integrity.json"), readFileSync(join(repository, "docs", "release", "python-artifact-integrity.json")));
    const scope = loadPythonArtifactManifest(root).scopes["backend-runtime"];
    const wheelhouse = join(root, "wheelhouse");
    mkdirSync(wheelhouse);
    for (const artifact of scope.artifacts) writeFileSync(join(wheelhouse, artifact.filename), "tampered");
    assert.throws(() => verifyWheelhouse(scope, wheelhouse), /artifact SHA-256 mismatch/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
