import assert from "node:assert/strict";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import test from "node:test";

import {
  backendStageReceipt,
  verifyBackendStageReceipt,
  writeBackendStageReceipt,
} from "./backend-stage-integrity.mjs";

const REPOSITORY = resolve(import.meta.dirname, "..", "..");
const TEST_ROOT = join(REPOSITORY, ".desktop-build");
const SOURCE_COMMIT = "a".repeat(40);
const PRODUCT_VERSION = "0.9.12";
const EXECUTABLE = "glacial-backend-x86_64-pc-windows-msvc.exe";

function withStage(run) {
  mkdirSync(TEST_ROOT, { recursive: true });
  const root = mkdtempSync(join(TEST_ROOT, "backend-stage-integrity-"));
  try {
    mkdirSync(join(root, "_internal"));
    writeFileSync(join(root, EXECUTABLE), "backend");
    writeFileSync(join(root, "_internal", "python313.dll"), "runtime");
    run(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function options(root, sourceCommit = SOURCE_COMMIT) {
  return {
    root,
    executableName: EXECUTABLE,
    sourceCommit,
    productVersion: PRODUCT_VERSION,
  };
}

test("backend stage receipt binds the complete payload to source identity", () => {
  withStage((root) => {
    const authority = writeBackendStageReceipt(options(root));
    assert.throws(() => verifyBackendStageReceipt(options(root)), /independent stage authority is missing/);
    const receipt = verifyBackendStageReceipt(options(root), authority);
    assert.equal(receipt.sourceCommit, SOURCE_COMMIT);
    assert.equal(receipt.executable.path, "backend-executable");
    assert.deepEqual(receipt.runtime.map((item) => item.path), ["_internal/python313.dll"]);

    writeFileSync(join(root, "_internal", "python313.dll"), "modified runtime");
    assert.throws(
      () => verifyBackendStageReceipt(options(root), authority),
      /does not match the current source identity and complete payload/,
    );
  });
});

test("backend stage receipt rejects stale identity and extra files", () => {
  withStage((root) => {
    assert.throws(
      () => verifyBackendStageReceipt(options(root)),
      /stage receipt is missing/,
    );
    const authority = writeBackendStageReceipt(options(root));
    assert.throws(
      () => verifyBackendStageReceipt(options(root, "b".repeat(40)), authority),
      /does not match the current source identity and complete payload/,
    );
    writeFileSync(join(root, "unexpected.txt"), "unexpected");
    assert.throws(
      () => verifyBackendStageReceipt(options(root), authority),
      /missing or unexpected top-level entry/,
    );
  });
});

test("copied or recomputed colocated receipts cannot replace external stage authority", () => {
  withStage((root) => {
    const authority = writeBackendStageReceipt(options(root));
    writeFileSync(join(root, "_internal", "python313.dll"), "attacker-controlled runtime");
    rmSync(join(root, ".glacial-backend-stage.json"));
    writeBackendStageReceipt(options(root));
    assert.throws(
      () => verifyBackendStageReceipt(options(root), authority),
      /independently authenticated source payload/,
    );
  });
});

test("signed staging rejects bytes that differ from the freshly built payload", () => {
  withStage((root) => {
    const expected = backendStageReceipt(options(root));
    writeFileSync(join(root, EXECUTABLE), "substituted backend");
    assert.throws(
      () => writeBackendStageReceipt(options(root), expected),
      /differs from its freshly constructed source payload/,
    );
  });
});

test("backend stage inventory rejects reparse entries where supported", (context) => {
  withStage((root) => {
    const target = join(root, "_internal", "target");
    mkdirSync(target);
    writeFileSync(join(target, "runtime.dll"), "target");
    try {
      symlinkSync(target, join(root, "_internal", "linked-runtime"), "junction");
    } catch (error) {
      if (error?.code === "EPERM") {
        context.skip("Creating a Windows symbolic link requires unavailable host permission.");
        return;
      }
      throw error;
    }
    assert.throws(
      () => writeBackendStageReceipt(options(root)),
      /symbolic link or junction/,
    );
  });
});
