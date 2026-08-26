import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import test from "node:test";

import { assertReleaseInputTree, releaseInputTreeReceipt } from "./release-input-provenance.mjs";

const ROOT = join(resolve(import.meta.dirname, "..", ".."), ".desktop-build");

function withTree(run) {
  mkdirSync(ROOT, { recursive: true });
  const root = mkdtempSync(join(ROOT, "input-provenance-"));
  try {
    mkdirSync(join(root, "nested"));
    writeFileSync(join(root, "nested", "input.js"), "trusted");
    run(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("release input receipt detects same-version installed-byte substitution", () => {
  withTree((root) => {
    const receipt = releaseInputTreeReceipt(root, "node-modules");
    assertReleaseInputTree(root, receipt);
    writeFileSync(join(root, "nested", "input.js"), "mutated");
    assert.throws(() => assertReleaseInputTree(root, receipt), /changed after authenticated reconstruction/);
  });
});

test("pnpm-shaped node trees have relocation-stable execution receipts", (context) => {
  mkdirSync(ROOT, { recursive: true });
  const roots = [mkdtempSync(join(ROOT, "pnpm-a-")), mkdtempSync(join(ROOT, "pnpm-b-"))];
  try {
    for (const [index, root] of roots.entries()) {
      const packageRoot = join(root, ".pnpm", "example@1.0.0", "node_modules", "example");
      mkdirSync(packageRoot, { recursive: true });
      writeFileSync(join(packageRoot, "index.js"), "module.exports = 'authenticated';\n");
      writeFileSync(join(root, ".modules.yaml"), `storeDir: C:\\different-store-${index}\nprunedAt: ${index}\n`);
      try { symlinkSync(packageRoot, join(root, "example"), "junction"); } catch (error) {
        if (error?.code === "EPERM") { context.skip("Creating a Windows junction is unavailable."); return; }
        throw error;
      }
    }
    assert.deepEqual(
      releaseInputTreeReceipt(roots[0], "node-modules"),
      releaseInputTreeReceipt(roots[1], "node-modules"),
    );
  } finally {
    for (const root of roots) rmSync(root, { recursive: true, force: true });
  }
});

test("release input receipt rejects junction escapes", (context) => {
  withTree((root) => {
    const outside = mkdtempSync(join(ROOT, "input-provenance-outside-"));
    try {
      writeFileSync(join(outside, "payload.js"), "outside");
      try { symlinkSync(outside, join(root, "escape"), "junction"); } catch (error) {
        if (error?.code === "EPERM") { context.skip("Creating a Windows junction is unavailable."); return; }
        throw error;
      }
      assert.throws(() => releaseInputTreeReceipt(root, "node-modules"), /outside the authenticated input tree/);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });
});
