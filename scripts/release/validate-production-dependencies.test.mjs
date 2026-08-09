import assert from "node:assert/strict";
import test from "node:test";

import {
  assertNoUnrelatedResolutionChurn,
  validateProductionDependencies,
} from "./validate-production-dependencies.mjs";

function fixture() {
  const dependencies = {
    "@tauri-apps/api": "2.11.1",
    "@vitejs/plugin-react": "5.2.0",
    react: "19.2.7",
    "react-dom": "19.2.7",
    vite: "7.3.6",
  };
  const importer = Object.entries(dependencies).map(([name, version]) => `      '${name}':\n        specifier: ${version}\n        version: ${version}`).join("\n");
  const packages = Object.entries(dependencies).map(([name, version]) => `  '${name}@${version}':\n    resolution: {integrity: test}`).join("\n\n");
  return {
    manifest: {
      version: "0.9.12",
      packageManager: "pnpm@11.16.0",
      dependencies,
    },
    lock: `lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n${importer}\n\npackages:\n\n${packages}\n\n  postcss@8.5.18:\n    resolution: {integrity: test}\n\nsnapshots:\n\n${packages}\n`,
    workspace: "allowBuilds:\n  esbuild: true\n\noverrides:\n  postcss: 8.5.18\n",
  };
}

test("exact direct production declarations and lock parity pass", () => {
  const { manifest, lock, workspace } = fixture();
  assert.equal(validateProductionDependencies(manifest, lock, workspace).directProductionDependencies, 5);
});

test("loose declarations, aliases, URLs, tags, Git sources, and wildcards fail closed", () => {
  for (const invalid of ["^19.2.7", "~19.2.7", "*", "latest", "workspace:*", "file:../react", "git+https://example.test/repo.git", "https://example.test/react.tgz"]) {
    const { manifest, lock, workspace } = fixture();
    manifest.dependencies.react = invalid;
    assert.throws(() => validateProductionDependencies(manifest, lock, workspace), /exact semantic version/);
  }
});

test("package/lock root mismatches and missing locked packages fail closed", () => {
  const mismatch = fixture();
  mismatch.lock = mismatch.lock.replace("specifier: 19.2.7", "specifier: 19.2.6");
  assert.throws(() => validateProductionDependencies(mismatch.manifest, mismatch.lock, mismatch.workspace), /root declarations/);
  const missing = fixture();
  missing.lock = missing.lock.replace("  'vite@7.3.6':\n    resolution: {integrity: test}\n\n", "");
  assert.throws(() => validateProductionDependencies(missing.manifest, missing.lock, missing.workspace), /expected locked package/);
});

test("package-manager identity and pnpm security settings fail closed", () => {
  const wrongManager = fixture();
  wrongManager.manifest.packageManager = "pnpm@11.20.0";
  assert.throws(() => validateProductionDependencies(wrongManager.manifest, wrongManager.lock, wrongManager.workspace), /packageManager/);
  const extraBuild = fixture();
  extraBuild.workspace = extraBuild.workspace.replace("  esbuild: true", "  esbuild: true\n  fsevents: true");
  assert.throws(() => validateProductionDependencies(extraBuild.manifest, extraBuild.lock, extraBuild.workspace), /approve only esbuild/);
  const missingOverride = fixture();
  missingOverride.workspace = missingOverride.workspace.replace("  postcss: 8.5.18", "  postcss: 8.5.19");
  assert.throws(() => validateProductionDependencies(missingOverride.manifest, missingOverride.lock, missingOverride.workspace), /PostCSS override/);
});

test("unrelated resolution churn is rejected while reviewed root declaration changes are ignored", () => {
  const before = fixture().lock;
  const rootOnly = before.replace("specifier: 19.2.7", "specifier: 19.2.6");
  assert.equal(assertNoUnrelatedResolutionChurn(before, rootOnly), true);
  const churn = before.replace("  'react@19.2.7':", "  'react@19.2.8':");
  assert.throws(() => assertNoUnrelatedResolutionChurn(before, churn), /unrelated resolution churn/);
});
