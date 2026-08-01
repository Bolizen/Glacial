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
  return {
    manifest: {
      version: "0.9.12",
      dependencies,
      overrides: { postcss: "8.5.18" },
    },
    lock: {
      version: "0.9.12",
      packages: {
        "": { version: "0.9.12", dependencies: { ...dependencies } },
        "node_modules/@tauri-apps/api": { version: "2.11.1" },
        "node_modules/@vitejs/plugin-react": { version: "5.2.0" },
        "node_modules/react": { version: "19.2.7" },
        "node_modules/react-dom": { version: "19.2.7" },
        "node_modules/vite": { version: "7.3.6" },
        "node_modules/postcss": { version: "8.5.18" },
      },
    },
  };
}

test("exact direct production declarations and lock parity pass", () => {
  const { manifest, lock } = fixture();
  assert.equal(validateProductionDependencies(manifest, lock).directProductionDependencies, 5);
});

test("loose declarations, aliases, URLs, tags, Git sources, and wildcards fail closed", () => {
  for (const invalid of ["^19.2.7", "~19.2.7", "*", "latest", "workspace:*", "file:../react", "git+https://example.test/repo.git", "https://example.test/react.tgz"]) {
    const { manifest, lock } = fixture();
    manifest.dependencies.react = invalid;
    lock.packages[""].dependencies.react = invalid;
    assert.throws(() => validateProductionDependencies(manifest, lock), /exact semantic version/);
  }
});

test("package/lock root mismatches and missing locked packages fail closed", () => {
  const mismatch = fixture();
  mismatch.lock.packages[""].dependencies.react = "19.2.6";
  assert.throws(() => validateProductionDependencies(mismatch.manifest, mismatch.lock), /root declarations/);
  const missing = fixture();
  delete missing.lock.packages["node_modules/vite"];
  assert.throws(() => validateProductionDependencies(missing.manifest, missing.lock), /expected locked package/);
});

test("unrelated resolution churn is rejected while reviewed root declaration changes are ignored", () => {
  const before = fixture().lock;
  const rootOnly = structuredClone(before);
  rootOnly.packages[""].dependencies.react = "19.2.7";
  assert.equal(assertNoUnrelatedResolutionChurn(before, rootOnly), true);
  const churn = structuredClone(before);
  churn.packages["node_modules/react"].version = "19.2.8";
  assert.throws(() => assertNoUnrelatedResolutionChurn(before, churn), /unrelated resolution churn/);
});
