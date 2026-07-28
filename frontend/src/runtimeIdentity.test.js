import assert from "node:assert/strict";
import test from "node:test";

import { createBuildIdentity } from "./buildIdentityContract.js";
import { normalizeBackendIdentity, reconcileRuntimeIdentity } from "./runtimeIdentity.js";

const VERSION = "0.9.10";
const COMMIT = "a".repeat(40);

function internalIdentity(overrides = {}) {
  return createBuildIdentity({
    productVersion: VERSION,
    sourceCommit: COMMIT,
    buildProfile: "internal-evidence",
    trustClassification: "unsigned",
    signingState: "unsigned",
    signerVerification: "not-applicable",
    frontendVersion: VERSION,
    tauriVersion: VERSION,
    unavailableFields: ["signerSubject", "signerThumbprint"],
    ...overrides,
  });
}

test("runtime identity reports an exact frontend/backend match", () => {
  const value = reconcileRuntimeIdentity(internalIdentity(), {
    schema_version: 1,
    product_name: "Glacial",
    product_version: VERSION,
    component: "owned-backend",
  });
  assert.equal(value.backendAgreement, "match");
});

test("runtime identity exposes a backend version mismatch", () => {
  const value = reconcileRuntimeIdentity(internalIdentity(), {
    schema_version: 1,
    product_name: "Glacial",
    product_version: "0.9.9",
    component: "owned-backend",
  });
  assert.equal(value.backendAgreement, "mismatch");
});

test("build profiles fail closed on missing commits, unknown production trust, and self-signed public RCs", () => {
  assert.throws(() => internalIdentity({ sourceCommit: "A".repeat(40) }), /lowercase 40-character/);
  assert.throws(() => createBuildIdentity({
    productVersion: VERSION,
    sourceCommit: COMMIT,
    buildProfile: "public-rc",
    trustClassification: "unknown",
    signingState: "unverified",
    signerVerification: "unverified",
    frontendVersion: VERSION,
    tauriVersion: VERSION,
  }), /publicly trusted/);
  assert.throws(() => createBuildIdentity({
    productVersion: VERSION,
    sourceCommit: COMMIT,
    buildProfile: "public-rc",
    trustClassification: "self-signed",
    signingState: "verified",
    signerVerification: "verified",
    signerSubject: "CN=Icefields Development",
    signerThumbprint: "A".repeat(40),
    frontendVersion: VERSION,
    tauriVersion: VERSION,
  }), /publicly trusted/);
});

test("backend identity rejects malformed or excessive identity shapes", () => {
  assert.throws(() => normalizeBackendIdentity({ product_name: "Glacial" }), /invalid/);
  assert.throws(() => normalizeBackendIdentity({
    schema_version: 1,
    product_name: "Glacial",
    product_version: "latest",
    component: "owned-backend",
  }), /version is invalid/);
});

