import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createBuildIdentity,
  developmentBuildIdentity,
  validateBuildIdentity,
} from "../../frontend/src/buildIdentityContract.js";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
export const REPOSITORY = resolve(dirname(SCRIPT_PATH), "..", "..");
export const FRONTEND = join(REPOSITORY, "frontend");

export function sourceVersion() {
  const packageJson = JSON.parse(readFileSync(join(FRONTEND, "package.json"), "utf8"));
  return String(packageJson.version);
}

export function buildIdentityForProfile({ profile, sourceCommit, signerIdentity = null }) {
  const version = sourceVersion();
  if (profile === "development") return developmentBuildIdentity(version);
  if (profile === "internal-evidence") {
    return createBuildIdentity({
      productVersion: version,
      sourceCommit,
      buildProfile: profile,
      trustClassification: "unsigned",
      signingState: "unsigned",
      signerVerification: "not-applicable",
      frontendVersion: version,
      tauriVersion: version,
      unavailableFields: ["signerSubject", "signerThumbprint"],
    });
  }
  return createBuildIdentity({
    productVersion: version,
    sourceCommit,
    buildProfile: profile,
    trustClassification: signerIdentity?.trustClassification ?? "unknown",
    signingState: signerIdentity ? "verified" : "unverified",
    signerVerification: signerIdentity ? "verified" : "unverified",
    signerSubject: signerIdentity?.canonicalSubject ?? null,
    signerThumbprint: signerIdentity?.signerThumbprint ?? null,
    frontendVersion: version,
    tauriVersion: version,
    unavailableFields: signerIdentity ? [] : ["signerSubject", "signerThumbprint"],
  });
}

export function parseInjectedBuildIdentity(environment = process.env) {
  const raw = environment.GLACIAL_BUILD_IDENTITY_JSON;
  if (!raw) return null;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("GLACIAL_BUILD_IDENTITY_JSON is malformed.");
  }
  return validateBuildIdentity(parsed, { expectedVersion: sourceVersion() });
}

export function serializeBuildIdentity(identity) {
  return JSON.stringify(validateBuildIdentity(identity, { expectedVersion: sourceVersion() }));
}

