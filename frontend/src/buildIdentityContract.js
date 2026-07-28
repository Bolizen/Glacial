export const BUILD_IDENTITY_SCHEMA_VERSION = 1;
export const BUILD_PROFILES = Object.freeze([
  "development",
  "internal-evidence",
  "signed-preview",
  "public-rc",
  "stable",
]);
export const TRUST_CLASSIFICATIONS = Object.freeze([
  "unsigned",
  "self-signed",
  "publicly-trusted",
  "unknown",
]);
export const SIGNING_STATES = Object.freeze(["unsigned", "verified", "unverified"]);

const COMMIT_PATTERN = /^[0-9a-f]{40}$/;
const THUMBPRINT_PATTERN = /^[0-9A-F]{40}$/;
const VERSION_PATTERN = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const SUBJECT_PATTERN = /^[\x20-\x21\x23-\x5B\x5D-\x7E]{1,512}$/;

export function createBuildIdentity(values) {
  return validateBuildIdentity({
    schemaVersion: BUILD_IDENTITY_SCHEMA_VERSION,
    productName: "Glacial",
    productVersion: values.productVersion,
    sourceCommit: values.sourceCommit ?? null,
    buildProfile: values.buildProfile,
    lifecycleStage: values.buildProfile,
    trustClassification: values.trustClassification,
    signingState: values.signingState,
    signerSubject: values.signerSubject ?? null,
    signerThumbprint: values.signerThumbprint ?? null,
    signerVerification: values.signerVerification,
    frontendVersion: values.frontendVersion,
    tauriVersion: values.tauriVersion,
    unavailableFields: values.unavailableFields ?? [],
  }, { expectedVersion: values.productVersion });
}

export function validateBuildIdentity(value, options = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Build identity must be an object.");
  }
  if (value.schemaVersion !== BUILD_IDENTITY_SCHEMA_VERSION) {
    throw new Error("Build identity schema version is unsupported.");
  }
  if (value.productName !== "Glacial") throw new Error("Build identity product name is invalid.");
  for (const [name, version] of [
    ["product version", value.productVersion],
    ["frontend version", value.frontendVersion],
    ["Tauri version", value.tauriVersion],
  ]) {
    if (typeof version !== "string" || !VERSION_PATTERN.test(version)) {
      throw new Error(`Build identity ${name} is invalid.`);
    }
  }
  if (options.expectedVersion && value.productVersion !== options.expectedVersion) {
    throw new Error("Build identity product version does not match the source version.");
  }
  if (value.frontendVersion !== value.productVersion || value.tauriVersion !== value.productVersion) {
    throw new Error("Build identity component versions do not agree.");
  }
  if (!BUILD_PROFILES.includes(value.buildProfile) || value.lifecycleStage !== value.buildProfile) {
    throw new Error("Build identity profile is missing or unsupported.");
  }
  if (!TRUST_CLASSIFICATIONS.includes(value.trustClassification)) {
    throw new Error("Build identity trust classification is unsupported.");
  }
  if (!SIGNING_STATES.includes(value.signingState)) {
    throw new Error("Build identity signing state is unsupported.");
  }
  if (!Array.isArray(value.unavailableFields)
      || value.unavailableFields.some((field) => !["sourceCommit", "signerSubject", "signerThumbprint"].includes(field))
      || new Set(value.unavailableFields).size !== value.unavailableFields.length) {
    throw new Error("Build identity unavailable fields are invalid.");
  }

  const development = value.buildProfile === "development";
  if (value.sourceCommit === null) {
    if (!development || !value.unavailableFields.includes("sourceCommit")) {
      throw new Error("Only development identity may have an unavailable source commit.");
    }
  } else if (typeof value.sourceCommit !== "string" || !COMMIT_PATTERN.test(value.sourceCommit)) {
    throw new Error("Build identity source commit must be a lowercase 40-character Git commit.");
  }

  const signed = value.signingState === "verified";
  if (development || value.buildProfile === "internal-evidence") {
    if (value.trustClassification !== "unsigned" || value.signingState !== "unsigned") {
      throw new Error(`${value.buildProfile} builds must identify as unsigned.`);
    }
  } else if (value.buildProfile === "signed-preview") {
    if (!signed || !["self-signed", "publicly-trusted"].includes(value.trustClassification)) {
      throw new Error("Signed-preview identity requires an observed verified signer.");
    }
  } else if (!signed || value.trustClassification !== "publicly-trusted") {
    throw new Error(`${value.buildProfile} identity requires an observed publicly trusted signer.`);
  }

  if (signed) {
    if (value.signerVerification !== "verified") {
      throw new Error("Signed identity must label signer evidence as verified.");
    }
    if (typeof value.signerSubject !== "string" || !SUBJECT_PATTERN.test(value.signerSubject)) {
      throw new Error("Verified signer subject is malformed.");
    }
    if (typeof value.signerThumbprint !== "string" || !THUMBPRINT_PATTERN.test(value.signerThumbprint)) {
      throw new Error("Verified signer thumbprint is malformed.");
    }
    if (value.unavailableFields.includes("signerSubject") || value.unavailableFields.includes("signerThumbprint")) {
      throw new Error("Verified signer fields cannot be unavailable.");
    }
  } else {
    if (value.signerSubject !== null || value.signerThumbprint !== null || value.signerVerification !== "not-applicable") {
      throw new Error("Unsigned identity must not report configured signer values as evidence.");
    }
    for (const field of ["signerSubject", "signerThumbprint"]) {
      if (!value.unavailableFields.includes(field)) throw new Error(`Unsigned identity must mark ${field} unavailable.`);
    }
  }
  return Object.freeze({ ...value, unavailableFields: Object.freeze([...value.unavailableFields]) });
}

export function developmentBuildIdentity(version) {
  return createBuildIdentity({
    productVersion: version,
    sourceCommit: null,
    buildProfile: "development",
    trustClassification: "unsigned",
    signingState: "unsigned",
    signerVerification: "not-applicable",
    frontendVersion: version,
    tauriVersion: version,
    unavailableFields: ["sourceCommit", "signerSubject", "signerThumbprint"],
  });
}

