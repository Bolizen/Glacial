import { invoke, isTauri } from "@tauri-apps/api/core";

import { developmentBuildIdentity, validateBuildIdentity } from "./buildIdentityContract.js";

const FALLBACK_VERSION = "0.9.10";

export function normalizeBackendIdentity(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Backend runtime identity is unavailable.");
  }
  if (value.schema_version !== 1 || value.product_name !== "Glacial" || value.component !== "owned-backend") {
    throw new Error("Backend runtime identity is invalid.");
  }
  if (typeof value.product_version !== "string" || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(value.product_version)) {
    throw new Error("Backend runtime version is invalid.");
  }
  return {
    schemaVersion: value.schema_version,
    productName: value.product_name,
    productVersion: value.product_version,
    component: value.component,
  };
}

export function reconcileRuntimeIdentity(buildValue, backendValue) {
  const build = validateBuildIdentity(buildValue);
  const backend = normalizeBackendIdentity(backendValue);
  return {
    build,
    backend,
    backendAgreement: backend.productName === build.productName && backend.productVersion === build.productVersion
      ? "match"
      : "mismatch",
  };
}

export async function requestHostBuildIdentity(dependencies = {}) {
  const useTauri = dependencies.isTauriImpl ? dependencies.isTauriImpl() : isTauri();
  if (!useTauri) {
    const injected = typeof __GLACIAL_BUILD_IDENTITY__ === "undefined"
      ? developmentBuildIdentity(FALLBACK_VERSION)
      : __GLACIAL_BUILD_IDENTITY__;
    return validateBuildIdentity(injected);
  }
  const invokeImpl = dependencies.invokeImpl || invoke;
  return validateBuildIdentity(await invokeImpl("build_identity"));
}

