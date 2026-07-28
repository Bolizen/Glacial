import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const REPOSITORY = resolve(dirname(SCRIPT_PATH), "..", "..");
const FRONTEND = join(REPOSITORY, "frontend");
const EXPECTED_VERSION = "0.9.10";
const EXPECTED_POSTCSS_OVERRIDE = "8.5.18";
const EXACT_SEMVER = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export function validateProductionDependencies(packageJson, packageLock) {
  if (packageJson.version !== EXPECTED_VERSION
      || packageLock.version !== EXPECTED_VERSION
      || packageLock.packages?.[""]?.version !== EXPECTED_VERSION) {
    throw new Error(`Application and lockfile versions must all equal ${EXPECTED_VERSION}.`);
  }
  const declared = packageJson.dependencies;
  const lockedRoot = packageLock.packages?.[""]?.dependencies;
  if (!declared || typeof declared !== "object" || Array.isArray(declared)) {
    throw new Error("package.json production dependencies must be an object.");
  }
  if (!lockedRoot || typeof lockedRoot !== "object" || Array.isArray(lockedRoot)) {
    throw new Error("package-lock root production dependencies are unavailable.");
  }
  if (JSON.stringify(Object.keys(declared).sort()) !== JSON.stringify(Object.keys(lockedRoot).sort())) {
    throw new Error("package.json and package-lock root dependency sets do not match.");
  }
  for (const [name, version] of Object.entries(declared)) {
    if (typeof version !== "string" || !EXACT_SEMVER.test(version)) {
      throw new Error(`${name} must use one exact semantic version; ranges, tags, URLs, Git, workspace aliases, and wildcards are rejected.`);
    }
    if (lockedRoot[name] !== version) {
      throw new Error(`${name} package/lock root declarations do not match.`);
    }
    const lockedPackage = packageLock.packages?.[`node_modules/${name}`];
    if (!lockedPackage || lockedPackage.version !== version) {
      throw new Error(`${name} does not have the expected locked package version ${version}.`);
    }
  }
  if (packageJson.overrides?.postcss !== EXPECTED_POSTCSS_OVERRIDE) {
    throw new Error(`The exact PostCSS override must remain ${EXPECTED_POSTCSS_OVERRIDE}.`);
  }
  return {
    applicationVersion: EXPECTED_VERSION,
    directProductionDependencies: Object.keys(declared).length,
    postcssOverride: EXPECTED_POSTCSS_OVERRIDE,
    graphFingerprint: resolvedGraphFingerprint(packageLock),
  };
}

export function resolvedGraphFingerprint(packageLock) {
  const normalized = structuredClone(packageLock);
  normalized.version = "<APPLICATION_VERSION>";
  if (normalized.packages?.[""]) {
    normalized.packages[""].version = "<APPLICATION_VERSION>";
    normalized.packages[""].dependencies = Object.fromEntries(
      Object.keys(normalized.packages[""].dependencies ?? {}).sort().map((name) => [name, "<ROOT_DECLARATION>"]),
    );
  }
  return createHash("sha256").update(JSON.stringify(normalized)).digest("hex").toUpperCase();
}

export function assertNoUnrelatedResolutionChurn(before, after) {
  if (resolvedGraphFingerprint(before) !== resolvedGraphFingerprint(after)) {
    throw new Error("package-lock.json contains unrelated resolution churn.");
  }
  return true;
}

function main() {
  const packageJson = JSON.parse(readFileSync(join(FRONTEND, "package.json"), "utf8"));
  const packageLock = JSON.parse(readFileSync(join(FRONTEND, "package-lock.json"), "utf8"));
  const result = validateProductionDependencies(packageJson, packageLock);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(SCRIPT_PATH)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}

