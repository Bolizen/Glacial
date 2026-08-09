import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { packageVersionKeys, readRootImporter, readTopLevelMap, resolvedGraphFingerprint } from "./pnpm-lock.mjs";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const REPOSITORY = resolve(dirname(SCRIPT_PATH), "..", "..");
const FRONTEND = join(REPOSITORY, "frontend");
const EXPECTED_VERSION = "0.9.12";
const EXPECTED_POSTCSS_OVERRIDE = "8.5.18";
const EXPECTED_PACKAGE_MANAGER = "pnpm@11.16.0";
const EXACT_SEMVER = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export function validateProductionDependencies(packageJson, pnpmLock, pnpmWorkspace) {
  if (packageJson.version !== EXPECTED_VERSION) throw new Error(`Application version must equal ${EXPECTED_VERSION}.`);
  if (packageJson.packageManager !== EXPECTED_PACKAGE_MANAGER) throw new Error(`packageManager must equal ${EXPECTED_PACKAGE_MANAGER}.`);
  const declared = packageJson.dependencies;
  const lockedRoot = readRootImporter(pnpmLock).dependencies;
  const lockedPackages = packageVersionKeys(pnpmLock);
  if (!declared || typeof declared !== "object" || Array.isArray(declared)) {
    throw new Error("package.json production dependencies must be an object.");
  }
  if (!lockedRoot || typeof lockedRoot !== "object" || Array.isArray(lockedRoot)) {
    throw new Error("pnpm lockfile root production dependencies are unavailable.");
  }
  if (JSON.stringify(Object.keys(declared).sort()) !== JSON.stringify(Object.keys(lockedRoot).sort())) {
    throw new Error("package.json and pnpm lockfile root dependency sets do not match.");
  }
  for (const [name, version] of Object.entries(declared)) {
    if (typeof version !== "string" || !EXACT_SEMVER.test(version)) {
      throw new Error(`${name} must use one exact semantic version; ranges, tags, URLs, Git, workspace aliases, and wildcards are rejected.`);
    }
    if (lockedRoot[name]?.specifier !== version || lockedRoot[name]?.version?.split("(", 1)[0] !== version) {
      throw new Error(`${name} package/lock root declarations do not match.`);
    }
    if (!lockedPackages.has(`${name}@${version}`)) {
      throw new Error(`${name} does not have the expected locked package version ${version}.`);
    }
  }
  const overrides = readTopLevelMap(pnpmWorkspace, "overrides");
  if (JSON.stringify(overrides) !== JSON.stringify({ postcss: EXPECTED_POSTCSS_OVERRIDE })) {
    throw new Error(`The exact PostCSS override must remain ${EXPECTED_POSTCSS_OVERRIDE}.`);
  }
  const allowBuilds = readTopLevelMap(pnpmWorkspace, "allowBuilds");
  if (JSON.stringify(allowBuilds) !== JSON.stringify({ esbuild: "true" })) {
    throw new Error("The pnpm dependency build-script allowlist must approve only esbuild.");
  }
  return {
    applicationVersion: EXPECTED_VERSION,
    directProductionDependencies: Object.keys(declared).length,
    postcssOverride: EXPECTED_POSTCSS_OVERRIDE,
    packageManager: EXPECTED_PACKAGE_MANAGER,
    graphFingerprint: resolvedGraphFingerprint(pnpmLock),
  };
}

export function assertNoUnrelatedResolutionChurn(before, after) {
  if (resolvedGraphFingerprint(before) !== resolvedGraphFingerprint(after)) {
    throw new Error("pnpm-lock.yaml contains unrelated resolution churn.");
  }
  return true;
}

function main() {
  const packageJson = JSON.parse(readFileSync(join(FRONTEND, "package.json"), "utf8"));
  const pnpmLock = readFileSync(join(FRONTEND, "pnpm-lock.yaml"), "utf8");
  const pnpmWorkspace = readFileSync(join(FRONTEND, "pnpm-workspace.yaml"), "utf8");
  const result = validateProductionDependencies(packageJson, pnpmLock, pnpmWorkspace);
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
