import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const repository = resolve(dirname(scriptPath), "..", "..");
const exactSemver = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export const WINDOWS_RELEASE_PYTHON = Object.freeze({
  name: "CPython",
  implementation: "cpython",
  version: "3.13.13",
  platform: "win32",
  bits: 64,
  machine: "AMD64",
});

export function currentProductVersion(root = repository) {
  const packageJson = JSON.parse(readFileSync(join(root, "frontend", "package.json"), "utf8"));
  if (typeof packageJson.version !== "string" || !exactSemver.test(packageJson.version)) {
    throw new Error("frontend/package.json does not declare one exact semantic application version.");
  }
  return packageJson.version;
}

export function assertWindowsReleasePythonIdentity(identity, options = {}) {
  const observed = {
    implementation: String(identity?.implementation ?? "unknown"),
    version: String(identity?.version ?? "unknown"),
    platform: String(identity?.platform ?? "unknown"),
    bits: Number(identity?.bits),
    machine: String(identity?.machine ?? "unknown"),
  };
  const valid = observed.implementation === WINDOWS_RELEASE_PYTHON.implementation
    && observed.version === WINDOWS_RELEASE_PYTHON.version
    && observed.platform === WINDOWS_RELEASE_PYTHON.platform
    && observed.bits === WINDOWS_RELEASE_PYTHON.bits
    && observed.machine.toLowerCase() === WINDOWS_RELEASE_PYTHON.machine.toLowerCase();
  if (valid) return true;

  const observedBits = Number.isFinite(observed.bits) ? `${observed.bits}-bit` : "unknown-bit";
  const selectionHint = options.selectionHint
    ?? "Supply the exact base interpreter with --python <path-to-python.exe>.";
  throw new Error(
    `Selected interpreter reports ${observed.implementation} ${observed.version}, architecture ${observedBits} ${observed.machine}, platform ${observed.platform}; `
    + `release validation requires ${WINDOWS_RELEASE_PYTHON.name} ${WINDOWS_RELEASE_PYTHON.version}, architecture ${WINDOWS_RELEASE_PYTHON.bits}-bit ${WINDOWS_RELEASE_PYTHON.machine}, platform Windows. ${selectionHint}`,
  );
}
