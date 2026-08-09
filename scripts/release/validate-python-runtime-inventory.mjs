import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync, rmdirSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertSafePath,
  ensureSafeDirectory,
  minimalEnvironment,
  privacySafePath,
  removeSafeTree,
  runCommand,
  sanitizeDiagnosticText,
} from "../desktop/windows-signing.mjs";
import { parseLockedPythonRequirements } from "./generate-third-party-inventory.mjs";

const scriptPath = fileURLToPath(import.meta.url);
const repository = resolve(dirname(scriptPath), "..", "..");
const requirementsPath = join(repository, "backend", "requirements.lock.txt");
const inventoryScript = join(repository, "scripts", "release", "generate-third-party-inventory.mjs");
const defaultEnvironment = join(repository, ".desktop-build", "runtime-inventory-venv");
const verifiedPythonVersions = new Set(["3.12.13", "3.13.13"]);

function fail(message) {
  throw new Error(message);
}

function canonicalizePackageName(value) {
  return value.toLowerCase().replaceAll(/[-_.]+/g, "-");
}

function parseArguments(argv) {
  let python;
  let environment = defaultEnvironment;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--python") {
      if (python !== undefined) fail("--python may be provided only once.");
      python = argv[index + 1];
      if (!python || python.startsWith("--")) fail("--python requires an executable path.");
      index += 1;
    } else if (argument === "--environment") {
      environment = argv[index + 1];
      if (!environment || environment.startsWith("--")) fail("--environment requires a path.");
      index += 1;
    } else {
      fail(`Unknown Python inventory validation argument: ${argument}`);
    }
  }
  if (!python) fail("--python is required; clean inventory validation never selects a developer virtual environment implicitly.");
  return { python: resolve(python), environment: resolve(environment) };
}

function run(command, args, options = {}) {
  const redactions = options.redactions ?? [];
  const result = runCommand(command, args, {
    cwd: options.cwd ?? repository,
    env: options.env,
    timeoutMs: options.timeoutMs ?? 900_000,
    includeFailureOutput: true,
    diagnosticRedactions: redactions,
  });
  if (options.visible !== false) {
    if (result.stdout) process.stdout.write(sanitizeDiagnosticText(result.stdout, redactions));
    if (result.stderr) process.stderr.write(sanitizeDiagnosticText(result.stderr, redactions));
  }
  return result;
}

function runJson(command, args, options = {}) {
  const result = run(command, args, { ...options, visible: false });
  try {
    return JSON.parse(result.stdout);
  } catch {
    fail(`${privacySafePath(command)} returned invalid JSON.`);
  }
}

function validateBaseInterpreter(python, environment) {
  if (!isAbsolute(python) || !existsSync(python) || !lstatSync(python).isFile() || lstatSync(python).isSymbolicLink()) {
    fail(`--python must identify a real absolute executable file: ${privacySafePath(python)}`);
  }
  const canonicalPython = realpathSync.native(python);
  const identity = runJson(canonicalPython, [
    "-c",
    "import json, platform, struct, sys; print(json.dumps({'executable': sys.executable, 'prefix': sys.prefix, 'base_prefix': sys.base_prefix, 'implementation': sys.implementation.name, 'version': platform.python_version(), 'platform': sys.platform, 'bits': struct.calcsize('P') * 8, 'machine': platform.machine()}))",
  ], { env: environment, redactions: [canonicalPython] });
  if (realpathSync.native(identity.executable).toLowerCase() !== canonicalPython.toLowerCase()) fail("Selected Python executable identity does not match --python.");
  if (resolve(identity.prefix).toLowerCase() !== resolve(identity.base_prefix).toLowerCase()) fail("--python must be a base interpreter, not a pre-existing virtual environment.");
  if (identity.implementation !== "cpython" || identity.platform !== "win32" || identity.bits !== 64) fail("Python inventory validation requires 64-bit CPython on Windows.");
  if (!verifiedPythonVersions.has(identity.version)) fail(`Python ${identity.version} is not a committed verified runtime version; expected 3.12.13 or 3.13.13.`);
  return { ...identity, executable: canonicalPython };
}

function validateEnvironmentIdentity(python, environmentPath, expectedVersion, environment) {
  const identity = runJson(python, [
    "-c",
    "import json, platform, sys, sysconfig; print(json.dumps({'executable': sys.executable, 'prefix': sys.prefix, 'base_prefix': sys.base_prefix, 'version': platform.python_version(), 'site_packages': sysconfig.get_path('purelib')}))",
  ], { env: environment, redactions: [python, environmentPath] });
  if (resolve(identity.prefix).toLowerCase() !== resolve(environmentPath).toLowerCase()) fail("Disposable Python environment prefix does not match the requested environment.");
  if (resolve(identity.prefix).toLowerCase() === resolve(identity.base_prefix).toLowerCase()) fail("Disposable Python environment was not isolated from its base interpreter.");
  if (identity.version !== expectedVersion) fail(`Disposable Python version ${identity.version} differs from selected base ${expectedVersion}.`);
  const sitePackages = assertSafePath(environmentPath, identity.site_packages);
  const child = relative(environmentPath, sitePackages);
  if (!child || child === ".." || child.startsWith(`..${sep}`) || isAbsolute(child)) fail("Disposable site-packages escapes its environment.");
  return { ...identity, sitePackages };
}

export function compareLockedRuntimeGraph(requirementsText, installedItems) {
  const expectedEntries = parseLockedPythonRequirements(requirementsText);
  const expected = new Map(expectedEntries.map((entry) => [canonicalizePackageName(entry.name), entry.version]));
  const installed = new Map();
  for (const item of installedItems) {
    const name = canonicalizePackageName(String(item.name ?? ""));
    const version = String(item.version ?? "");
    if (!name || !version) fail("pip list returned incomplete package metadata.");
    if (name === "pip") continue;
    if (installed.has(name)) fail(`pip list returned duplicate package metadata for ${name}.`);
    installed.set(name, version);
  }
  const missing = [...expected.keys()].filter((name) => !installed.has(name)).sort();
  const unexpected = [...installed.keys()].filter((name) => !expected.has(name)).sort();
  const versionMismatches = [...expected.entries()]
    .filter(([name, version]) => installed.has(name) && installed.get(name) !== version)
    .map(([name, expectedVersion]) => ({ name, expected: expectedVersion, installed: installed.get(name) }));
  return {
    expectedCount: expected.size,
    installedCount: installed.size,
    missing,
    unexpected,
    versionMismatches,
  };
}

function assertLockedRuntimeGraph(comparison) {
  if (!comparison.missing.length && !comparison.unexpected.length && !comparison.versionMismatches.length && comparison.expectedCount === comparison.installedCount) return;
  fail(`Installed backend runtime does not match requirements.lock.txt.\nMissing: ${comparison.missing.join(", ") || "(none)"}\nUnexpected: ${comparison.unexpected.join(", ") || "(none)"}\nVersion mismatches: ${comparison.versionMismatches.map((item) => `${item.name} ${item.installed} != ${item.expected}`).join(", ") || "(none)"}`);
}

export function validatePythonRuntimeInventory(argv = process.argv.slice(2)) {
  const options = parseArguments(argv);
  const environmentPath = assertSafePath(repository, options.environment);
  if (environmentPath.toLowerCase() === repository.toLowerCase()) fail("Disposable environment cannot be the repository root.");
  if (existsSync(environmentPath)) fail(`Disposable Python environment already exists: ${privacySafePath(environmentPath)}`);

  const parent = dirname(environmentPath);
  const parentExisted = existsSync(parent);
  const childEnvironment = minimalEnvironment(process.env, {
    PIP_DISABLE_PIP_VERSION_CHECK: "1",
    PYTHONNOUSERSITE: "1",
    PYTHONDONTWRITEBYTECODE: "1",
  });
  const baseIdentity = validateBaseInterpreter(options.python, childEnvironment);
  let cleanupEnvironment = false;
  try {
    ensureSafeDirectory(repository, parent);
    cleanupEnvironment = true;
    run(baseIdentity.executable, ["-m", "venv", environmentPath], { env: childEnvironment, redactions: [baseIdentity.executable, environmentPath] });
    const environmentPython = join(environmentPath, "Scripts", "python.exe");
    if (!existsSync(environmentPython) || !lstatSync(environmentPython).isFile() || lstatSync(environmentPython).isSymbolicLink()) fail("Disposable virtual environment did not create a real Python executable.");
    const environmentIdentity = validateEnvironmentIdentity(environmentPython, environmentPath, baseIdentity.version, childEnvironment);
    const installArguments = [
      "-m", "pip", "--isolated", "install", "--disable-pip-version-check", "--no-cache-dir", "--no-deps", "--requirement", requirementsPath,
    ];
    run(environmentPython, installArguments, { env: childEnvironment, redactions: [environmentPython, environmentPath], timeoutMs: 900_000 });
    run(environmentPython, ["-m", "pip", "--isolated", "check"], { env: childEnvironment, redactions: [environmentPython, environmentPath] });
    const installedItems = runJson(environmentPython, ["-m", "pip", "--isolated", "list", "--format=json", "--disable-pip-version-check"], {
      env: childEnvironment,
      redactions: [environmentPython, environmentPath],
    });
    const comparison = compareLockedRuntimeGraph(readFileSync(requirementsPath), installedItems);
    assertLockedRuntimeGraph(comparison);
    run(process.execPath, [inventoryScript, "--check", "--python-site-packages", environmentIdentity.sitePackages], {
      env: childEnvironment,
      redactions: [environmentIdentity.sitePackages, environmentPath],
      timeoutMs: 900_000,
    });
    const summary = {
      python: {
        executable: privacySafePath(baseIdentity.executable),
        version: baseIdentity.version,
        implementation: baseIdentity.implementation,
        platform: baseIdentity.platform,
        bits: baseIdentity.bits,
        machine: baseIdentity.machine,
      },
      environment: privacySafePath(environmentPath),
      sitePackages: privacySafePath(environmentIdentity.sitePackages),
      installCommand: [privacySafePath(environmentPython), ...installArguments],
      bootstrapExcludedFromRuntimeGraph: ["pip"],
      ...comparison,
      inventoryCheck: "PASS",
    };
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
    return summary;
  } finally {
    if (cleanupEnvironment) removeSafeTree(repository, environmentPath);
    if (!parentExisted && existsSync(parent) && readdirSync(parent).length === 0) rmdirSync(parent);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(scriptPath)) {
  try {
    validatePythonRuntimeInventory();
  } catch (error) {
    process.stderr.write(`${sanitizeDiagnosticText(error.message)}\n`);
    process.exitCode = 1;
  }
}
