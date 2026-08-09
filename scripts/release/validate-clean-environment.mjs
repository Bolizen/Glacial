import { existsSync, lstatSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertSafePath,
  ensureSafeDirectory,
  minimalEnvironment,
  privacySafePath,
  removeSafeTree,
  resolvePnpmInvocation,
  resolveToolExecutable,
  runCommand,
  sanitizeDiagnosticText,
  sha256,
  validateStructuredDigest,
} from "../desktop/windows-signing.mjs";
import {
  loadPythonArtifactManifest,
  renderHashedRequirements,
  verifyWheelhouse,
} from "./python-artifact-integrity.mjs";
import {
  WINDOWS_RELEASE_PYTHON,
  assertWindowsReleasePythonIdentity,
} from "./release-contract.mjs";

const scriptPath = fileURLToPath(import.meta.url);
const repository = resolve(dirname(scriptPath), "..", "..");
const frontendRelative = "frontend";
const testFiles = [
  "scripts/release/release-contract.test.mjs",
  "scripts/release/python-artifact-integrity.test.mjs",
  "scripts/release/validate-clean-environment.test.mjs",
  "scripts/release/validate-python-runtime-inventory.test.mjs",
  "scripts/release/validate-production-dependencies.test.mjs",
  "scripts/release/generate-third-party-inventory.test.mjs",
  "scripts/desktop/Signer-Preflight.test.mjs",
];

function fail(message) {
  throw new Error(message);
}

export function parseCleanEnvironmentArguments(argv) {
  let python;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument !== "--python") fail(`Unknown clean-environment gate argument: ${argument}`);
    if (python !== undefined) fail("--python may be provided only once.");
    python = argv[index + 1];
    if (!python || python.startsWith("--")) fail("--python requires an executable path.");
    index += 1;
  }
  if (!python) fail("--python is required; the clean-environment gate never selects an interpreter implicitly.");
  return { python: resolve(python) };
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

function runText(command, args, options = {}) {
  return String(run(command, args, { ...options, visible: false }).stdout ?? "").trim();
}

function runJson(command, args, options = {}) {
  const output = runText(command, args, options);
  try { return JSON.parse(output); } catch { fail(`${privacySafePath(command)} returned invalid JSON.`); }
}

export function inspectReleasePython(python, environment = minimalEnvironment(process.env)) {
  if (!isAbsolute(python) || !existsSync(python) || !lstatSync(python).isFile() || lstatSync(python).isSymbolicLink()) {
    fail(`--python must identify a real absolute executable file: ${privacySafePath(python)}`);
  }
  const canonicalPython = realpathSync.native(python);
  const identity = runJson(canonicalPython, [
    "-c",
    "import json, platform, struct, sys; print(json.dumps({'executable': sys.executable, 'prefix': sys.prefix, 'base_prefix': sys.base_prefix, 'implementation': sys.implementation.name, 'version': platform.python_version(), 'platform': sys.platform, 'bits': struct.calcsize('P') * 8, 'machine': platform.machine()}))",
  ], { env: environment, redactions: [canonicalPython] });
  if (realpathSync.native(identity.executable).toLowerCase() !== canonicalPython.toLowerCase()) fail("Selected Python executable identity does not match --python.");
  if (resolve(identity.prefix).toLowerCase() !== resolve(identity.base_prefix).toLowerCase()) fail("--python must be a base interpreter, not a virtual environment.");
  assertWindowsReleasePythonIdentity(identity);
  return { ...identity, executable: canonicalPython };
}

function gitState(git, root, environment) {
  return {
    head: validateStructuredDigest(runText(git, ["rev-parse", "HEAD"], { cwd: root, env: environment }), "git-commit"),
    status: runText(git, ["status", "--porcelain=v1", "--untracked-files=all"], { cwd: root, env: environment }),
    workingDiff: runText(git, ["diff", "--binary"], { cwd: root, env: environment }),
    cachedDiff: runText(git, ["diff", "--cached", "--binary"], { cwd: root, env: environment }),
  };
}

function assertCleanState(state, label, expectedHead = state.head) {
  if (state.head !== expectedHead) fail(`${label} HEAD changed during clean-environment validation.`);
  if (state.status || state.workingDiff || state.cachedDiff) fail(`${label} is not clean.`);
}

function assertSameState(before, after, label) {
  assertCleanState(before, `${label} before validation`);
  assertCleanState(after, `${label} after validation`, before.head);
}

function assertRepositoryChild(root, target, label) {
  const child = relative(resolve(root), resolve(target));
  if (!child || child === ".." || child.startsWith(`..${sep}`) || isAbsolute(child)) fail(`${label} must remain inside the disposable checkout.`);
  return resolve(target);
}

function expectedPnpmVersion(root) {
  const packageManager = JSON.parse(readFileSync(join(root, "frontend", "package.json"), "utf8")).packageManager;
  const match = String(packageManager ?? "").match(/^pnpm@(\d+\.\d+\.\d+)$/);
  if (!match) fail("frontend/package.json must pin one exact pnpm packageManager version.");
  return match[1];
}

export function compareInstalledGraph(scope, installedItems) {
  const expected = new Map(scope.artifacts.map((artifact) => [artifact.canonicalName, artifact.version]));
  const installed = new Map();
  for (const item of installedItems) {
    const name = String(item?.name ?? "").toLowerCase().replaceAll(/[-_.]+/g, "-");
    const version = String(item?.version ?? "");
    if (name === "pip") continue;
    if (!name || !version || installed.has(name)) fail("pip list returned invalid or duplicate installed metadata.");
    installed.set(name, version);
  }
  const missing = [...expected.keys()].filter((name) => !installed.has(name)).sort();
  const unexpected = [...installed.keys()].filter((name) => !expected.has(name)).sort();
  const mismatched = [...expected.entries()].filter(([name, version]) => installed.has(name) && installed.get(name) !== version);
  if (missing.length || unexpected.length || mismatched.length || expected.size !== installed.size) {
    fail(`Installed ${scope.id} graph differs from its lock. Missing: ${missing.join(", ") || "(none)"}; unexpected: ${unexpected.join(", ") || "(none)"}; mismatched: ${mismatched.map(([name, version]) => `${name}!=${version}`).join(", ") || "(none)"}.`);
  }
  return { expectedCount: expected.size, installedCount: installed.size };
}

function provisionBuildEnvironment({ basePython, checkout, environment, manifest }) {
  const scope = manifest.scopes["desktop-build"];
  const stateRoot = assertRepositoryChild(checkout, join(checkout, ".desktop-build", "clean-gate-python"), "Python state root");
  const wheelhouse = join(stateRoot, "desktop-build-wheelhouse");
  const hashedRequirements = join(stateRoot, "desktop-build-requirements.txt");
  const virtualEnvironment = join(stateRoot, "desktop-build-venv");
  ensureSafeDirectory(checkout, stateRoot);
  ensureSafeDirectory(checkout, wheelhouse);
  writeFileSync(hashedRequirements, renderHashedRequirements(scope), { encoding: "utf8", flag: "wx" });
  run(basePython, [
    "-m", "pip", "--isolated", "download", "--disable-pip-version-check", "--no-cache-dir", "--only-binary=:all:", "--no-deps",
    "--require-hashes", "--requirement", hashedRequirements, "--dest", wheelhouse, "--index-url", manifest.source.indexUrl,
  ], { cwd: checkout, env: environment, redactions: [basePython, wheelhouse, hashedRequirements] });
  const artifacts = verifyWheelhouse(scope, wheelhouse);
  run(basePython, ["-m", "venv", virtualEnvironment], { cwd: checkout, env: environment, redactions: [basePython, virtualEnvironment] });
  const environmentPython = join(virtualEnvironment, "Scripts", "python.exe");
  const environmentIdentity = runJson(environmentPython, [
    "-c",
    "import json, platform, struct, sys; print(json.dumps({'executable': sys.executable, 'prefix': sys.prefix, 'base_prefix': sys.base_prefix, 'implementation': sys.implementation.name, 'version': platform.python_version(), 'platform': sys.platform, 'bits': struct.calcsize('P') * 8, 'machine': platform.machine()}))",
  ], { cwd: checkout, env: environment, redactions: [environmentPython, virtualEnvironment] });
  if (realpathSync.native(environmentIdentity.executable).toLowerCase() !== realpathSync.native(environmentPython).toLowerCase()
      || resolve(environmentIdentity.prefix).toLowerCase() !== resolve(virtualEnvironment).toLowerCase()
      || resolve(environmentIdentity.prefix).toLowerCase() === resolve(environmentIdentity.base_prefix).toLowerCase()) {
    fail("Disposable desktop-build interpreter identity does not match its new virtual environment.");
  }
  assertWindowsReleasePythonIdentity(environmentIdentity);
  run(environmentPython, [
    "-m", "pip", "--isolated", "install", "--disable-pip-version-check", "--no-cache-dir", "--no-index", "--no-deps",
    "--require-hashes", "--find-links", wheelhouse, "--requirement", hashedRequirements,
  ], { cwd: checkout, env: environment, redactions: [environmentPython, wheelhouse, hashedRequirements] });
  run(environmentPython, ["-m", "pip", "--isolated", "check"], { cwd: checkout, env: environment, redactions: [environmentPython] });
  const installed = runJson(environmentPython, ["-m", "pip", "--isolated", "list", "--format=json", "--disable-pip-version-check"], {
    cwd: checkout, env: environment, redactions: [environmentPython],
  });
  const graph = compareInstalledGraph(scope, installed);
  const pyinstallerVersion = runText(environmentPython, ["-m", "PyInstaller", "--version"], { cwd: checkout, env: environment, redactions: [environmentPython] });
  if (pyinstallerVersion !== "6.21.0") fail(`Disposable build environment has PyInstaller ${pyinstallerVersion}; expected 6.21.0.`);
  return { ...graph, pipCheck: "PASS", pyinstallerVersion, artifacts };
}

function runCleanCheckout({ checkout, python, git, pnpm, cargo, environment, commit }) {
  const frontend = join(checkout, frontendRelative);
  const isolatedRoot = join(checkout, ".desktop-build");
  ensureSafeDirectory(checkout, isolatedRoot);
  writeFileSync(join(isolatedRoot, "empty-npmrc"), "", { encoding: "utf8", flag: "wx" });
  const manifest = loadPythonArtifactManifest(checkout);
  const before = gitState(git, checkout, environment);
  assertCleanState(before, "Disposable committed checkout", commit);
  const pnpmLock = join(frontend, "pnpm-lock.yaml");
  const pnpmLockBefore = sha256(pnpmLock);

  const pnpmVersion = runText(pnpm.command, [...pnpm.prefixArgs, "--version"], { cwd: frontend, env: environment });
  const requiredPnpm = expectedPnpmVersion(checkout);
  if (pnpmVersion !== requiredPnpm) fail(`Resolved pnpm ${pnpmVersion} differs from packageManager pnpm@${requiredPnpm}.`);
  run(pnpm.command, [
    ...pnpm.prefixArgs, "install", "--frozen-lockfile", "--verify-store-integrity",
    "--store-dir", join(checkout, ".desktop-build", "pnpm-store"),
    "--cache-dir", join(checkout, ".desktop-build", "pnpm-cache"),
    "--state-dir", join(checkout, ".desktop-build", "pnpm-state"),
  ], { cwd: frontend, env: environment });
  if (sha256(pnpmLock) !== pnpmLockBefore) fail("Frozen pnpm provisioning modified pnpm-lock.yaml.");

  run(cargo, ["fetch", "--locked", "--manifest-path", join(frontend, "src-tauri", "Cargo.toml"), "--target", "x86_64-pc-windows-msvc"], {
    cwd: checkout, env: environment,
  });

  const build = provisionBuildEnvironment({ basePython: python, checkout, environment, manifest });
  run(process.execPath, [join(checkout, "scripts", "release", "validate-python-runtime-inventory.mjs"), "--python", python, "--environment", join(checkout, ".desktop-build", "runtime-inventory-venv")], {
    cwd: checkout, env: environment, redactions: [python],
  });
  run(pnpm.command, [...pnpm.prefixArgs, "run", "validate:production-dependencies"], { cwd: frontend, env: environment });
  run(pnpm.command, [...pnpm.prefixArgs, "run", "build"], { cwd: frontend, env: environment });
  run(pnpm.command, [...pnpm.prefixArgs, "run", "desktop:backend:plan"], { cwd: frontend, env: environment });
  run(pnpm.command, [...pnpm.prefixArgs, "run", "test:release-signing"], { cwd: frontend, env: environment });
  run(process.execPath, ["--test", ...testFiles.map((path) => join(checkout, path))], { cwd: checkout, env: environment });
  run(process.execPath, [join(checkout, "scripts", "release", "validate-v1-readiness-audit.mjs")], { cwd: checkout, env: environment });
  run(git, ["diff", "--check"], { cwd: checkout, env: environment });

  const after = gitState(git, checkout, environment);
  assertSameState(before, after, "Disposable committed checkout");
  return {
    commit,
    runtimeContract: WINDOWS_RELEASE_PYTHON,
    pnpm: { version: pnpmVersion, frozenLockfile: "PASS", isolatedStore: true, lockSha256: pnpmLockBefore },
    python: {
      artifactManifestSha256: manifest.sha256,
      source: manifest.source,
      runtime: {
        lockSha256: manifest.scopes["backend-runtime"].lockSha256,
        expectedCount: manifest.scopes["backend-runtime"].artifacts.length,
        installedCount: manifest.scopes["backend-runtime"].artifacts.length,
        pipCheck: "PASS",
        inventory: "PASS",
        documentationVersion: "PASS",
        artifacts: manifest.scopes["backend-runtime"].artifacts.map(({ filename, sha256: digest }) => ({ filename, sha256: digest })),
      },
      buildLockSha256: manifest.scopes["desktop-build"].lockSha256,
      build,
    },
    cargo: { lockedFetch: "PASS", isolatedHome: true },
    validation: {
      productionDependencies: "PASS",
      runtimeInventory: "PASS",
      currentDocumentationVersion: "PASS",
      frontendBuild: "PASS",
      backendDryRunPlan: "PASS",
      releaseSigningTests: "PASS",
      focusedReleaseTests: "PASS",
      readiness: "PASS",
      gitDiffCheck: "PASS",
    },
    cleanCheckout: { headUnchanged: true, statusEmpty: true, workingDiffEmpty: true, cachedDiffEmpty: true },
  };
}

export function validateCleanEnvironment(argv = process.argv.slice(2)) {
  const options = parseCleanEnvironmentArguments(argv);
  const hostEnvironment = minimalEnvironment(process.env, {
    PIP_DISABLE_PIP_VERSION_CHECK: "1",
    PIP_CONFIG_FILE: "NUL",
    PIP_NO_INPUT: "1",
    PYTHONNOUSERSITE: "1",
    PYTHONDONTWRITEBYTECODE: "1",
  });
  const pythonIdentity = inspectReleasePython(options.python, hostEnvironment);
  const git = resolveToolExecutable("git.exe", process.env, { forbiddenRoot: repository });
  const pnpm = resolvePnpmInvocation(process.env, { forbiddenRoot: repository });
  const cargo = resolveToolExecutable("cargo.exe", process.env, { forbiddenRoot: repository });
  const primaryBefore = gitState(git, repository, hostEnvironment);
  assertCleanState(primaryBefore, "Primary repository");
  const commit = primaryBefore.head;
  const runRoot = assertSafePath(repository, join(repository, ".desktop-build", `clean-environment-gate-${process.pid}`));
  const checkout = join(runRoot, "checkout");
  if (existsSync(runRoot)) fail(`Disposable gate root already exists: ${privacySafePath(runRoot)}`);
  let worktreeRegistered = false;
  let cleanupError;
  let summary;
  try {
    ensureSafeDirectory(repository, runRoot);
    run(git, ["worktree", "add", "--detach", checkout, commit], { cwd: repository, env: hostEnvironment, redactions: [checkout] });
    worktreeRegistered = true;
    const environment = minimalEnvironment(process.env, {
      CARGO_HOME: join(checkout, ".desktop-build", "cargo-home"),
      CARGO_TARGET_DIR: join(checkout, ".desktop-build", "cargo-target"),
      NPM_CONFIG_CACHE: join(checkout, ".desktop-build", "npm-cache"),
      NPM_CONFIG_GLOBALCONFIG: "NUL",
      NPM_CONFIG_REGISTRY: "https://registry.npmjs.org/",
      NPM_CONFIG_USERCONFIG: join(checkout, ".desktop-build", "empty-npmrc"),
      PIP_DISABLE_PIP_VERSION_CHECK: "1",
      PIP_CONFIG_FILE: "NUL",
      PIP_NO_INPUT: "1",
      PYTHONNOUSERSITE: "1",
      PYTHONDONTWRITEBYTECODE: "1",
    });
    summary = runCleanCheckout({ checkout, python: pythonIdentity.executable, git, pnpm, cargo, environment, commit });
  } finally {
    if (worktreeRegistered) {
      try { run(git, ["worktree", "remove", "--force", checkout], { cwd: repository, env: hostEnvironment, redactions: [checkout], visible: false }); } catch (error) {
        cleanupError = new Error(`Disposable worktree cleanup failed: ${sanitizeDiagnosticText(error.message, [checkout])}`);
      }
    }
    if (!cleanupError && existsSync(runRoot)) {
      try { removeSafeTree(repository, runRoot); } catch (error) { cleanupError = error; }
    }
  }
  if (cleanupError) throw cleanupError;
  const primaryAfter = gitState(git, repository, hostEnvironment);
  assertSameState(primaryBefore, primaryAfter, "Primary repository");
  const result = {
    gate: "PASS",
    ...summary,
    selectedPython: {
      implementation: pythonIdentity.implementation,
      version: pythonIdentity.version,
      platform: pythonIdentity.platform,
      bits: pythonIdentity.bits,
      machine: pythonIdentity.machine,
    },
    primaryRepository: { headUnchanged: true, statusEmpty: true, workingDiffEmpty: true, cachedDiffEmpty: true },
    cleanup: { worktree: "removed", environments: "removed", wheelhouses: "removed", storesAndBuildOutputs: "removed" },
  };
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  return result;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(scriptPath)) {
  try { validateCleanEnvironment(); } catch (error) { process.stderr.write(`${sanitizeDiagnosticText(error.message)}\n`); process.exitCode = 1; }
}
