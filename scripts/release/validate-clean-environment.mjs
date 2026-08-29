import { createWriteStream, copyFileSync, cpSync, existsSync, lstatSync, readFileSync, realpathSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { get as httpsGet } from "node:https";
import { createHash } from "node:crypto";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  DESKTOP_BUILD_ROOT,
  assertSafePath,
  assertNoNodeRuntimeInjection,
  ensureSafeDirectory,
  minimalEnvironment,
  privacySafePath,
  resolveToolExecutable,
  runCommand,
  sanitizeDiagnosticText,
  sha256,
  validateAuthorizedSigningEnvironment,
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
import { assertReleaseInputTree, releaseInputTreeReceipt } from "./release-input-provenance.mjs";
import {
  assertAuthenticatedReleaseTool,
  assertCurrentReleaseAuthority,
  authenticateReleaseTools,
  loadReleaseAuthority,
  releaseToolEnvironment,
} from "./release-authority.mjs";

const scriptPath = fileURLToPath(import.meta.url);
const repository = resolve(dirname(scriptPath), "..", "..");
const frontendRelative = "frontend";
const CANONICAL_WORKER_ARGUMENT = "--glacial-canonical-release-worker";
export const PINNED_PNPM = Object.freeze({
  version: "11.16.0",
  url: "https://registry.npmjs.org/pnpm/-/pnpm-11.16.0.tgz",
  integrity: "sha512-t2fpqY/IeuwPQtrvzQ6ElBws20XXPE4eaIYPsr39vgMqtZIQVHnl4Fwjf3QMil/9u7UjhXl93CKWdFobu4g+jQ==",
  shasum: "fc0b55d90c04ed8a7c3e37659cc72c188028f6f1",
});
const testFiles = [
  "scripts/release/release-contract.test.mjs",
  "scripts/release/python-artifact-integrity.test.mjs",
  "scripts/release/release-input-provenance.test.mjs",
  "scripts/release/release-authority.test.mjs",
  "scripts/release/validate-clean-environment.test.mjs",
  "scripts/release/validate-python-runtime-inventory.test.mjs",
  "scripts/release/validate-production-dependencies.test.mjs",
  "scripts/release/generate-third-party-inventory.test.mjs",
  "scripts/desktop/Signer-Preflight.test.mjs",
];

function fail(message) {
  throw new Error(message);
}

export function prepareViteConfigScratch(nodeModules) {
  const root = resolve(nodeModules);
  const scratch = join(root, ".vite-temp");
  if (existsSync(scratch)) {
    const metadata = lstatSync(scratch);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()
        || realpathSync.native(scratch).toLowerCase() !== scratch.toLowerCase()
        || readdirSync(scratch).length !== 0) {
      fail("Vite config scratch must be an empty normal directory before authentication.");
    }
  } else {
    ensureSafeDirectory(root, scratch);
  }
  return scratch;
}

export function parseCleanEnvironmentArguments(argv) {
  let python;
  let profile = null;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--python") {
      if (python !== undefined) fail("--python may be provided only once.");
      python = argv[index + 1];
      if (!python || python.startsWith("--")) fail("--python requires an executable path.");
      index += 1;
    } else if (argument === "--profile") {
      if (profile !== null) fail("--profile may be provided only once.");
      profile = argv[index + 1];
      if (!new Set(["signed-preview", "public-rc"]).has(profile)) fail("--profile requires signed-preview or public-rc.");
      index += 1;
    } else {
      fail(`Unknown clean-environment gate argument: ${argument}`);
    }
  }
  if (!python) fail("--python is required; the clean-environment gate never selects an interpreter implicitly.");
  return { python: resolve(python), profile };
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

function downloadPinnedArtifact(url, destination) {
  return new Promise((resolveDownload, rejectDownload) => {
    const request = httpsGet(url, { headers: { "user-agent": "Glacial-release-provenance/1" } }, (response) => {
      if (response.statusCode !== 200) {
        response.resume();
        rejectDownload(new Error(`Pinned artifact download returned HTTP ${response.statusCode ?? "unknown"}.`));
        return;
      }
      const output = createWriteStream(destination, { flags: "wx" });
      const failDownload = (error) => { output.destroy(); rejectDownload(error); };
      response.once("error", failDownload);
      output.once("error", failDownload);
      output.once("finish", () => output.close(() => resolveDownload()));
      response.pipe(output);
    });
    request.once("error", rejectDownload);
  });
}

function validateArchiveListing(listing) {
  const entries = String(listing).split(/\r?\n/).filter(Boolean);
  if (!entries.length) fail("Pinned archive is empty.");
  for (const entry of entries) {
    const normalized = entry.replace(/\/$/, "");
    if (!normalized || normalized.includes("\\") || normalized.startsWith("/")
        || /^[A-Za-z]:/.test(normalized) || normalized.split("/").includes("..")) {
      fail("Pinned archive contains an unsafe path.");
    }
  }
}

function extractPinnedArchive({ tar, archive, destination, checkout, environment }) {
  validateArchiveListing(runText(tar, ["-tf", archive], { cwd: checkout, env: environment, redactions: [archive, destination] }));
  ensureSafeDirectory(checkout, destination);
  run(tar, ["-xf", archive, "-C", destination], { cwd: checkout, env: environment, redactions: [archive, destination] });
}

function assertPinnedBaseDistribution(path, distribution) {
  if (!existsSync(path) || statSync(path).size !== distribution.bytes
      || sha256(path).toLowerCase() !== distribution.sha256) {
    fail("Python base distribution differs from the repository-pinned Python.org artifact.");
  }
}

function fileDigest(path, algorithm, encoding) {
  return createHash(algorithm).update(readFileSync(path)).digest(encoding);
}

function assertPinnedPnpmArchive(path) {
  const sha512 = `sha512-${fileDigest(path, "sha512", "base64")}`;
  if (sha512 !== PINNED_PNPM.integrity || fileDigest(path, "sha1", "hex") !== PINNED_PNPM.shasum) {
    fail("Downloaded pnpm tool differs from repository-pinned npm registry identities.");
  }
}

function provisionPinnedPnpm({ checkout, isolatedRoot, tar, environment }) {
  const archive = join(isolatedRoot, `pnpm-${PINNED_PNPM.version}.tgz`);
  const root = join(isolatedRoot, "pnpm-tool");
  return downloadPinnedArtifact(PINNED_PNPM.url, archive).then(() => {
    assertPinnedPnpmArchive(archive);
    extractPinnedArchive({ tar, archive, destination: root, checkout, environment });
    assertPinnedPnpmArchive(archive);
    const packageRoot = join(root, "package");
    const cli = join(packageRoot, "bin", "pnpm.cjs");
    if (!existsSync(cli) || !lstatSync(cli).isFile() || lstatSync(cli).isSymbolicLink()) fail("Pinned pnpm archive lacks its expected CLI.");
    const receipt = releaseInputTreeReceipt(packageRoot, "pnpm-tool");
    return { archive, root: packageRoot, cli, receipt };
  });
}

function mergeWheelData(checkout, environmentRoot, sitePackages) {
  for (const name of readdirSync(sitePackages).filter((entry) => entry.endsWith(".data"))) {
    const dataRoot = join(sitePackages, name);
    const targets = {
      purelib: sitePackages,
      platlib: sitePackages,
      scripts: join(environmentRoot, "Scripts"),
      data: environmentRoot,
      headers: join(environmentRoot, "Include"),
    };
    if (readdirSync(dataRoot).some((kind) => !(kind in targets))) fail("Wheel contains an unsupported data installation category.");
    for (const [kind, targetRoot] of Object.entries(targets)) {
      const source = join(dataRoot, kind);
      if (!existsSync(source)) continue;
      ensureSafeDirectory(checkout, targetRoot);
      for (const child of readdirSync(source)) {
        const destination = join(targetRoot, child);
        if (existsSync(destination)) fail("Wheel data extraction would overwrite an installed path.");
        renameSync(join(source, child), destination);
      }
    }
    removeDisposableTree(checkout, dataRoot);
  }
}

export function inspectReleasePython(python, environment = minimalEnvironment(process.env)) {
  const selectedPython = typeof python === "string" ? python : assertAuthenticatedReleaseTool(python);
  if (!isAbsolute(selectedPython) || !existsSync(selectedPython) || !lstatSync(selectedPython).isFile() || lstatSync(selectedPython).isSymbolicLink()) {
    fail(`--python must identify a real absolute executable file: ${privacySafePath(selectedPython)}`);
  }
  const canonicalPython = realpathSync.native(selectedPython);
  const identity = runJson(typeof python === "string" ? canonicalPython : python, [
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

export function removeDisposableTree(root, target) {
  const safeTarget = assertSafePath(root, target);
  if (!existsSync(safeTarget)) return false;
  if (lstatSync(safeTarget).isSymbolicLink()) fail("Disposable cleanup root must not be a symbolic link or junction.");
  rmSync(safeTarget, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  if (existsSync(safeTarget)) fail("Disposable cleanup target still exists after removal.");
  return true;
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

function reconstructPythonEnvironment({ checkout, environment, manifest, scopeId, virtualEnvironment, baseArchive, wheelhouse, tar }) {
  const scope = manifest.scopes[scopeId];
  if (!scope) fail(`Python artifact manifest is missing scope ${scopeId}.`);
  const artifacts = verifyWheelhouse(scope, wheelhouse);
  assertPinnedBaseDistribution(baseArchive, manifest.baseDistribution);
  extractPinnedArchive({ tar, archive: baseArchive, destination: virtualEnvironment, checkout, environment });
  const sitePackages = join(virtualEnvironment, "Lib", "site-packages");
  ensureSafeDirectory(checkout, sitePackages);
  for (const artifact of scope.artifacts) extractPinnedArchive({ tar, archive: join(wheelhouse, artifact.filename), destination: sitePackages, checkout, environment });
  mergeWheelData(checkout, virtualEnvironment, sitePackages);
  writeFileSync(join(virtualEnvironment, "python313._pth"), "python313.zip\n.\nLib/site-packages\nimport site\n", { encoding: "utf8" });
  const environmentPython = join(virtualEnvironment, "python.exe");
  const environmentIdentity = runJson(environmentPython, [
    "-c",
    "import json, platform, struct, sys, sysconfig; print(json.dumps({'executable': sys.executable, 'prefix': sys.prefix, 'base_prefix': sys.base_prefix, 'implementation': sys.implementation.name, 'version': platform.python_version(), 'platform': sys.platform, 'bits': struct.calcsize('P') * 8, 'machine': platform.machine(), 'site_packages': sysconfig.get_path('purelib')}))",
  ], { cwd: checkout, env: environment, redactions: [environmentPython, virtualEnvironment] });
  if (realpathSync.native(environmentIdentity.executable).toLowerCase() !== realpathSync.native(environmentPython).toLowerCase()
      || resolve(environmentIdentity.prefix).toLowerCase() !== resolve(virtualEnvironment).toLowerCase()
      || resolve(environmentIdentity.base_prefix).toLowerCase() !== resolve(virtualEnvironment).toLowerCase()
      || resolve(environmentIdentity.site_packages).toLowerCase() !== resolve(sitePackages).toLowerCase()) fail("Authenticated embedded interpreter identity does not match its disposable environment.");
  assertWindowsReleasePythonIdentity(environmentIdentity);
  const installed = runJson(environmentPython, ["-c", "import importlib.metadata as m, json; print(json.dumps([{'name': d.metadata['Name'], 'version': d.version} for d in m.distributions()]))"], { cwd: checkout, env: environment, redactions: [environmentPython] });
  const graph = compareInstalledGraph(scope, installed);
  const pyinstallerVersion = scopeId === "desktop-build" ? runText(environmentPython, ["-m", "PyInstaller", "--version"], { cwd: checkout, env: environment, redactions: [environmentPython] }) : null;
  if (scopeId === "desktop-build" && pyinstallerVersion !== "6.21.0") fail(`Disposable build environment has PyInstaller ${pyinstallerVersion}; expected 6.21.0.`);
  const label = scopeId === "desktop-build" ? "python-build-environment" : "python-runtime-environment";
  return { ...graph, importGraph: "PASS", pyinstallerVersion, artifacts, root: virtualEnvironment, python: environmentPython, sitePackages: environmentIdentity.site_packages, receipt: releaseInputTreeReceipt(virtualEnvironment, label) };
}

function provisionPythonEnvironment({ basePython, checkout, environment, manifest, scopeId, virtualEnvironment, baseArchive, tar }) {
  const scope = manifest.scopes[scopeId];
  if (!scope) fail(`Python artifact manifest is missing scope ${scopeId}.`);
  const stateRoot = assertRepositoryChild(checkout, join(checkout, ".desktop-build", `p-${scopeId}`), "Python state root");
  const wheelhouse = join(stateRoot, "w");
  const hashedRequirements = join(stateRoot, "requirements.txt");
  assertRepositoryChild(checkout, virtualEnvironment, `${scopeId} virtual environment`);
  ensureSafeDirectory(checkout, stateRoot);
  ensureSafeDirectory(checkout, wheelhouse);
  writeFileSync(hashedRequirements, renderHashedRequirements(scope), { encoding: "utf8", flag: "wx" });
  run(basePython, [
    "-m", "pip", "--isolated", "download", "--disable-pip-version-check", "--no-cache-dir", "--only-binary=:all:", "--no-deps",
    "--require-hashes", "--requirement", hashedRequirements, "--dest", wheelhouse, "--index-url", manifest.source.indexUrl,
  ], { cwd: checkout, env: environment, redactions: [basePython, wheelhouse, hashedRequirements] });
  return reconstructPythonEnvironment({ checkout, environment, manifest, scopeId, virtualEnvironment, baseArchive, wheelhouse, tar });
}

export function verifyPreparedInputsByReconstruction({ checkout, preparedInputs, tar, cargo, environment }) {
  const manifest = loadPythonArtifactManifest(checkout);
  const isolatedRoot = join(checkout, ".desktop-build");
  const reconstruction = join(isolatedRoot, "independent-reconstruction");
  if (existsSync(reconstruction)) fail("Independent reconstruction root already exists.");
  ensureSafeDirectory(checkout, reconstruction);
  try {
    assertPinnedPnpmArchive(preparedInputs.pnpmTool.archive);
    const pnpmRoot = join(reconstruction, "pnpm-tool");
    extractPinnedArchive({ tar, archive: preparedInputs.pnpmTool.archive, destination: pnpmRoot, checkout, environment });
    const reconstructedPnpmRoot = join(pnpmRoot, "package");
    const reconstructedPnpmReceipt = releaseInputTreeReceipt(reconstructedPnpmRoot, "pnpm-tool");
    if (JSON.stringify(reconstructedPnpmReceipt) !== JSON.stringify(preparedInputs.pnpmTool.receipt)) fail("Prepared pnpm tool differs from the independently reconstructed pinned tool.");
    const pnpmCli = join(reconstructedPnpmRoot, "bin", "pnpm.cjs");

    const frontend = join(reconstruction, "frontend");
    ensureSafeDirectory(checkout, frontend);
    for (const name of ["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"]) copyFileSync(join(checkout, "frontend", name), join(frontend, name));
    run(process.execPath, [pnpmCli, "install", "--frozen-lockfile", "--verify-store-integrity", "--store-dir", join(reconstruction, "pnpm-store"), "--cache-dir", join(reconstruction, "pnpm-cache")], { cwd: frontend, env: environment });
    prepareViteConfigScratch(join(frontend, "node_modules"));
    const nodeReceipt = releaseInputTreeReceipt(join(frontend, "node_modules"), "node-modules");
    if (JSON.stringify(nodeReceipt) !== JSON.stringify(preparedInputs.node.receipt)) fail("Prepared node_modules differs from an independent frozen reconstruction.");

    const baseArchive = join(isolatedRoot, manifest.baseDistribution.filename);
    for (const [scopeId, prepared, name] of [
      ["desktop-build", preparedInputs.buildPython, "python-build"],
      ["backend-runtime", preparedInputs.runtimePython, "python-runtime"],
    ]) {
      const rebuilt = reconstructPythonEnvironment({
        checkout, environment, manifest, scopeId, virtualEnvironment: join(reconstruction, name), baseArchive,
        wheelhouse: join(isolatedRoot, `p-${scopeId}`, "w"), tar,
      });
      if (JSON.stringify(rebuilt.receipt) !== JSON.stringify(prepared.receipt)) fail(`Prepared ${scopeId} tree differs from independent authenticated reconstruction.`);
    }

    const cargoRoot = join(reconstruction, "cargo-home");
    const cargoEnvironment = minimalEnvironment(environment, { CARGO_HOME: cargoRoot, CARGO_NET_OFFLINE: "false" }, ["CARGO_HOME"]);
    run(cargo, ["fetch", "--locked", "--manifest-path", join(checkout, "frontend", "src-tauri", "Cargo.toml"), "--target", "x86_64-pc-windows-msvc"], { cwd: checkout, env: cargoEnvironment });
    const cargoReceipt = releaseInputTreeReceipt(cargoRoot, "cargo-home");
    if (JSON.stringify(cargoReceipt) !== JSON.stringify(preparedInputs.cargo.receipt)) fail("Prepared Cargo home differs from independent locked reconstruction.");
    return true;
  } finally {
    if (existsSync(reconstruction)) removeDisposableTree(checkout, reconstruction);
  }
}

async function runCleanCheckout({ checkout, python, git, cargo, tar, tools, authority, environment, commit, primarySource, profile }) {
  const frontend = join(checkout, frontendRelative);
  const isolatedRoot = join(checkout, ".desktop-build");
  ensureSafeDirectory(checkout, isolatedRoot);
  writeFileSync(join(isolatedRoot, "u"), "", { encoding: "utf8", flag: "wx" });
  const manifest = loadPythonArtifactManifest(checkout);
  const pnpmTool = await provisionPinnedPnpm({ checkout, isolatedRoot, tar, environment });
  const pnpm = { command: process.execPath, prefixArgs: [pnpmTool.cli] };
  const baseArchive = join(isolatedRoot, manifest.baseDistribution.filename);
  await downloadPinnedArtifact(manifest.baseDistribution.url, baseArchive);
  assertPinnedBaseDistribution(baseArchive, manifest.baseDistribution);
  const before = gitState(git, checkout, environment);
  assertCleanState(before, "Disposable committed checkout", commit);
  const pnpmLock = join(frontend, "pnpm-lock.yaml");
  const pnpmLockBefore = sha256(pnpmLock);

  const pnpmVersion = runText(pnpm.command, [...pnpm.prefixArgs, "--version"], { cwd: frontend, env: environment });
  const requiredPnpm = expectedPnpmVersion(checkout);
  if (pnpmVersion !== requiredPnpm) fail(`Resolved pnpm ${pnpmVersion} differs from packageManager pnpm@${requiredPnpm}.`);
  run(pnpm.command, [
    ...pnpm.prefixArgs, "install", "--frozen-lockfile", "--verify-store-integrity",
    "--store-dir", join(checkout, ".desktop-build", "s"),
    "--cache-dir", join(checkout, ".desktop-build", "k"),
  ], { cwd: frontend, env: environment });
  if (sha256(pnpmLock) !== pnpmLockBefore) fail("Frozen pnpm provisioning modified pnpm-lock.yaml.");
  prepareViteConfigScratch(join(frontend, "node_modules"));
  const nodeReceipt = releaseInputTreeReceipt(join(frontend, "node_modules"), "node-modules");

  run(cargo, ["fetch", "--locked", "--manifest-path", join(frontend, "src-tauri", "Cargo.toml"), "--target", "x86_64-pc-windows-msvc"], {
    cwd: checkout, env: environment,
  });
  const cargoRoot = join(checkout, ".desktop-build", "c");
  const cargoReceipt = releaseInputTreeReceipt(cargoRoot, "cargo-home");

  const build = provisionPythonEnvironment({
    basePython: python, checkout, environment, manifest, scopeId: "desktop-build",
    virtualEnvironment: join(checkout, ".desktop-build", "venv"), baseArchive, tar,
  });
  const runtime = provisionPythonEnvironment({
    basePython: python, checkout, environment, manifest, scopeId: "backend-runtime",
    virtualEnvironment: join(checkout, "backend", ".venv"), baseArchive, tar,
  });
  run(process.execPath, [join(checkout, "scripts", "release", "validate-g051-documentation.mjs"), "--python-site-packages", runtime.sitePackages, "--python-runtime", runtime.python], {
    cwd: checkout, env: environment, redactions: [python, runtime.root],
  });
  run(pnpm.command, [...pnpm.prefixArgs, "run", "validate:production-dependencies"], { cwd: frontend, env: environment });
  run(pnpm.command, [...pnpm.prefixArgs, "run", "build"], { cwd: frontend, env: environment });
  run(pnpm.command, [...pnpm.prefixArgs, "run", "desktop:backend:plan"], { cwd: frontend, env: environment });
  run(pnpm.command, [...pnpm.prefixArgs, "run", "test:release-signing"], { cwd: frontend, env: environment });
  run(process.execPath, ["--test", ...testFiles.map((path) => join(checkout, path))], { cwd: checkout, env: environment });
  run(process.execPath, [join(checkout, "scripts", "release", "validate-v1-readiness-audit.mjs")], { cwd: checkout, env: environment });
  run(git, ["diff", "--check"], { cwd: checkout, env: environment });
  assertReleaseInputTree(join(frontend, "node_modules"), nodeReceipt);
  assertReleaseInputTree(build.root, build.receipt);
  assertReleaseInputTree(runtime.root, runtime.receipt);
  assertReleaseInputTree(cargoRoot, cargoReceipt);

  const preparedInputs = {
    schemaVersion: 1,
    source: primarySource,
    releaseAuthority: profile ? {
      schemaVersion: authority.schemaVersion,
      authorityId: authority.authorityId,
      digest: authority.digest,
      authorization: authority.authorization,
      source: authority.source,
      signing: authority.signing,
    } : null,
    node: { root: join(frontend, "node_modules"), receipt: nodeReceipt },
    buildPython: { root: build.root, receipt: build.receipt },
    runtimePython: { root: runtime.root, receipt: runtime.receipt },
    cargo: { root: cargoRoot, receipt: cargoReceipt },
    pnpmTool,
    provenance: {
      schemaVersion: 1,
      sourceCommit: commit,
      pnpm: { version: pnpmVersion, lockSha256: pnpmLockBefore, toolIntegrity: PINNED_PNPM.integrity, frozenLockfile: true, verifyStoreIntegrity: true, isolatedStore: true },
      python: {
        artifactManifestSha256: manifest.sha256,
        baseDistribution: manifest.baseDistribution,
        source: manifest.source,
        buildLockSha256: manifest.scopes["desktop-build"].lockSha256,
        runtimeLockSha256: manifest.scopes["backend-runtime"].lockSha256,
        buildArtifacts: build.artifacts,
        runtimeArtifacts: runtime.artifacts,
      },
      cargo: { lockedFetch: true, isolatedHome: true },
      executedInputTrees: {},
    },
  };
  preparedInputs.provenance.executedInputTrees = {
    node: preparedInputs.node.receipt,
    buildPython: preparedInputs.buildPython.receipt,
    runtimePython: preparedInputs.runtimePython.receipt,
    cargo: preparedInputs.cargo.receipt,
    pnpmTool: preparedInputs.pnpmTool.receipt,
  };

  let signedRelease = null;
  if (profile) {
    const module = await import(pathToFileURL(join(checkout, "scripts", "desktop", "Build-SignedWindowsRelease.mjs")).href);
    const built = await module.buildSignedRelease(profile, preparedInputs);
    assertReleaseInputTree(built.releaseCandidate, built.candidateReceipt);
    const destination = assertSafePath(DESKTOP_BUILD_ROOT, join(DESKTOP_BUILD_ROOT, "release-candidates", basename(built.releaseCandidate)));
    const staging = assertSafePath(DESKTOP_BUILD_ROOT, `${destination}.copying`);
    if (existsSync(destination) || existsSync(staging)) fail("Primary release candidate destination or staging path already exists.");
    ensureSafeDirectory(DESKTOP_BUILD_ROOT, dirname(destination));
    let published = false;
    try {
      assertCurrentReleaseAuthority(authority, { profile });
      cpSync(built.releaseCandidate, staging, { recursive: true, errorOnExist: true, force: false });
      assertReleaseInputTree(staging, built.candidateReceipt);
      module.verifyPublishedHashes(staging, join(staging, "release-candidate-manifest.json"), join(staging, "SHA256SUMS.txt"));
      assertCurrentReleaseAuthority(authority, { profile });
      if (existsSync(destination)) fail("Primary release candidate destination appeared during verified copy.");
      renameSync(staging, destination);
      published = true;
      assertReleaseInputTree(destination, built.candidateReceipt);
      module.verifyPublishedHashes(destination, join(destination, "release-candidate-manifest.json"), join(destination, "SHA256SUMS.txt"));
      assertCurrentReleaseAuthority(authority, { profile });
    } catch (error) {
      if (published && existsSync(destination) && !existsSync(staging)) renameSync(destination, staging);
      throw error;
    } finally {
      if (existsSync(staging)) removeDisposableTree(DESKTOP_BUILD_ROOT, staging);
    }
    signedRelease = { profile, candidate: destination, manifest: join(destination, "release-candidate-manifest.json"), sha256Sums: join(destination, "SHA256SUMS.txt") };
  }

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
        importGraph: "PASS",
        inventory: "PASS",
        documentationVersion: "PASS",
        artifacts: runtime.artifacts,
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
    signedRelease,
  };
}

export async function validateCleanEnvironment(argv = process.argv.slice(2)) {
  assertNoNodeRuntimeInjection(process.env);
  const options = parseCleanEnvironmentArguments(argv);
  const hostEnvironment = minimalEnvironment(process.env, {
    PIP_DISABLE_PIP_VERSION_CHECK: "1",
    PIP_CONFIG_FILE: "NUL",
    PIP_NO_INPUT: "1",
    PYTHONNOUSERSITE: "1",
    PYTHONDONTWRITEBYTECODE: "1",
  });
  let authority = null;
  let tools = null;
  if (options.profile) {
    authority = loadReleaseAuthority(process.env, {
      repository,
    });
    tools = authenticateReleaseTools(authority, { node: process.execPath, python: options.python });
    validateAuthorizedSigningEnvironment(process.env, { authority, tools, profile: options.profile });
  }
  const python = tools?.python ?? options.python;
  const git = tools?.git ?? resolveToolExecutable("git.exe", process.env, { forbiddenRoot: repository });
  const cargo = tools?.cargo ?? resolveToolExecutable("cargo.exe", process.env, { forbiddenRoot: repository });
  const tar = tools?.tar ?? resolveToolExecutable("tar.exe", process.env, { forbiddenRoot: repository });
  const pythonIdentity = inspectReleasePython(python, hostEnvironment);
  const primaryBefore = gitState(git, repository, hostEnvironment);
  assertCleanState(primaryBefore, "Primary repository");
  const commit = primaryBefore.head;
  let primarySource = null;
  if (options.profile) {
    const releaseModule = await import(pathToFileURL(join(repository, "scripts", "desktop", "Build-SignedWindowsRelease.mjs")).href);
    primarySource = releaseModule.verifyReleaseSource(git, authority);
  }
  const checkout = assertSafePath(repository, join(repository, "dist"));
  if (existsSync(checkout)) fail(`Disposable gate checkout already exists: ${privacySafePath(checkout)}`);
  let worktreeRegistered = false;
  let cleanupError;
  let summary;
  try {
    run(git, ["worktree", "add", "--detach", checkout, commit], { cwd: repository, env: hostEnvironment, redactions: [checkout] });
    worktreeRegistered = true;
    let environment = minimalEnvironment(process.env, {
      CARGO_HOME: join(checkout, ".desktop-build", "c"),
      CARGO_TARGET_DIR: join(checkout, ".desktop-build", "t"),
      NPM_CONFIG_CACHE: join(checkout, ".desktop-build", "n"),
      NPM_CONFIG_GLOBALCONFIG: "NUL",
      NPM_CONFIG_REGISTRY: "https://registry.npmjs.org/",
      NPM_CONFIG_USERCONFIG: join(checkout, ".desktop-build", "u"),
      PIP_DISABLE_PIP_VERSION_CHECK: "1",
      PIP_CONFIG_FILE: "NUL",
      PIP_NO_INPUT: "1",
      PYTHONNOUSERSITE: "1",
      PYTHONDONTWRITEBYTECODE: "1",
    });
    if (tools) environment = releaseToolEnvironment(environment, tools);
    summary = await runCleanCheckout({
      checkout,
      python,
      git,
      cargo,
      tar,
      tools,
      authority,
      environment,
      commit,
      primarySource,
      profile: options.profile,
    });
  } finally {
    if (worktreeRegistered && existsSync(checkout)) {
      for (const target of [join(checkout, "frontend", "node_modules"), join(checkout, "frontend", "dist"), join(checkout, "frontend", "src-tauri", "binaries"), join(checkout, "frontend", "src-tauri", "target"), join(checkout, "backend", ".venv"), join(checkout, ".desktop-build")]) {
        try { removeDisposableTree(checkout, target); } catch (error) { cleanupError ??= error; }
      }
    }
    if (worktreeRegistered) {
      try { run(git, ["worktree", "remove", "--force", checkout], { cwd: repository, env: hostEnvironment, redactions: [checkout], visible: false }); } catch (error) {
        cleanupError ??= new Error(`Disposable worktree cleanup failed: ${sanitizeDiagnosticText(error.message, [checkout])}`);
      }
    }
    if (existsSync(checkout)) {
      try { removeDisposableTree(repository, checkout); } catch (error) { cleanupError ??= error; }
    }
    if (cleanupError) throw cleanupError;
  }
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

async function main() {
  const argv = process.argv.slice(2);
  const workerCount = argv.filter((argument) => argument === CANONICAL_WORKER_ARGUMENT).length;
  if (workerCount > 1) fail("The canonical release-worker marker may be provided only once.");
  const worker = workerCount === 1;
  const cleanArguments = argv.filter((argument) => argument !== CANONICAL_WORKER_ARGUMENT);
  const options = parseCleanEnvironmentArguments(cleanArguments);
  if (options.profile && !worker) {
    assertNoNodeRuntimeInjection(process.env);
    const environment = { ...process.env };
    for (const name of Object.keys(environment)) {
      if (new Set(["NODE_OPTIONS", "NODE_PATH"]).has(name.toUpperCase())) delete environment[name];
    }
    const result = runCommand(process.execPath, [scriptPath, CANONICAL_WORKER_ARGUMENT, ...cleanArguments], {
      cwd: repository,
      env: environment,
      timeoutMs: 3_600_000,
      includeFailureOutput: true,
    });
    if (result.stdout) process.stdout.write(sanitizeDiagnosticText(result.stdout));
    if (result.stderr) process.stderr.write(sanitizeDiagnosticText(result.stderr));
    return;
  }
  await validateCleanEnvironment(cleanArguments);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(scriptPath)) {
  main().catch((error) => { process.stderr.write(`${sanitizeDiagnosticText(error.message)}\n`); process.exitCode = 1; });
}
