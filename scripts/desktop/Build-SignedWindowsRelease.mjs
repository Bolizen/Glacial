import {
  constants,
  copyFileSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DESKTOP_BUILD_ROOT,
  assertSafeTree,
  assertSafePath,
  createTauriSigningOverlay,
  ensureSafeDirectory,
  loadSigningConfig,
  minimalEnvironment,
  preflightSigningProvider,
  removeSafeTree,
  resolveNpmInvocation,
  resolveSystemExecutable,
  resolveToolExecutable,
  runCommand,
  sha256,
  signBackendTree,
  signingEnvironment,
  verifyPayloadTree,
  verifySignature,
} from "./windows-signing.mjs";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const REPOSITORY = resolve(dirname(SCRIPT_PATH), "..", "..");
const FRONTEND = join(REPOSITORY, "frontend");
const PYINSTALLER_ROOT = join(DESKTOP_BUILD_ROOT, "pyinstaller");
const PYINSTALLER_PAYLOAD = join(PYINSTALLER_ROOT, "dist", "glacial-backend");
const SIDECAR_STAGE = join(FRONTEND, "src-tauri", "binaries");
const TAURI_TARGET = join(FRONTEND, "src-tauri", "target", "release");
const PORTABLE_ROOT = join(DESKTOP_BUILD_ROOT, "portable", "Glacial");
const RELEASE_CANDIDATES = join(DESKTOP_BUILD_ROOT, "release-candidates");
const RELEASE_WORK = join(DESKTOP_BUILD_ROOT, "release-work");
const EXPECTED_NSIS_COMPONENTS = ["NSISdl.dll", "StartMenu.dll", "System.dll", "nsDialogs.dll", "nsis_tauri_utils.dll", "uninstall.exe"];

function redact(text, secretValues = []) {
  let value = String(text ?? "");
  for (const secret of secretValues.filter((item) => typeof item === "string" && item.length > 0)) value = value.replaceAll(secret, "[REDACTED]");
  return value;
}

function runVisible(command, args, options = {}) {
  const result = runCommand(command, args, { cwd: options.cwd, env: options.env, timeoutMs: options.timeoutMs ?? 900_000 });
  const secrets = options.secretValues ?? [];
  if (result.stdout) process.stdout.write(redact(result.stdout, secrets));
  if (result.stderr) process.stderr.write(redact(result.stderr, secrets));
  return result;
}

function runText(command, args, options = {}) {
  return String(runCommand(command, args, options).stdout ?? "").trim();
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function cargoVersion(path) {
  const match = readFileSync(path, "utf8").match(/^version\s*=\s*"([^"]+)"/m);
  return match?.[1] ?? null;
}

function lockVersion(path) {
  const content = readFileSync(path, "utf8");
  const match = content.match(/\[\[package\]\]\s+name\s*=\s*"glacial"\s+version\s*=\s*"([^"]+)"/m);
  return match?.[1] ?? null;
}

export function verifyReleaseSource(gitPath) {
  const environment = minimalEnvironment(process.env);
  const root = resolve(runText(gitPath, ["rev-parse", "--show-toplevel"], { cwd: REPOSITORY, env: environment }));
  if (root.toLowerCase() !== REPOSITORY.toLowerCase()) throw new Error(`Repository root mismatch: ${root}`);
  const branch = runText(gitPath, ["branch", "--show-current"], { cwd: REPOSITORY, env: environment });
  if (branch !== "main") throw new Error(`The release branch must be main; current branch is ${branch || "detached"}.`);
  const status = runText(gitPath, ["status", "--short"], { cwd: REPOSITORY, env: environment });
  if (status) throw new Error(`The release working tree must be clean.\n${status}`);
  const commit = runText(gitPath, ["rev-parse", "HEAD"], { cwd: REPOSITORY, env: environment });
  const originMain = runText(gitPath, ["rev-parse", "origin/main"], { cwd: REPOSITORY, env: environment });
  if (commit !== originMain) throw new Error(`HEAD ${commit} does not match origin/main ${originMain}.`);

  const packageJson = readJson(join(FRONTEND, "package.json"));
  const packageLock = readJson(join(FRONTEND, "package-lock.json"));
  const tauri = readJson(join(FRONTEND, "src-tauri", "tauri.conf.json"));
  const versions = {
    packageJson: packageJson.version,
    packageLock: packageLock.version,
    packageLockRoot: packageLock.packages?.[""]?.version,
    tauri: tauri.version,
    cargo: cargoVersion(join(FRONTEND, "src-tauri", "Cargo.toml")),
    cargoLock: lockVersion(join(FRONTEND, "src-tauri", "Cargo.lock")),
  };
  for (const [name, version] of Object.entries(versions)) if (version !== "0.4.0") throw new Error(`${name} identifies version ${version ?? "unknown"}; expected 0.4.0.`);
  if (!readFileSync(join(REPOSITORY, "backend", "app", "changelog.py"), "utf8").includes('"version": "0.4.0"')) throw new Error("Backend release metadata does not identify 0.4.0.");
  return { root, branch, commit, originMain, version: "0.4.0", versions, status: "" };
}

export function assertSameReleaseSource(before, after) {
  for (const field of ["root", "branch", "commit", "originMain", "version", "status"]) {
    if (before[field] !== after[field]) throw new Error(`Release source changed during the build (${field}).`);
  }
  if (JSON.stringify(before.versions) !== JSON.stringify(after.versions)) throw new Error("Release metadata changed during the build.");
  return true;
}

function parseRequirementsLock(path) {
  return readFileSync(path, "utf8").split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#")).map((line) => line.split(/[ ;]/, 1)[0].toLowerCase().replaceAll("_", "-")).sort();
}

function installedPackages(python, environment) {
  const result = JSON.parse(runText(python, ["-m", "pip", "list", "--format=json"], { cwd: REPOSITORY, env: environment }));
  return result.filter((item) => item.name.toLowerCase() !== "pip").map((item) => `${item.name.toLowerCase()}==${item.version}`.replaceAll("_", "-")).sort();
}

function equalStringArrays(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export function validateDesktopBuildEnvironment(options = {}) {
  const validateRuntime = options.validateRuntime !== false;
  const buildPython = join(DESKTOP_BUILD_ROOT, "venv", "Scripts", "python.exe");
  const runtimePython = join(REPOSITORY, "backend", ".venv", "Scripts", "python.exe");
  const buildLock = join(REPOSITORY, "backend", "desktop-build-requirements.lock");
  const runtimeLock = join(REPOSITORY, "backend", "requirements.lock.txt");
  for (const path of [buildPython, runtimePython, buildLock, runtimeLock]) if (!existsSync(path) || !lstatSync(path).isFile()) throw new Error(`Required build input is missing: ${relative(REPOSITORY, path)}`);
  const environment = minimalEnvironment(process.env);
  const approvedBuild = parseRequirementsLock(buildLock);
  const approvedRuntime = parseRequirementsLock(runtimeLock);
  const actualBuild = installedPackages(buildPython, environment);
  const actualRuntime = validateRuntime ? installedPackages(runtimePython, environment) : null;
  if (!equalStringArrays(approvedBuild, actualBuild)) throw new Error("Desktop build packages do not match the exact build lock.");
  if (validateRuntime && !equalStringArrays(approvedRuntime, actualRuntime)) throw new Error("Backend runtime packages do not match requirements.lock.txt.");
  runCommand(buildPython, ["-m", "pip", "check"], { cwd: REPOSITORY, env: environment });
  if (validateRuntime) runCommand(runtimePython, ["-m", "pip", "check"], { cwd: REPOSITORY, env: environment });
  if (runText(buildPython, ["-m", "PyInstaller", "--version"], { env: environment }) !== "6.21.0") throw new Error("PyInstaller 6.21.0 is required.");
  return buildPython;
}

function buildBackend(buildPython) {
  removeSafeTree(DESKTOP_BUILD_ROOT, PYINSTALLER_ROOT);
  ensureSafeDirectory(DESKTOP_BUILD_ROOT, PYINSTALLER_ROOT);
  const environment = minimalEnvironment(process.env, { PYINSTALLER_CONFIG_DIR: join(PYINSTALLER_ROOT, "cache") });
  runVisible(buildPython, ["-m", "PyInstaller", "--noconfirm", "--clean", "--distpath", join(PYINSTALLER_ROOT, "dist"), "--workpath", join(PYINSTALLER_ROOT, "work"), join(REPOSITORY, "backend", "glacial-backend.spec")], { env: environment });
  if (!existsSync(join(PYINSTALLER_PAYLOAD, "glacial-backend.exe")) || !existsSync(join(PYINSTALLER_PAYLOAD, "_internal"))) throw new Error("PyInstaller did not produce the expected backend payload.");
}

function stageSignedBackend(rustcPath) {
  const targetTriple = runText(rustcPath, ["--print", "host-tuple"], { env: minimalEnvironment(process.env) });
  if (targetTriple !== "x86_64-pc-windows-msvc") throw new Error(`Expected x86_64-pc-windows-msvc; found ${targetTriple}.`);
  removeSafeTree(REPOSITORY, SIDECAR_STAGE);
  ensureSafeDirectory(REPOSITORY, SIDECAR_STAGE);
  copyFileSync(join(PYINSTALLER_PAYLOAD, "glacial-backend.exe"), join(SIDECAR_STAGE, `glacial-backend-${targetTriple}.exe`));
  cpSync(join(PYINSTALLER_PAYLOAD, "_internal"), join(SIDECAR_STAGE, "_internal"), { recursive: true, errorOnExist: true });
}

function parseAuditLog(path) {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8").split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
}

function requireSigningEvents(events, config, installer, application) {
  const expectedNames = [...EXPECTED_NSIS_COMPONENTS, basename(installer), basename(application)].map((name) => name.toLowerCase());
  for (const expected of expectedNames) {
    const matches = events.filter((event) => basename(event.path).toLowerCase() === expected);
    if (matches.length !== 1) throw new Error(`Expected exactly one signing event for ${expected}; found ${matches.length}.`);
    if (matches[0].signerThumbprint !== config.expectedThumbprint || !matches[0].timestampThumbprint) throw new Error(`Invalid signing event identity for ${expected}.`);
  }
  const applicationEvent = events.find((event) => resolve(event.path).toLowerCase() === resolve(application).toLowerCase());
  if (!applicationEvent || applicationEvent.sha256 !== sha256(application)) throw new Error("The recorded Glacial.exe signing event does not match the packaged application bytes.");
}

function findInstaller(version) {
  const nsisRoot = join(TAURI_TARGET, "bundle", "nsis");
  if (!existsSync(nsisRoot)) throw new Error("Tauri did not produce an NSIS bundle directory.");
  const installers = readdirSync(nsisRoot).filter((name) => name.toLowerCase().endsWith("-setup.exe")).map((name) => join(nsisRoot, name));
  if (installers.length !== 1) throw new Error(`Expected exactly one NSIS installer; found ${installers.length}.`);
  const expected = `Glacial_${version}_x64-setup.exe`;
  if (basename(installers[0]) !== expected) throw new Error(`Unexpected installer filename: ${basename(installers[0])}`);
  return installers[0];
}

export function assertFileIdentity(left, right, label = "file") {
  if (statSync(left).size !== statSync(right).size || sha256(left) !== sha256(right)) throw new Error(`${label} bytes are not identical.`);
  return true;
}

function assemblePortable(config, expectedCanonicalSubject) {
  const application = join(TAURI_TARGET, "glacial.exe");
  const stagedBackend = join(SIDECAR_STAGE, "glacial-backend-x86_64-pc-windows-msvc.exe");
  const stagedInternal = join(SIDECAR_STAGE, "_internal");
  for (const required of [application, stagedBackend, stagedInternal]) if (!existsSync(required)) throw new Error(`Signed portable input is missing: ${required}`);
  verifySignature(application, config, { expectFirstParty: true, expectedCanonicalSubject });
  verifyPayloadTree(SIDECAR_STAGE, config, { requiredFirstParty: ["glacial-backend-x86_64-pc-windows-msvc.exe"], expectedCanonicalSubject });
  removeSafeTree(DESKTOP_BUILD_ROOT, PORTABLE_ROOT);
  ensureSafeDirectory(DESKTOP_BUILD_ROOT, PORTABLE_ROOT);
  const portableApplication = join(PORTABLE_ROOT, "Glacial.exe");
  copyFileSync(application, portableApplication);
  copyFileSync(stagedBackend, join(PORTABLE_ROOT, "glacial-backend.exe"));
  cpSync(stagedInternal, join(PORTABLE_ROOT, "_internal"), { recursive: true, errorOnExist: true });
  assertFileIdentity(application, portableApplication, "Glacial.exe installer/portable input");
  return verifyPayloadTree(PORTABLE_ROOT, config, { requiredFirstParty: ["Glacial.exe", "glacial-backend.exe"], expectedCanonicalSubject });
}

function listPayloadFiles(root, current = root, output = []) {
  if (current === root) assertSafeTree(root);
  if (lstatSync(current).isSymbolicLink()) throw new Error(`Payload contains a symbolic link or junction: ${current}`);
  for (const entry of readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const path = join(current, entry.name);
    if (lstatSync(path).isSymbolicLink()) throw new Error(`Payload contains a symbolic link or junction: ${path}`);
    if (entry.isDirectory()) listPayloadFiles(root, path, output); else if (entry.isFile()) output.push(path);
  }
  return output;
}

function auditPortablePayload(root) {
  const files = listPayloadFiles(root);
  const forbiddenPath = /(^|\/)(\.git|\.svn|node_modules|tests?|fixtures?|__pycache__|logs?|cache)(\/|$)/i;
  const forbiddenFile = /(^|\/)(\.env($|\.)|\.npmrc$|.*\.(map|db|sqlite|sqlite3|bak|backup|log|pem|pfx|key|pyc|pyo))$/i;
  const violations = [];
  let obsoleteBrandingMatches = 0;
  for (const path of files) {
    const payloadPath = relative(root, path).replaceAll("\\", "/");
    if (forbiddenPath.test(payloadPath) || forbiddenFile.test(payloadPath)) violations.push(payloadPath);
    if (/codexforge/i.test(payloadPath)) obsoleteBrandingMatches += 1;
    if (readFileSync(path).toString("latin1").toLowerCase().includes("codexforge")) obsoleteBrandingMatches += 1;
  }
  if (violations.length) throw new Error(`Forbidden payload files found:\n${violations.join("\n")}`);
  if (obsoleteBrandingMatches) throw new Error("Obsolete CodexForge branding remains in the portable payload.");
  return { files: files.length, forbiddenFiles: 0, obsoleteCodexForgeMatches: 0 };
}

function fileInventory(root) {
  return new Map(listPayloadFiles(root).map((path) => [relative(root, path).replaceAll("\\", "/"), { bytes: statSync(path).size, sha256: sha256(path) }]));
}

function createPortableZip(tarPath, source, destination) {
  if (existsSync(destination)) throw new Error(`Refusing to overwrite an existing portable archive: ${destination}`);
  runVisible(tarPath, ["-a", "-c", "-f", resolve(destination), "-C", resolve(source), "."], { env: minimalEnvironment(process.env) });
  if (!existsSync(destination)) throw new Error("The archive tool did not produce the portable ZIP.");
}

function verifyPortableArchive(tarPath, archive, source, verificationRoot, config, expectedCanonicalSubject) {
  if (existsSync(verificationRoot)) throw new Error("Refusing to overwrite an existing ZIP verification directory.");
  ensureSafeDirectory(DESKTOP_BUILD_ROOT, verificationRoot);
  try {
    runVisible(tarPath, ["-x", "-f", resolve(archive), "-C", resolve(verificationRoot)], { env: minimalEnvironment(process.env) });
    const sourceFiles = fileInventory(source);
    const archiveFiles = fileInventory(verificationRoot);
    if (sourceFiles.size !== archiveFiles.size) throw new Error("The portable ZIP file set does not match its source directory.");
    for (const [path, expected] of sourceFiles) {
      const actual = archiveFiles.get(path);
      if (!actual || actual.bytes !== expected.bytes || actual.sha256 !== expected.sha256) throw new Error(`The portable ZIP changed or omitted ${path}.`);
    }
    auditPortablePayload(verificationRoot);
    return verifyPayloadTree(verificationRoot, config, { requiredFirstParty: ["Glacial.exe", "glacial-backend.exe"], expectedCanonicalSubject });
  } finally {
    removeSafeTree(DESKTOP_BUILD_ROOT, verificationRoot);
  }
}

function artifactRecord(kind, path, root) {
  return { kind, filename: basename(path), path: relative(root, path).replaceAll("\\", "/"), bytes: statSync(path).size, sha256: sha256(path) };
}

function writeReleaseMetadata({ workRoot, source, signerIdentity, installer, portableZip, portablePeRecords, backendSigningRecords, signingEvents, payloadAudit, buildStartedUtc, applicationSha256 }) {
  const artifacts = [artifactRecord("nsis-installer", installer, workRoot), artifactRecord("portable-zip", portableZip, workRoot)];
  const manifest = {
    schema: "glacial-release-candidate/v1",
    product: "Glacial",
    version: source.version,
    commit: source.commit,
    branch: source.branch,
    originMain: source.originMain,
    headMatchedOriginMain: true,
    workingTreeCleanBeforeBuild: true,
    workingTreeCleanBeforePublication: true,
    buildStartedUtc,
    buildCompletedUtc: new Date().toISOString(),
    signing: {
      signerSubject: signerIdentity.canonicalSubject,
      signerThumbprint: signerIdentity.signerThumbprint,
      trust: signerIdentity.trustClassification === "publicly-trusted" ? "publicly trusted" : "self-signed",
      timestampRequired: true,
      applicationSha256,
      backend: backendSigningRecords.map((record) => ({ path: record.relativePath, classification: record.classification, beforeSha256: record.beforeSha256, afterSha256: record.afterSha256, signerThumbprint: record.signature.signerThumbprint })),
      events: signingEvents.map(({ path, ...event }) => ({ file: basename(path), ...event })),
      portablePeFiles: portablePeRecords,
    },
    payloadAudit,
    artifacts,
    acceptance: { automatedPortableBackendRuntimeSmokeTest: "NOT COMPLETED: deferred to manual acceptance because of local Windows security policy.", pendingManualChecks: ["portable application launch", "backend startup", "backend authentication"] },
    warnings: signerIdentity.trustClassification === "self-signed" ? ["The v0.4.0 certificate is self-signed and not publicly trusted.", "Windows Smart App Control or SmartScreen may still block the application; do not weaken Windows security controls."] : [],
  };
  const manifestPath = join(workRoot, "release-candidate-manifest.json");
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx" });
  const sumsPath = join(workRoot, "SHA256SUMS.txt");
  writeFileSync(sumsPath, `${artifacts.map((artifact) => `${artifact.sha256}  ${artifact.filename}`).join("\n")}\n`, { flag: "wx" });
  verifyPublishedHashes(workRoot, manifestPath, sumsPath);
  return { artifacts, manifestPath, sumsPath };
}

export function verifyPublishedHashes(root, manifestPath, sumsPath) {
  const manifest = readJson(manifestPath);
  const sums = new Map(readFileSync(sumsPath, "utf8").trim().split(/\r?\n/).filter(Boolean).map((line) => {
    const match = line.match(/^([0-9A-F]{64})  (.+)$/);
    if (!match) throw new Error(`Malformed SHA256SUMS.txt line: ${line}`);
    return [match[2], match[1]];
  }));
  for (const artifact of manifest.artifacts) {
    const path = assertSafePath(root, join(root, artifact.path), { pathInspector: false });
    if (sha256(path) !== artifact.sha256 || statSync(path).size !== artifact.bytes || sums.get(artifact.filename) !== artifact.sha256) throw new Error(`Published hash mismatch for ${artifact.filename}.`);
  }
  if (sums.size !== manifest.artifacts.length) throw new Error("SHA256SUMS.txt and manifest artifact sets differ.");
  return true;
}

export async function runReleaseSteps(steps, state = {}) {
  for (const step of steps) await step.run(state);
  return state;
}

export function publishCandidate({ workRoot, finalRoot, sourceBefore, sourceVerifier, integrityVerifier = () => {}, renamer = renameSync, pathOptions = {} }) {
  assertSafePath(DESKTOP_BUILD_ROOT, workRoot, pathOptions);
  assertSafePath(DESKTOP_BUILD_ROOT, finalRoot, pathOptions);
  if (existsSync(finalRoot)) throw new Error(`Refusing to overwrite an existing release candidate: ${finalRoot}`);
  ensureSafeDirectory(DESKTOP_BUILD_ROOT, dirname(finalRoot), pathOptions);
  integrityVerifier();
  const sourceAfter = sourceVerifier();
  assertSameReleaseSource(sourceBefore, sourceAfter);
  if (existsSync(finalRoot)) throw new Error(`Refusing to overwrite an existing release candidate: ${finalRoot}`);
  renamer(workRoot, finalRoot);
  return sourceAfter;
}

function formatTimestamp(date) {
  return date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

function dryRun() {
  const config = loadSigningConfig(process.env, { dryRun: true });
  process.stdout.write(`${JSON.stringify({ mode: "dry-run", repository: REPOSITORY, provider: config.provider, expectedSubject: config.expectedSubject, expectedThumbprint: config.expectedThumbprint, timestampOrigin: new URL(config.timestampUrl).origin, tauriOverlay: createTauriSigningOverlay(), actualSteps: ["verify-source", "preflight-disposable-signature", "build-backend", "sign-backend", "stage-backend", "clean-generated-tauri-release-output", "tauri-build-and-sign-once", "verify-installer-and-application", "assemble-portable-from-identical-bytes", "verify-zip", "write-final-hashes", "revalidate-source", "atomic-publish"] }, null, 2)}\n`);
}

async function buildSignedRelease() {
  if (process.platform !== "win32") throw new Error("The signed Windows release workflow must run on Windows.");
  const gitPath = resolveToolExecutable("git.exe", process.env, { forbiddenRoot: REPOSITORY });
  const rustcPath = resolveToolExecutable("rustc.exe", process.env, { forbiddenRoot: REPOSITORY });
  const npm = resolveNpmInvocation(process.env, { forbiddenRoot: REPOSITORY });
  const tarPath = resolveSystemExecutable("System32/tar.exe");
  const source = verifyReleaseSource(gitPath);
  const started = new Date();
  const buildStartedUtc = started.toISOString();
  const releaseId = `Glacial-${source.version}-${source.commit.slice(0, 12)}-${formatTimestamp(started)}`;
  const signingRoot = join(DESKTOP_BUILD_ROOT, "signing", releaseId);
  const workRoot = join(RELEASE_WORK, releaseId);
  const finalRoot = join(RELEASE_CANDIDATES, releaseId);
  for (const path of [signingRoot, workRoot, finalRoot]) assertSafePath(DESKTOP_BUILD_ROOT, path);
  if (existsSync(signingRoot) || existsSync(workRoot) || existsSync(finalRoot)) throw new Error(`Refusing to reuse release state: ${releaseId}`);
  ensureSafeDirectory(DESKTOP_BUILD_ROOT, signingRoot);
  ensureSafeDirectory(DESKTOP_BUILD_ROOT, join(workRoot, "artifacts"));

  const releaseEnvironment = signingEnvironment(process.env, releaseId);
  const config = loadSigningConfig(releaseEnvironment);
  const signerIdentity = preflightSigningProvider(config, { probeParent: join(signingRoot, "probe") });
  const overlayPath = join(signingRoot, "tauri.signing.conf.json");
  writeFileSync(overlayPath, `${JSON.stringify(createTauriSigningOverlay(npm.command), null, 2)}\n`, { flag: "wx" });
  const secretValues = config.provider === "command" ? config.providerEnvironmentNames.map((name) => config.providerEnvironment[name]).filter(Boolean) : [];

  const state = { source, releaseId, workRoot, finalRoot, signerIdentity };
  await runReleaseSteps([
    { name: "build-backend", run: () => { state.buildPython = validateDesktopBuildEnvironment(); buildBackend(state.buildPython); } },
    { name: "sign-backend", run: () => { state.backendSigningRecords = signBackendTree(PYINSTALLER_PAYLOAD, config); } },
    { name: "stage-backend", run: () => stageSignedBackend(rustcPath) },
    { name: "clean-tauri-release-output", run: () => removeSafeTree(REPOSITORY, TAURI_TARGET) },
    { name: "tauri-build", run: () => runVisible(npm.command, [...npm.prefixArgs, "run", "tauri:build", "--", "--config", overlayPath], { cwd: FRONTEND, env: releaseEnvironment, secretValues }) },
    { name: "verify-tauri-output", run: () => {
      state.installer = findInstaller(source.version);
      state.application = join(TAURI_TARGET, "glacial.exe");
      verifySignature(state.installer, config, { expectFirstParty: true, expectedCanonicalSubject: signerIdentity.expectedCanonicalSubject });
      verifySignature(state.application, config, { expectFirstParty: true, expectedCanonicalSubject: signerIdentity.expectedCanonicalSubject });
      state.applicationSha256 = sha256(state.application);
      state.signingEvents = parseAuditLog(config.auditLog);
      requireSigningEvents(state.signingEvents, config, state.installer, state.application);
    } },
    { name: "assemble-portable", run: () => { state.portablePeRecords = assemblePortable(config, signerIdentity.expectedCanonicalSubject); state.payloadAudit = auditPortablePayload(PORTABLE_ROOT); } },
    { name: "copy-and-package", run: () => {
      state.installerDestination = join(workRoot, "artifacts", basename(state.installer));
      copyFileSync(state.installer, state.installerDestination, constants.COPYFILE_EXCL);
      verifySignature(state.installerDestination, config, { expectFirstParty: true, expectedCanonicalSubject: signerIdentity.expectedCanonicalSubject });
      state.portableZip = join(workRoot, "artifacts", `Glacial_${source.version}_x64-portable.zip`);
      createPortableZip(tarPath, PORTABLE_ROOT, state.portableZip);
      verifyPortableArchive(tarPath, state.portableZip, PORTABLE_ROOT, join(workRoot, "zip-verification"), config, signerIdentity.expectedCanonicalSubject);
    } },
    { name: "write-metadata", run: () => { state.metadata = writeReleaseMetadata({ workRoot, source, signerIdentity, installer: state.installerDestination, portableZip: state.portableZip, portablePeRecords: state.portablePeRecords, backendSigningRecords: state.backendSigningRecords, signingEvents: state.signingEvents, payloadAudit: state.payloadAudit, buildStartedUtc, applicationSha256: state.applicationSha256 }); } },
    { name: "publish", run: () => publishCandidate({ workRoot, finalRoot, sourceBefore: source, integrityVerifier: () => verifyPublishedHashes(workRoot, state.metadata.manifestPath, state.metadata.sumsPath), sourceVerifier: () => verifyReleaseSource(gitPath) }) },
  ], state);

  process.stdout.write(`${JSON.stringify({ releaseCandidate: finalRoot, artifacts: state.metadata.artifacts, manifest: join(finalRoot, basename(state.metadata.manifestPath)), sha256Sums: join(finalRoot, basename(state.metadata.sumsPath)) }, null, 2)}\n`);
}

async function main() {
  if (process.argv.includes("--dry-run")) { dryRun(); return; }
  await buildSignedRelease();
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(SCRIPT_PATH)) {
  main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
