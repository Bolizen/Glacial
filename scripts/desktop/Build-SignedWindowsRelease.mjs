import {
  constants,
  copyFileSync,
  cpSync,
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { fork } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  DESKTOP_BUILD_ROOT,
  assertSafePath,
  createTauriSigningOverlay,
  ensureSafeDirectory,
  inspectAuthenticode,
  inspectSigningObject,
  loadSigningConfig,
  minimalEnvironment,
  preflightSigningProvider,
  parseSigningAuditRecord,
  privacySafePath,
  removeSafeTree,
  resolvePrivacySafePath,
  resolvePnpmInvocation,
  resolveToolExecutable,
  runCommand,
  sanitizeDiagnosticText,
  sha256,
  signBackendTree,
  signingBrokerEnvironment,
  signingEnvironment,
  validateStructuredDigest,
  verifySignature,
} from "./windows-signing.mjs";
import {
  buildIdentityForProfile,
  serializeBuildIdentity,
} from "../release/build-identity.mjs";
import { validateProductionDependencies } from "../release/validate-production-dependencies.mjs";
import { assertWindowsReleasePythonIdentity } from "../release/release-contract.mjs";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const SIGNING_BROKER = resolve(dirname(SCRIPT_PATH), "windows-signing-broker.mjs");
const REPOSITORY = resolve(dirname(SCRIPT_PATH), "..", "..");
const FRONTEND = join(REPOSITORY, "frontend");
const PYINSTALLER_ROOT = join(DESKTOP_BUILD_ROOT, "pyinstaller");
const PYINSTALLER_PAYLOAD = join(PYINSTALLER_ROOT, "dist", "glacial-backend");
const SIDECAR_STAGE = join(FRONTEND, "src-tauri", "binaries");
const TAURI_TARGET = join(FRONTEND, "src-tauri", "target", "release");
const RELEASE_CANDIDATES = join(DESKTOP_BUILD_ROOT, "release-candidates");
const RELEASE_WORK = join(DESKTOP_BUILD_ROOT, "release-work");
const EXPECTED_NSIS_COMPONENTS = ["NSISdl.dll", "StartMenu.dll", "System.dll", "nsDialogs.dll", "nsis_tauri_utils.dll"];
const RELEASE_PROFILES = new Set(["signed-preview", "public-rc"]);
const ACTUAL_RELEASE_STEPS = [
  "verify-source",
  "preflight-disposable-signature",
  "enforce-release-profile-trust",
  "build-backend",
  "sign-backend",
  "stage-backend",
  "clean-generated-tauri-release-output",
  "tauri-build-and-sign-once",
  "verify-installer-captured-application-and-restoration",
  "copy-verified-installer",
  "write-final-hashes",
  "revalidate-source",
  "atomic-publish",
];

function runVisible(command, args, options = {}) {
  const result = runCommand(command, args, {
    cwd: options.cwd,
    env: options.env,
    timeoutMs: options.timeoutMs ?? 900_000,
    includeFailureOutput: options.includeFailureOutput === true,
  });
  const secrets = options.secretValues ?? [];
  if (result.stdout) process.stdout.write(sanitizeDiagnosticText(result.stdout, secrets));
  if (result.stderr) process.stderr.write(sanitizeDiagnosticText(result.stderr, secrets));
  return result;
}

function runText(command, args, options = {}) {
  return String(runCommand(command, args, options).stdout ?? "").trim();
}

export function startSigningBroker(environment) {
  const token = randomBytes(32).toString("hex");
  const child = fork(SIGNING_BROKER, [], { env: { ...environment, GLACIAL_WINDOWS_SIGN_BROKER_TOKEN: token }, stdio: ["ignore", "ignore", "pipe", "ipc"], windowsHide: true });
  return new Promise((resolveStart, rejectStart) => {
    const fail = (error) => rejectStart(new Error(`Signing broker failed to start: ${sanitizeDiagnosticText(error.message)}`));
    child.once("error", fail);
    child.once("exit", (code) => { if (code !== null) fail(new Error(`exit ${code}`)); });
    child.on("message", (message) => {
      if (message?.type !== "ready") return;
      child.removeListener("error", fail);
      resolveStart({
        port: message.port,
        token,
        stop: () => new Promise((resolveStop, rejectStop) => {
          child.once("exit", (code) => code === 0 ? resolveStop() : rejectStop(new Error("Signing broker closed before the authorized artifact set was complete.")));
          child.send({ type: "close" });
        }),
      });
    });
  });
}

export function tauriBuildArguments(pnpm, overlayPath) {
  return [...pnpm.prefixArgs, "run", "tauri:build", "--config", overlayPath];
}

export async function runBrokeredTauriBuild(runBuild, stopBroker) {
  let buildError = null;
  try {
    return await runBuild();
  } catch (error) {
    buildError = error;
  } finally {
    try {
      await stopBroker();
    } catch (stopError) {
      if (buildError) {
        throw new Error(
          `Tauri build failed: ${sanitizeDiagnosticText(buildError.message)}\nSigning broker shutdown failed: ${sanitizeDiagnosticText(stopError.message)}`,
        );
      }
      throw stopError;
    }
  }
  throw buildError;
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

export function parseReleaseArguments(args) {
  if (!Array.isArray(args)) throw new Error("Release arguments must be an array.");
  let profile = null;
  let dryRun = false;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--profile") {
      if (profile !== null) throw new Error("The --profile argument must be supplied exactly once.");
      const value = args[index + 1];
      if (!RELEASE_PROFILES.has(value)) throw new Error(`Unsupported release profile: ${value ?? "(missing)"}.`);
      profile = value;
      index += 1;
    } else if (argument === "--dry-run") {
      if (dryRun) throw new Error("The --dry-run argument may be supplied at most once.");
      dryRun = true;
    } else {
      throw new Error(`Unsupported release argument: ${String(argument)}.`);
    }
  }
  if (profile === null) throw new Error("An explicit --profile signed-preview or --profile public-rc argument is required.");
  return { profile, dryRun };
}

export function requiredSignerTrust(profile) {
  if (profile === "signed-preview") return "valid-signed-signer";
  if (profile === "public-rc") return "publicly-trusted";
  throw new Error(`Unsupported release profile: ${String(profile)}.`);
}

export function assertReleaseProfileTrust(profile, signerIdentity) {
  const trustClassification = signerIdentity?.trustClassification;
  if (profile === "signed-preview") {
    if (!["self-signed", "publicly-trusted"].includes(trustClassification)) throw new Error("The signed-preview signer trust classification is invalid or unsupported.");
  } else if (profile === "public-rc") {
    if (trustClassification !== "publicly-trusted") throw new Error("The public-rc profile requires signer trust classified exactly as publicly-trusted.");
  } else {
    throw new Error(`Unsupported release profile: ${String(profile)}.`);
  }
  return signerIdentity;
}

export function releaseProfileManifestFields(profile, signerIdentity) {
  assertReleaseProfileTrust(profile, signerIdentity);
  return {
    releaseProfile: profile,
    requiredSignerTrust: requiredSignerTrust(profile),
    signerTrustClassification: signerIdentity.trustClassification,
  };
}

export function buildDryRunPlan(profile, config) {
  return {
    mode: "dry-run",
    repository: REPOSITORY,
    releaseProfile: profile,
    requiredSignerTrust: requiredSignerTrust(profile),
    trustGate: {
      after: "preflight-disposable-signature",
      before: "build-backend",
      enforcement: profile === "public-rc"
        ? "require-exact-publicly-trusted"
        : "accept-valid-self-signed-or-publicly-trusted",
    },
    provider: config.provider,
    expectedSubject: config.expectedSubject,
    expectedThumbprint: config.expectedThumbprint,
    timestampOrigin: new URL(config.timestampUrl).origin,
    tauriOverlay: createTauriSigningOverlay(),
    actualSteps: [...ACTUAL_RELEASE_STEPS],
  };
}

export async function runAfterSignerPreflight({ profile, preflight, runTrustedSteps, state = {} }) {
  const signerIdentity = await preflight();
  assertReleaseProfileTrust(profile, signerIdentity);
  state.signerIdentity = signerIdentity;
  await runTrustedSteps(state);
  return state;
}

export function verifyReleaseSource(gitPath) {
  const environment = minimalEnvironment(process.env);
  const root = resolve(runText(gitPath, ["rev-parse", "--show-toplevel"], { cwd: REPOSITORY, env: environment }));
  if (root.toLowerCase() !== REPOSITORY.toLowerCase()) throw new Error(`Repository root mismatch: ${root}`);
  const branch = runText(gitPath, ["branch", "--show-current"], { cwd: REPOSITORY, env: environment });
  if (branch !== "main") throw new Error(`The release branch must be main; current branch is ${branch || "detached"}.`);
  const status = runText(gitPath, ["status", "--short"], { cwd: REPOSITORY, env: environment });
  if (status) throw new Error(`The release working tree must be clean.\n${status}`);
  const commit = validateStructuredDigest(
    runText(gitPath, ["rev-parse", "HEAD"], { cwd: REPOSITORY, env: environment }),
    "git-commit",
  );
  const originMain = validateStructuredDigest(
    runText(gitPath, ["rev-parse", "origin/main"], { cwd: REPOSITORY, env: environment }),
    "git-commit",
  );
  if (commit !== originMain) throw new Error(`HEAD ${commit} does not match origin/main ${originMain}.`);

  const packageJson = readJson(join(FRONTEND, "package.json"));
  const pnpmLock = readFileSync(join(FRONTEND, "pnpm-lock.yaml"), "utf8");
  const pnpmWorkspace = readFileSync(join(FRONTEND, "pnpm-workspace.yaml"), "utf8");
  const tauri = readJson(join(FRONTEND, "src-tauri", "tauri.conf.json"));
  const versions = {
    packageJson: packageJson.version,
    tauri: tauri.version,
    cargo: cargoVersion(join(FRONTEND, "src-tauri", "Cargo.toml")),
    cargoLock: lockVersion(join(FRONTEND, "src-tauri", "Cargo.lock")),
  };
  for (const [name, version] of Object.entries(versions)) if (version !== "0.9.12") throw new Error(`${name} identifies version ${version ?? "unknown"}; expected 0.9.12.`);
  if (readFileSync(join(REPOSITORY, "backend", "app", "version.py"), "utf8").trim() !== 'GLACIAL_VERSION = "0.9.12"') throw new Error("Backend version constant does not identify 0.9.12.");
  if (!readFileSync(join(REPOSITORY, "backend", "app", "changelog.py"), "utf8").includes('"version": "0.9.12"')) throw new Error("Backend release metadata does not identify 0.9.12.");
  validateProductionDependencies(packageJson, pnpmLock, pnpmWorkspace);
  return { root, branch, commit, originMain, version: "0.9.12", versions, status: "" };
}

export function assertSameReleaseSource(before, after) {
  for (const field of ["root", "branch", "commit", "originMain", "version", "status"]) {
    if (before[field] !== after[field]) throw new Error(`Release source changed during the build (${field}).`);
  }
  if (JSON.stringify(before.versions) !== JSON.stringify(after.versions)) throw new Error("Release metadata changed during the build.");
  return true;
}

export function canonicalizePackageName(value) {
  return String(value).toLowerCase().replace(/[-_.]+/g, "-");
}

function decodeRequirementsLock(path) {
  const bytes = readFileSync(path);
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return bytes.subarray(2).toString("utf16le");
  if (bytes[0] === 0xfe && bytes[1] === 0xff) {
    const littleEndian = Buffer.from(bytes.subarray(2));
    if (littleEndian.length % 2 !== 0) throw new Error(`Requirements lock has invalid UTF-16BE byte length: ${relative(REPOSITORY, path)}`);
    littleEndian.swap16();
    return littleEndian.toString("utf16le");
  }
  const start = bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? 3 : 0;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(start));
  } catch {
    throw new Error(`Requirements lock is not valid UTF-8, UTF-16LE, or UTF-16BE: ${relative(REPOSITORY, path)}`);
  }
}

export function parseRequirementsLock(path) {
  return decodeRequirementsLock(path).split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#")).map((line, index) => {
    const requirement = line.split(/[ ;]/, 1)[0];
    const separator = requirement.indexOf("==");
    if (separator <= 0 || separator === requirement.length - 2) throw new Error(`Requirements lock entry ${index + 1} is not an exact name==version pin: ${relative(REPOSITORY, path)}`);
    return `${canonicalizePackageName(requirement.slice(0, separator))}==${requirement.slice(separator + 2)}`;
  }).sort();
}

export function normalizeInstalledPackages(items) {
  return items.filter((item) => canonicalizePackageName(item.name) !== "pip").map((item) => `${canonicalizePackageName(item.name)}==${item.version}`).sort();
}

export function assertInterpreterIdentity(python, identity) {
  const expectedExecutable = resolve(python).toLowerCase();
  const expectedPrefix = resolve(dirname(dirname(python))).toLowerCase();
  if (resolve(identity.executable).toLowerCase() !== expectedExecutable || resolve(identity.prefix).toLowerCase() !== expectedPrefix) {
    throw new Error(`Python interpreter identity mismatch; expected ${expectedExecutable} with prefix ${expectedPrefix}.`);
  }
  return true;
}

function installedPackages(python, environment) {
  const identity = JSON.parse(runText(python, ["-c", "import json, platform, struct, sys; print(json.dumps({'executable': sys.executable, 'prefix': sys.prefix, 'implementation': sys.implementation.name, 'version': platform.python_version(), 'platform': sys.platform, 'bits': struct.calcsize('P') * 8, 'machine': platform.machine()}))"], { cwd: REPOSITORY, env: environment }));
  assertInterpreterIdentity(python, identity);
  assertWindowsReleasePythonIdentity(identity, {
    selectionHint: "Provision the desktop build and backend runtime environments from the committed Windows release Python.",
  });
  const result = JSON.parse(runText(python, ["-m", "pip", "list", "--format=json"], { cwd: REPOSITORY, env: environment }));
  return normalizeInstalledPackages(result);
}

export function packageSetDifference(approved, actual) {
  const approvedSet = new Set(approved);
  const actualSet = new Set(actual);
  return {
    missing: approved.filter((value) => !actualSet.has(value)),
    unexpected: actual.filter((value) => !approvedSet.has(value)),
  };
}

export function assertExactPackageSet(label, approved, actual) {
  const difference = packageSetDifference(approved, actual);
  if (difference.missing.length === 0 && difference.unexpected.length === 0 && approved.length === actual.length) return true;
  const missing = difference.missing.length > 0 ? difference.missing.join(", ") : "(none)";
  const unexpected = difference.unexpected.length > 0 ? difference.unexpected.join(", ") : "(none)";
  throw new Error(`${label}\nMissing from environment: ${missing}\nUnexpected in environment: ${unexpected}`);
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
  assertExactPackageSet("Desktop build packages do not match the exact build lock.", approvedBuild, actualBuild);
  if (validateRuntime) assertExactPackageSet("Backend runtime packages do not match requirements.lock.txt.", approvedRuntime, actualRuntime);
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

export function parseAuditLog(path, auditKey) {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8").split(/\r?\n/).filter(Boolean).map((line) => parseSigningAuditRecord(line, auditKey));
}

export function tauriSigningEventsAfterBackend(events, backendSigningEventCount) {
  if (!Number.isSafeInteger(backendSigningEventCount) || backendSigningEventCount < 0 || backendSigningEventCount > events.length) {
    throw new Error("The backend-to-Tauri signing audit boundary is invalid.");
  }
  return events.slice(backendSigningEventCount);
}

function requireSigningEventIdentity(event, config, expectedCanonicalSubject, label, expectedRole = null, options = {}) {
  validateStructuredDigest(event.beforeSha256, "sha256");
  validateStructuredDigest(event.sha256, "sha256");
  if (
    event.signerThumbprint !== config.expectedThumbprint
    || !/^[0-9A-F]{40}$/.test(String(event.timestampThumbprint ?? ""))
  ) throw new Error(`Invalid signing event identity for ${label}.`);
  if (String(event.canonicalSubject ?? "").toUpperCase() !== expectedCanonicalSubject) throw new Error(`Invalid signing event subject for ${label}.`);
  if (config.releaseId) {
    if (event.releaseId !== config.releaseId || event.artifactRole !== expectedRole || !/^[0-9A-F]+:[0-9A-F]+$/.test(String(event.objectIdentity ?? ""))) {
      throw new Error(`Invalid signing object authorization evidence for ${label}.`);
    }
    const eventPath = resolvePrivacySafePath(event.applicationCapturePath || event.path);
    const expectedObjectIdentity = event.applicationCapturePath ? event.evidenceObjectIdentity : event.objectIdentity;
    if (event.applicationCapturePath && !/^[0-9A-F]+:[0-9A-F]+$/.test(String(expectedObjectIdentity ?? ""))) {
      throw new Error(`Invalid signing evidence object identity for ${label}.`);
    }
    if (existsSync(eventPath)) {
      const identity = inspectSigningObject(eventPath, options);
      if (identity.objectId !== expectedObjectIdentity) throw new Error(`The signed filesystem object identity changed before final evidence verification for ${label}.`);
      if (sha256(eventPath) !== event.sha256) throw new Error(`The signed bytes do not match the signing event for ${label}.`);
    }
  }
}

export function requireApplicationCapture(events, config, expectedCanonicalSubject, options = {}) {
  const captures = events.filter((event) => event.applicationCapturePath);
  if (captures.length !== 1) throw new Error(`Expected exactly one Glacial application capture; found ${captures.length}.`);
  const event = captures[0];
  if (resolvePrivacySafePath(event.path).toLowerCase() !== resolve(config.applicationTarget).toLowerCase()) throw new Error("An unrelated executable was recorded as the Glacial application capture.");
  if (resolvePrivacySafePath(event.applicationCapturePath).toLowerCase() !== resolve(config.applicationCapture).toLowerCase()) throw new Error("The Glacial application capture path is unexpected.");
  if (!existsSync(config.applicationCapture) || event.sha256 !== sha256(config.applicationCapture)) throw new Error("The Glacial application capture hash does not match its signing event.");
  if (!/^[0-9A-F]{64}$/.test(String(event.beforeSha256 ?? ""))) throw new Error("The Glacial application signing event is missing its pre-signing hash.");
  requireSigningEventIdentity(event, config, expectedCanonicalSubject, "Glacial.exe", "application", options);
  return event;
}

export function assertExpectedTauriRestoration(workingApplication, capturedApplication, options = {}) {
  if (!existsSync(workingApplication) || !existsSync(capturedApplication)) throw new Error("The Tauri application lifecycle evidence is incomplete.");
  if (sha256(workingApplication) === sha256(capturedApplication)) throw new Error("Tauri did not restore the expected unsigned working application.");
  const signature = options.signature ?? inspectAuthenticode(workingApplication, options.runner, options.env);
  if (signature.status !== "NotSigned") throw new Error("The restored Tauri working application has an unexpected signature state.");
  return { path: resolve(workingApplication), sha256: sha256(workingApplication), status: signature.status };
}

export function assertNsisApplicationSource(nsisScript, expectedApplication) {
  const content = readFileSync(nsisScript, "utf8");
  const matches = [...content.matchAll(/^!define MAINBINARYSRCPATH "([^"]+)"\r?$/gm)];
  if (matches.length !== 1) throw new Error(`Expected exactly one NSIS main application source; found ${matches.length}.`);
  const fileDirectives = [...content.matchAll(/^[ \t]*File[ \t]+"\$\{MAINBINARYSRCPATH\}"[ \t]*\r?$/gm)];
  if (fileDirectives.length !== 1) throw new Error(`Expected exactly one NSIS main application File directive; found ${fileDirectives.length}.`);
  const source = resolve(matches[0][1]);
  if (source.toLowerCase() !== resolve(expectedApplication).toLowerCase()) throw new Error("The NSIS installer references an unexpected application source.");
  return source;
}

export function requireSigningEvents(events, config, installer, expectedCanonicalSubject, options = {}) {
  if (events.length !== EXPECTED_NSIS_COMPONENTS.length + 3) throw new Error(`Unexpected signing event cardinality: ${events.length}.`);
  const expectedNames = [...EXPECTED_NSIS_COMPONENTS, basename(installer)].map((name) => name.toLowerCase());
  for (const expected of expectedNames) {
    const matches = events.filter((event) => basename(event.path).toLowerCase() === expected);
    if (matches.length !== 1) throw new Error(`Expected exactly one signing event for ${expected}; found ${matches.length}.`);
    const role = expected === basename(installer).toLowerCase() ? "installer" : `nsis-plugin:${expected}`;
    requireSigningEventIdentity(matches[0], config, expectedCanonicalSubject, expected, role, options);
  }
  const applicationEvent = requireApplicationCapture(events, config, expectedCanonicalSubject, options);
  const applicationIndex = events.indexOf(applicationEvent);
  const installerEvent = events.find((event) => resolvePrivacySafePath(event.path).toLowerCase() === resolve(installer).toLowerCase());
  if (!installerEvent) throw new Error("The final installer signing event path is unexpected.");
  const installerIndex = events.indexOf(installerEvent);
  if (applicationIndex < 0 || installerIndex <= applicationIndex) throw new Error("The Tauri application and installer signing event order is unexpected.");
  const pluginNames = new Set(EXPECTED_NSIS_COMPONENTS.map((name) => name.toLowerCase()));
  const transient = events.slice(applicationIndex + 1, installerIndex).filter((event) => !pluginNames.has(basename(event.path).toLowerCase()));
  if (transient.length !== 1 || !basename(transient[0].path).toLowerCase().endsWith(".tmp") || transient[0].applicationCapturePath) throw new Error("Expected exactly one transient NSIS uninstaller signing event.");
  requireSigningEventIdentity(transient[0], config, expectedCanonicalSubject, "NSIS uninstaller", "nsis-uninstaller", options);
  return { applicationEvent, uninstallerEvent: transient[0] };
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

function artifactRecord(kind, path, root) {
  return {
    kind,
    filename: basename(path),
    path: relative(root, path).replaceAll("\\", "/"),
    bytes: statSync(path).size,
    sha256: validateStructuredDigest(sha256(path), "sha256"),
  };
}

function writeReleaseMetadata({ workRoot, source, releaseProfile, buildIdentity, signerIdentity, installer, backendSigningRecords, signingEvents, buildStartedUtc, applicationSha256, installerApplicationEvidence }) {
  const artifacts = [artifactRecord("nsis-installer", installer, workRoot)];
  const manifest = {
    schema: "glacial-release-candidate/v1",
    product: "Glacial",
    ...releaseProfileManifestFields(releaseProfile, signerIdentity),
    version: source.version,
    commit: source.commit,
    branch: source.branch,
    originMain: source.originMain,
    buildIdentity,
    headMatchedOriginMain: true,
    workingTreeCleanBeforeBuild: true,
    workingTreeCleanBeforePublication: true,
    buildStartedUtc,
    buildCompletedUtc: new Date().toISOString(),
    signing: {
      signerSubject: signerIdentity.canonicalSubject,
      signerThumbprint: signerIdentity.signerThumbprint,
      trustClassification: signerIdentity.trustClassification,
      trust: signerIdentity.trustClassification === "publicly-trusted" ? "publicly trusted" : "self-signed",
      timestampRequired: true,
      applicationSha256,
      installerApplicationEvidence,
      backend: backendSigningRecords.map((record) => ({
        path: record.relativePath,
        classification: record.classification,
        beforeSha256: validateStructuredDigest(record.beforeSha256, "sha256"),
        afterSha256: validateStructuredDigest(record.afterSha256, "sha256"),
        signerThumbprint: record.signature.signerThumbprint,
      })),
      events: signingEvents.map(({ path, applicationCapturePath, ...event }) => ({ file: basename(path), applicationCapture: applicationCapturePath || null, ...event })),
    },
    artifacts,
    acceptance: { installedLifecycle: "NOT COMPLETED: deferred to frozen installed-edition acceptance.", pendingManualChecks: ["NSIS installation", "installed application launch", "backend startup and authentication", "upgrade, reset, recovery, and uninstall"] },
    warnings: signerIdentity.trustClassification === "self-signed" ? [`The v${source.version} certificate is self-signed and not publicly trusted.`, "Windows Smart App Control or SmartScreen may still block the application; do not weaken Windows security controls."] : [],
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
    validateStructuredDigest(artifact.sha256, "sha256");
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
  integrityVerifier(workRoot);
  const sourceAfter = sourceVerifier();
  assertSameReleaseSource(sourceBefore, sourceAfter);
  if (existsSync(finalRoot)) throw new Error(`Refusing to overwrite an existing release candidate: ${finalRoot}`);
  renamer(workRoot, finalRoot);
  try {
    integrityVerifier(finalRoot);
  } catch (error) {
    if (existsSync(finalRoot) && !existsSync(workRoot)) renamer(finalRoot, workRoot);
    throw error;
  }
  return sourceAfter;
}

function formatTimestamp(date) {
  return date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

function dryRun(profile) {
  const config = loadSigningConfig(process.env, { dryRun: true });
  process.stdout.write(`${sanitizeDiagnosticText(JSON.stringify(buildDryRunPlan(profile, config), null, 2))}\n`);
}

async function buildSignedRelease(releaseProfile) {
  if (process.platform !== "win32") throw new Error("The signed Windows release workflow must run on Windows.");
  const gitPath = resolveToolExecutable("git.exe", process.env, { forbiddenRoot: REPOSITORY });
  const rustcPath = resolveToolExecutable("rustc.exe", process.env, { forbiddenRoot: REPOSITORY });
  const pnpm = resolvePnpmInvocation(process.env, { forbiddenRoot: REPOSITORY });
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

  const releaseEnvironment = signingEnvironment(process.env, releaseId, randomBytes(32).toString("hex"));
  const tauriTemporaryRoot = join(signingRoot, "tauri-temp");
  ensureSafeDirectory(DESKTOP_BUILD_ROOT, tauriTemporaryRoot);
  releaseEnvironment.TEMP = tauriTemporaryRoot;
  releaseEnvironment.TMP = tauriTemporaryRoot;
  const config = loadSigningConfig(releaseEnvironment);
  const overlayPath = join(signingRoot, "tauri.signing.conf.json");
  const state = { source, releaseId, workRoot, finalRoot, releaseProfile };
  await runAfterSignerPreflight({
    profile: releaseProfile,
    preflight: () => preflightSigningProvider(config, { probeParent: join(signingRoot, "probe") }),
    state,
    runTrustedSteps: async () => {
      const { signerIdentity } = state;
      state.buildIdentity = buildIdentityForProfile({
        profile: releaseProfile,
        sourceCommit: source.commit,
        signerIdentity,
      });
      releaseEnvironment.GLACIAL_BUILD_IDENTITY_JSON = serializeBuildIdentity(state.buildIdentity);
      ensureSafeDirectory(DESKTOP_BUILD_ROOT, join(workRoot, "artifacts"));
      writeFileSync(overlayPath, `${JSON.stringify(createTauriSigningOverlay(pnpm.command), null, 2)}\n`, { flag: "wx" });
      await runReleaseSteps([
        { name: "build-backend", run: () => { state.buildPython = validateDesktopBuildEnvironment(); buildBackend(state.buildPython); } },
        { name: "sign-backend", run: () => {
          state.backendSigningRecords = signBackendTree(PYINSTALLER_PAYLOAD, config);
          state.backendSigningEventCount = parseAuditLog(config.auditLog, config.auditKey).length;
        } },
        { name: "stage-backend", run: () => stageSignedBackend(rustcPath) },
        { name: "clean-tauri-release-output", run: () => removeSafeTree(REPOSITORY, TAURI_TARGET) },
        { name: "tauri-build", run: async () => {
          const broker = await startSigningBroker(releaseEnvironment);
          const buildEnvironment = signingBrokerEnvironment(releaseEnvironment, releaseId, broker.port, broker.token, releaseEnvironment.GLACIAL_BUILD_IDENTITY_JSON);
          await runBrokeredTauriBuild(
            () => runVisible(pnpm.command, tauriBuildArguments(pnpm, overlayPath), {
              cwd: FRONTEND,
              env: buildEnvironment,
              includeFailureOutput: true,
            }),
            broker.stop,
          );
        } },
        { name: "verify-tauri-output", run: () => {
          state.installer = findInstaller(source.version);
          state.workingApplication = join(TAURI_TARGET, "glacial.exe");
          state.application = config.applicationCapture;
          for (const path of [state.workingApplication, state.application]) if (!existsSync(path)) throw new Error(`Tauri application lifecycle evidence is missing: ${path}`);
          verifySignature(state.installer, config, { expectFirstParty: true, expectedCanonicalSubject: signerIdentity.expectedCanonicalSubject });
          verifySignature(state.application, config, { expectFirstParty: true, expectedCanonicalSubject: signerIdentity.expectedCanonicalSubject });
          const restored = assertExpectedTauriRestoration(state.workingApplication, state.application);
          state.applicationSha256 = sha256(state.application);
          const allSigningEvents = parseAuditLog(config.auditLog, config.auditKey);
          state.signingEvents = tauriSigningEventsAfterBackend(allSigningEvents, state.backendSigningEventCount);
          const signingEvidence = requireSigningEvents(state.signingEvents, config, state.installer, signerIdentity.expectedCanonicalSubject);
          const nsisScript = join(TAURI_TARGET, "nsis", "x64", "installer.nsi");
          const nsisSource = assertNsisApplicationSource(nsisScript, state.workingApplication);
          state.installerApplicationEvidence = { method: "tauri-v2.11.4-static-nsis-source", nsisScript: relative(REPOSITORY, nsisScript).replaceAll("\\", "/"), nsisSource: relative(REPOSITORY, nsisSource).replaceAll("\\", "/"), signedCaptureSha256: state.applicationSha256, signingEventSha256: signingEvidence.applicationEvent.sha256, restoredWorkingSha256: restored.sha256 };
        } },
        { name: "copy-installer", run: () => {
          state.installerDestination = join(workRoot, "artifacts", basename(state.installer));
          copyFileSync(state.installer, state.installerDestination, constants.COPYFILE_EXCL);
          verifySignature(state.installerDestination, config, { expectFirstParty: true, expectedCanonicalSubject: signerIdentity.expectedCanonicalSubject });
        } },
        { name: "write-metadata", run: () => { state.metadata = writeReleaseMetadata({ workRoot, source, releaseProfile, buildIdentity: state.buildIdentity, signerIdentity, installer: state.installerDestination, backendSigningRecords: state.backendSigningRecords, signingEvents: state.signingEvents, buildStartedUtc, applicationSha256: state.applicationSha256, installerApplicationEvidence: state.installerApplicationEvidence }); } },
        { name: "publish", run: () => publishCandidate({ workRoot, finalRoot, sourceBefore: source, integrityVerifier: (root) => verifyPublishedHashes(root, join(root, basename(state.metadata.manifestPath)), join(root, basename(state.metadata.sumsPath))), sourceVerifier: () => verifyReleaseSource(gitPath) }) },
      ], state);
    },
  });

  process.stdout.write(`${JSON.stringify({ releaseProfile, releaseCandidate: privacySafePath(finalRoot), artifacts: state.metadata.artifacts, manifest: privacySafePath(join(finalRoot, basename(state.metadata.manifestPath))), sha256Sums: privacySafePath(join(finalRoot, basename(state.metadata.sumsPath))) }, null, 2)}\n`);
}

async function main() {
  const options = parseReleaseArguments(process.argv.slice(2));
  if (options.dryRun) { dryRun(options.profile); return; }
  await buildSignedRelease(options.profile);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(SCRIPT_PATH)) {
  main().catch((error) => { process.stderr.write(`${sanitizeDiagnosticText(error.message)}\n`); process.exitCode = 1; });
}
