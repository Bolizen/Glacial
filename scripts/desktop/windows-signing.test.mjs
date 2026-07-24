import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DESKTOP_BUILD_ROOT,
  assertCertificateIdentity,
  assertSafePath,
  buildCommandSignArgs,
  buildStoreSignArgs,
  buildTimestampArgs,
  createPowerShellInvocation,
  createTauriSigningOverlay,
  createUnsignedProbeCopy,
  hasEmbeddedAuthenticode,
  isPortableExecutable,
  loadSigningConfig,
  minimalEnvironment,
  normalizeThumbprint,
  planBackendSigning,
  preflightSigningProvider,
  removeSafeTree,
  resolveNpmInvocation,
  resolveSystemExecutable,
  runCommand,
  sha256,
  signOne,
  signingEnvironment,
} from "./windows-signing.mjs";
import {
  assertExpectedTauriRestoration,
  assertExactPackageSet,
  assertFileIdentity,
  assertInterpreterIdentity,
  assertNsisApplicationSource,
  assertSameReleaseSource,
  canonicalizePackageName,
  copyCapturedApplication,
  createPortableZip,
  normalizeInstalledPackages,
  packageSetDifference,
  parseRequirementsLock,
  publishCandidate,
  requireApplicationCapture,
  requireSigningEvents,
  runReleaseSteps,
  validatePortableZipEntryNames,
  verifyPortableArchiveCompatibility,
  verifyPublishedHashes,
} from "./Build-SignedWindowsRelease.mjs";
import { developmentPlan, runDevelopmentCommand } from "./desktop-development.mjs";

const TEST_PATH = fileURLToPath(import.meta.url);
const REPOSITORY = resolve(dirname(TEST_PATH), "..", "..");
const TEST_ROOT = join(DESKTOP_BUILD_ROOT, "release-signing-tests");
const PORTABLE_ZIP_TEST_ROOT = join(DESKTOP_BUILD_ROOT, "portable-zip-tests", String(process.pid));
const FAILED_RC = join(DESKTOP_BUILD_ROOT, "release-candidates", "Glacial-0.4.0-fbf96d568350-20260719T065059Z");
const THUMBPRINT = "A".repeat(40);
const RELEASE_ID = "Glacial-0.6.4-ffffffffffff-20260720T120000Z";

function cleanTestRoot() {
  removeSafeTree(DESKTOP_BUILD_ROOT, TEST_ROOT, { pathInspector: false });
}

function storeEnvironment(overrides = {}) {
  return {
    ...process.env,
    GLACIAL_WINDOWS_SIGNING_PROVIDER: "store",
    GLACIAL_WINDOWS_CERTIFICATE_THUMBPRINT: THUMBPRINT,
    GLACIAL_WINDOWS_EXPECTED_SUBJECT: "CN=Icefields Development",
    GLACIAL_WINDOWS_SIGNTOOL_PATH: "C:\\Reviewed Tools\\signtool.exe",
    GLACIAL_WINDOWS_TIMESTAMP_URL: "https://timestamp.digicert.com",
    GLACIAL_WINDOWS_REQUIRE_TIMESTAMP: "1",
    ...overrides,
  };
}

function commandEnvironment(overrides = {}) {
  return {
    ...process.env,
    GLACIAL_WINDOWS_SIGNING_PROVIDER: "command",
    GLACIAL_WINDOWS_EXPECTED_THUMBPRINT: THUMBPRINT,
    GLACIAL_WINDOWS_EXPECTED_SUBJECT: "CN=Icefields Development",
    GLACIAL_WINDOWS_SIGNTOOL_PATH: "C:\\Reviewed Tools\\signtool.exe",
    GLACIAL_WINDOWS_TIMESTAMP_URL: "https://timestamp.digicert.com",
    GLACIAL_WINDOWS_REQUIRE_TIMESTAMP: "1",
    GLACIAL_WINDOWS_SIGN_COMMAND: "C:\\Reviewed Tools\\provider.exe",
    GLACIAL_WINDOWS_SIGN_COMMAND_ARGS: '["sign","--file","{file}"]',
    ...overrides,
  };
}

function minimalPe() {
  const buffer = Buffer.alloc(256);
  buffer.write("MZ", 0, "ascii");
  buffer.writeUInt32LE(0x80, 0x3c);
  buffer.write("PE\0\0", 0x80, "binary");
  return buffer;
}

function minimalPeWithAuthenticode() {
  const buffer = Buffer.alloc(528);
  minimalPe().copy(buffer);
  const optionalHeader = 0x80 + 24;
  buffer.writeUInt16LE(0x20b, optionalHeader);
  buffer.writeUInt32LE(0x81234567, 0x80 + 8);
  const securityDirectory = optionalHeader + 112 + 32;
  buffer.writeUInt32LE(512, securityDirectory);
  buffer.writeUInt32LE(16, securityDirectory + 4);
  buffer.fill(0x41, 512);
  return buffer;
}

function sourceState(overrides = {}) {
  return {
    root: REPOSITORY,
    branch: "main",
    commit: "f".repeat(40),
    originMain: "f".repeat(40),
    version: "0.6.4",
    status: "",
    versions: { packageJson: "0.6.4", tauri: "0.6.4" },
    ...overrides,
  };
}

test.beforeEach(cleanTestRoot);
test.after(cleanTestRoot);

test("runtime package locks decode UTF-16LE and use PEP-compatible name canonicalization", () => {
  const lock = join(TEST_ROOT, "requirements.lock.txt");
  mkdirSync(TEST_ROOT, { recursive: true });
  const content = "Typing_Extensions==4.15.0\r\npydantic.core==2.46.4\r\n";
  writeFileSync(lock, Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(content, "utf16le")]));
  assert.deepEqual(parseRequirementsLock(lock), ["pydantic-core==2.46.4", "typing-extensions==4.15.0"]);
  assert.equal(canonicalizePackageName("A..B___C---D"), "a-b-c-d");
  assert.deepEqual(normalizeInstalledPackages([
    { name: "pip", version: "26.0.1" },
    { name: "Typing_Extensions", version: "4.15.0" },
    { name: "pydantic.core", version: "2.46.4" },
  ]), ["pydantic-core==2.46.4", "typing-extensions==4.15.0"]);
});

test("runtime package mismatches report missing and unexpected entries", () => {
  const approved = ["alpha==1", "bravo==2"];
  const actual = ["alpha==1", "charlie==3"];
  assert.deepEqual(packageSetDifference(approved, actual), { missing: ["bravo==2"], unexpected: ["charlie==3"] });
  assert.throws(() => assertExactPackageSet("Runtime mismatch.", approved, actual), (error) => {
    assert.match(error.message, /Missing from environment: bravo==2/);
    assert.match(error.message, /Unexpected in environment: charlie==3/);
    return true;
  });
});

test("runtime package checks require the intended interpreter and virtual-environment prefix", () => {
  const python = join(REPOSITORY, "backend", ".venv", "Scripts", "python.exe");
  const prefix = join(REPOSITORY, "backend", ".venv");
  assert.equal(assertInterpreterIdentity(python, { executable: python, prefix }), true);
  assert.throws(() => assertInterpreterIdentity(python, { executable: join(prefix, "other.exe"), prefix }), /identity mismatch/);
  assert.throws(() => assertInterpreterIdentity(python, { executable: python, prefix: join(REPOSITORY, "backend", "other-venv") }), /identity mismatch/);
});

test("PowerShell helper transports hostile paths only through environment JSON", () => {
  const hostile = "C:\\Repo With Space\\quote' ; & | (payload)\\Glacial.exe";
  const invocation = createPowerShellInvocation("signature", { path: hostile }, process.env);
  assert.ok(invocation.command.toLowerCase().endsWith("powershell.exe"));
  assert.deepEqual(invocation.args.slice(0, 3), ["-NoProfile", "-NonInteractive", "-Command"]);
  assert.equal(invocation.args.some((argument) => argument.includes(hostile)), false);
  assert.equal(JSON.parse(invocation.env.GLACIAL_WINDOWS_HELPER_PAYLOAD).path, hostile);
  assert.equal(invocation.args.some((argument) => argument.includes("GLACIAL_WINDOWS_HELPER_PAYLOAD")), true);
});

test("timestamp URL policy permits HTTPS and only the exact DigiCert HTTP exception", () => {
  for (const value of [
    "http://timestamp.example.test",
    "https://user:password@timestamp.example.test",
    "https://timestamp.example.test/?token=secret",
    "https://timestamp.example.test/#secret",
  ]) {
    assert.throws(() => loadSigningConfig(storeEnvironment({ GLACIAL_WINDOWS_TIMESTAMP_URL: value }), { dryRun: true }));
  }
  const config = loadSigningConfig(storeEnvironment(), { dryRun: true });
  assert.equal(config.timestampUrl, "https://timestamp.digicert.com/");
  const digiCertHttp = loadSigningConfig(storeEnvironment({ GLACIAL_WINDOWS_TIMESTAMP_URL: "http://timestamp.digicert.com" }), { dryRun: true });
  assert.equal(digiCertHttp.timestampUrl, "http://timestamp.digicert.com");
  assert.throws(() => loadSigningConfig(storeEnvironment({ GLACIAL_WINDOWS_TIMESTAMP_URL: "http://timestamp.digicert.com/other" }), { dryRun: true }));
});

test("thumbprints normalize exactly and reject malformed input", () => {
  assert.equal(normalizeThumbprint(`aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa`), "A".repeat(40));
  assert.throws(() => normalizeThumbprint("A".repeat(39)));
  assert.throws(() => normalizeThumbprint(`${"A".repeat(39)}G`));
});

test("certificate selection requires one exact canonical subject and accessible key", () => {
  const config = loadSigningConfig(storeEnvironment(), { dryRun: true });
  const valid = { Thumbprint: THUMBPRINT, CanonicalSubject: "CN=ICEFIELDS DEVELOPMENT", HasPrivateKey: true, TrustValid: true, TrustClassification: "self-signed" };
  assert.equal(assertCertificateIdentity([valid], config, "CN=ICEFIELDS DEVELOPMENT"), valid);
  assert.throws(() => assertCertificateIdentity([], config, "CN=ICEFIELDS DEVELOPMENT"), /exactly one/);
  assert.throws(() => assertCertificateIdentity([valid, valid], config, "CN=ICEFIELDS DEVELOPMENT"), /exactly one/);
  assert.throws(() => assertCertificateIdentity([{ ...valid, CanonicalSubject: "CN=ICEFIELDS DEVELOPMENT EVIL" }], config, "CN=ICEFIELDS DEVELOPMENT"), /exact canonical/);
  assert.throws(() => assertCertificateIdentity([{ ...valid, Thumbprint: "B".repeat(40) }], config, "CN=ICEFIELDS DEVELOPMENT"), /thumbprint/);
  assert.throws(() => assertCertificateIdentity([{ ...valid, HasPrivateKey: false }], config, "CN=ICEFIELDS DEVELOPMENT"), /private key/);
  assert.throws(() => assertCertificateIdentity([{ ...valid, TrustClassification: "private-trusted" }], config, "CN=ICEFIELDS DEVELOPMENT"), /private, or ambiguous/);
});

test("store signing and RFC 3161 timestamping are separate checked operations", () => {
  const config = loadSigningConfig(storeEnvironment(), { dryRun: true });
  const file = "C:\\Payload With Space\\Glacial.exe";
  const signArgs = buildStoreSignArgs(config, file);
  const timestampArgs = buildTimestampArgs(config, file);
  assert.deepEqual(signArgs.slice(0, 7), ["sign", "/debug", "/v", "/s", "My", "/sha1", THUMBPRINT]);
  assert.equal(signArgs.includes("/tr"), false);
  assert.deepEqual(timestampArgs.slice(0, 7), ["timestamp", "/debug", "/v", "/tr", config.timestampUrl, "/td", "SHA256"]);
  assert.equal(signArgs.at(-1), file);
  assert.equal(timestampArgs.at(-1), file);
});

test("command provider keeps the file as one direct argument and forwards only named environment", () => {
  const source = commandEnvironment({
    GLACIAL_WINDOWS_SIGN_COMMAND_ENV: '["AZURE_CLIENT_ID"]',
    AZURE_CLIENT_ID: "allowed-value",
    AZURE_CLIENT_SECRET: "not-allowed",
    AWS_SECRET_ACCESS_KEY: "not-allowed-either",
  });
  const releaseEnvironment = signingEnvironment(source, "Glacial-0.6.4-ffffffffffff-20260719T120000Z");
  assert.equal(releaseEnvironment.AZURE_CLIENT_ID, "allowed-value");
  assert.equal("AZURE_CLIENT_SECRET" in releaseEnvironment, false);
  assert.equal("AWS_SECRET_ACCESS_KEY" in releaseEnvironment, false);
  const config = loadSigningConfig(releaseEnvironment, { dryRun: true });
  assert.deepEqual(buildCommandSignArgs(config, "C:\\a b;&()\\file.exe"), ["sign", "--file", "C:\\a b;&()\\file.exe"]);
  assert.equal(config.providerEnvironment.AZURE_CLIENT_ID, "allowed-value");
  for (const commandArgs of [
    '["sign","--token","literal-secret","{file}"]',
    '["sign","https://provider.example/sign?credential=value","{file}"]',
    '["sign","line\\nbreak","{file}"]',
  ]) assert.throws(() => loadSigningConfig(commandEnvironment({ GLACIAL_WINDOWS_SIGN_COMMAND_ARGS: commandArgs }), { dryRun: true }));
});

test("base child environment excludes unrelated credential variables", () => {
  const environment = minimalEnvironment({ ...process.env, AZURE_CLIENT_SECRET: "secret", GITHUB_TOKEN: "token", CUSTOM_FLAG: "value" });
  assert.equal("AZURE_CLIENT_SECRET" in environment, false);
  assert.equal("GITHUB_TOKEN" in environment, false);
  assert.equal("CUSTOM_FLAG" in environment, false);
  assert.ok(environment.SYSTEMROOT || environment.SystemRoot || environment.WINDIR);
});

test("opt-in signing failure diagnostics are useful, bounded, and control-character sanitized", () => {
  assert.throws(
    () => runCommand(process.execPath, ["-e", "process.stdout.write('certificate selected\\u001b[31m'); process.stderr.write('timestamp unavailable'); process.exit(1)"], { env: minimalEnvironment(process.env), includeFailureOutput: true }),
    (error) => {
      assert.match(error.message, /certificate selected/);
      assert.match(error.message, /timestamp unavailable/);
      assert.equal(error.message.includes("\u001b"), false);
      assert.equal(error.message.includes("[31m"), false);
      return true;
    },
  );
});

test("Tauri overlay uses object-form direct arguments and no embedded certificate identity", () => {
  const overlay = createTauriSigningOverlay("C:\\Program Files\\nodejs\\node.exe", "C:\\Repo With Space\\windows-signing.mjs");
  assert.deepEqual(overlay.bundle.windows.signCommand, {
    cmd: "C:\\Program Files\\nodejs\\node.exe",
    args: ["C:\\Repo With Space\\windows-signing.mjs", "sign-one", "%1"],
  });
  assert.equal(JSON.stringify(overlay).includes(THUMBPRINT), false);
  const schema = JSON.parse(readFileSync(join(REPOSITORY, "frontend", "node_modules", "@tauri-apps", "cli", "config.schema.json"), "utf8"));
  const customSignCommand = schema.definitions.CustomSignCommandConfig;
  const objectForm = customSignCommand.anyOf.find((entry) => entry.type === "object");
  assert.deepEqual(objectForm.required.sort(), ["args", "cmd"]);
  assert.equal(objectForm.properties.args.items.type, "string");
});

test("PE discovery classification preserves valid vendor signatures and rejects ambiguity", () => {
  const unsigned = minimalPe();
  assert.equal(isPortableExecutable(unsigned), true);
  const plan = planBackendSigning([
    { relativePath: "glacial-backend.exe", signature: { status: "NotSigned" }, embeddedSignature: false },
    { relativePath: "vendor.dll", signature: { status: "Valid" }, embeddedSignature: true },
  ]);
  assert.equal(plan[0].action, "sign-first-party");
  assert.equal(plan[1].action, "preserve-vendor-signature");
  assert.throws(() => planBackendSigning([{ relativePath: "broken.pyd", signature: { status: "HashMismatch" }, embeddedSignature: true }]));
});

test("the disposable probe removes an existing Authenticode table only from its copy", () => {
  const source = join(TEST_ROOT, "signed-probe-source.exe");
  const destination = join(TEST_ROOT, "unsigned-probe-copy.exe");
  mkdirSync(TEST_ROOT, { recursive: true });
  const original = minimalPeWithAuthenticode();
  writeFileSync(source, original);
  assert.equal(hasEmbeddedAuthenticode(readFileSync(source)), true);
  createUnsignedProbeCopy(source, destination);
  assert.deepEqual(readFileSync(source), original);
  assert.notDeepEqual(readFileSync(destination), original);
  assert.equal(hasEmbeddedAuthenticode(readFileSync(destination)), false);
  assert.equal(isPortableExecutable(readFileSync(destination)), true);
});

test("reparse-point output ancestors are rejected before mutation", () => {
  const root = join(TEST_ROOT, "safe-root");
  mkdirSync(root, { recursive: true });
  const target = join(root, "nested", "artifact");
  const pathInspector = (paths) => ({ Items: paths.map((path, index) => ({ Path: path, Exists: true, ReparsePoint: index === 0 })) });
  assert.throws(() => assertSafePath(root, target, { pathInspector }), /reparse point/);
});

test("private-key probe fails before builds and cleans disposable files on timestamp/signing failure", () => {
  const probeParent = join(TEST_ROOT, "probe-parent");
  mkdirSync(probeParent, { recursive: true });
  const probeSource = join(TEST_ROOT, "probe-source.exe");
  writeFileSync(probeSource, minimalPe());
  const config = loadSigningConfig(storeEnvironment(), { dryRun: true });
  const calls = [];
  const runner = (command, args, options = {}) => {
    const operation = options.env?.GLACIAL_WINDOWS_HELPER_OPERATION;
    if (operation === "canonical-subject") return { status: 0, stdout: '{"CanonicalSubject":"CN=ICEFIELDS DEVELOPMENT"}', stderr: "" };
    if (operation === "certificate") return { status: 0, stdout: JSON.stringify({ Candidates: [{ Thumbprint: THUMBPRINT, CanonicalSubject: "CN=ICEFIELDS DEVELOPMENT", HasPrivateKey: true, TrustValid: true, TrustClassification: "self-signed" }] }), stderr: "" };
    if (operation === "signature") return { status: 0, stdout: JSON.stringify({ Status: "NotSigned", StatusMessage: "The file is not digitally signed.", SignerThumbprint: null, CanonicalSubject: null, TimestampThumbprint: null, TrustValid: false, TrustClassification: "invalid", ChainStatuses: [] }), stderr: "" };
    if (args[0] === "sign") { calls.push("sign"); return { status: 0, stdout: "Successfully signed", stderr: "" }; }
    if (args[0] === "timestamp") { calls.push("timestamp"); throw new Error("timestamp service unavailable"); }
    throw new Error(`Unexpected probe command: ${command}`);
  };
  assert.throws(() => preflightSigningProvider(config, { probeParent, probeSource, runner, pathInspector: false }), /timestamp service unavailable/);
  assert.deepEqual(calls, ["sign", "timestamp"]);
  assert.deepEqual(readFileSync(probeSource), minimalPe());
  assert.equal(existsSync(probeParent), true);
  assert.equal(readFileSync(probeSource).length, 256);
  assert.deepEqual(readdirSync(probeParent), []);
});

test("private-key probe signs, verifies, derives trust, and removes its disposable PE", () => {
  const probeParent = join(TEST_ROOT, "successful-probe-parent");
  mkdirSync(probeParent, { recursive: true });
  const probeSource = join(TEST_ROOT, "successful-probe-source.exe");
  writeFileSync(probeSource, minimalPe());
  const config = loadSigningConfig(storeEnvironment(), { dryRun: true });
  const signature = { Status: "Valid", StatusMessage: "Signature verified.", SignerThumbprint: THUMBPRINT, CanonicalSubject: "CN=ICEFIELDS DEVELOPMENT", TimestampThumbprint: "B".repeat(40), TrustValid: true, TrustClassification: "self-signed", ChainStatuses: [] };
  const calls = [];
  let signed = false;
  const runner = (command, args, options = {}) => {
    const operation = options.env?.GLACIAL_WINDOWS_HELPER_OPERATION;
    if (operation === "canonical-subject") return { status: 0, stdout: '{"CanonicalSubject":"CN=ICEFIELDS DEVELOPMENT"}', stderr: "" };
    if (operation === "certificate") return { status: 0, stdout: JSON.stringify({ Candidates: [{ Thumbprint: THUMBPRINT, CanonicalSubject: "CN=ICEFIELDS DEVELOPMENT", HasPrivateKey: true, TrustValid: true, TrustClassification: "self-signed" }] }), stderr: "" };
    if (operation === "signature") return { status: 0, stdout: JSON.stringify(signed ? signature : { Status: "NotSigned", StatusMessage: "The file is not digitally signed.", SignerThumbprint: null, CanonicalSubject: null, TimestampThumbprint: null, TrustValid: false, TrustClassification: "invalid", ChainStatuses: [] }), stderr: "" };
    if (["sign", "timestamp", "verify"].includes(args[0])) { calls.push(args[0]); if (args[0] === "sign") signed = true; return { status: 0, stdout: "", stderr: "" }; }
    throw new Error(`Unexpected probe command: ${command}`);
  };
  const identity = preflightSigningProvider(config, { probeParent, probeSource, runner, pathInspector: false });
  assert.equal(identity.signerThumbprint, THUMBPRINT);
  assert.equal(identity.trustClassification, "self-signed");
  assert.deepEqual(calls, ["sign", "timestamp", "verify"]);
  assert.deepEqual(readdirSync(probeParent), []);
});

test("signed application capture survives Tauri restoration and is the only portable application input", () => {
  const workingApplication = join(TEST_ROOT, "tauri", "target", "release", "glacial.exe");
  const capture = join(TEST_ROOT, "signing", "application", "Glacial.exe");
  const auditLog = join(TEST_ROOT, "signing", "signing-events.jsonl");
  const portableApplication = join(TEST_ROOT, "portable", "Glacial.exe");
  const nsisScript = join(TEST_ROOT, "tauri", "target", "release", "nsis", "x64", "installer.nsi");
  const failedEvidence = join(TEST_ROOT, "failed-build-evidence.exe");
  mkdirSync(dirname(workingApplication), { recursive: true });
  mkdirSync(dirname(portableApplication), { recursive: true });
  mkdirSync(dirname(nsisScript), { recursive: true });
  const original = minimalPe();
  writeFileSync(workingApplication, original);
  writeFileSync(failedEvidence, "preserve failed build");
  writeFileSync(nsisScript, `!define MAINBINARYSRCPATH "${workingApplication}"\r\nFile "\${MAINBINARYSRCPATH}"\r\n`);
  const config = {
    ...loadSigningConfig(storeEnvironment({ GLACIAL_WINDOWS_RELEASE_ID: RELEASE_ID }), { dryRun: true }),
    applicationTarget: workingApplication,
    applicationCapture: capture,
    auditLog,
  };
  const signature = { Status: "Valid", StatusMessage: "Signature verified.", SignerThumbprint: THUMBPRINT, CanonicalSubject: "CN=ICEFIELDS DEVELOPMENT", TimestampThumbprint: "B".repeat(40), TrustValid: true, TrustClassification: "self-signed", ChainStatuses: [] };
  const runner = (command, args, options = {}) => {
    const operation = options.env?.GLACIAL_WINDOWS_HELPER_OPERATION;
    if (operation === "canonical-subject") return { status: 0, stdout: '{"CanonicalSubject":"CN=ICEFIELDS DEVELOPMENT"}', stderr: "" };
    if (operation === "signature") return { status: 0, stdout: JSON.stringify(signature), stderr: "" };
    if (args[0] === "sign") { writeFileSync(args.at(-1), Buffer.concat([readFileSync(args.at(-1)), Buffer.from("signed")])) ; return { status: 0, stdout: "", stderr: "" }; }
    if (["timestamp", "verify"].includes(args[0])) return { status: 0, stdout: "", stderr: "" };
    throw new Error(`Unexpected signing command: ${command}`);
  };

  signOne(workingApplication, config, { runner, pathInspector: false });
  const capturedBytes = readFileSync(capture);
  const [applicationEvent] = readFileSync(auditLog, "utf8").trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.notDeepEqual(capturedBytes, original);
  assert.equal(applicationEvent.beforeSha256, createHash("sha256").update(original).digest("hex").toUpperCase());
  assert.equal(applicationEvent.sha256, sha256(capture));
  assert.equal(applicationEvent.applicationCapturePath, capture);

  writeFileSync(workingApplication, original);
  assert.equal(assertExpectedTauriRestoration(workingApplication, capture, { signature: { status: "NotSigned" } }).status, "NotSigned");
  assert.equal(assertNsisApplicationSource(nsisScript, workingApplication), workingApplication);
  copyCapturedApplication(capture, portableApplication, config);
  assert.deepEqual(readFileSync(portableApplication), capturedBytes);
  assert.throws(() => copyCapturedApplication(workingApplication, join(TEST_ROOT, "portable", "wrong.exe"), config), /preserved signed/);
  assert.throws(() => signOne(workingApplication, config, { runner, pathInspector: false }), /duplicate/);
  assert.equal(readFileSync(failedEvidence, "utf8"), "preserve failed build");

  const unrelated = join(TEST_ROOT, "unrelated.exe");
  writeFileSync(unrelated, minimalPe());
  signOne(unrelated, config, { runner, pathInspector: false });
  assert.deepEqual(readFileSync(capture), capturedBytes);
  const events = readFileSync(auditLog, "utf8").trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(events[1].applicationCapturePath, null);
});

test("application capture validation rejects missing, duplicate, unrelated, and hash-mismatched events", () => {
  const capture = join(TEST_ROOT, "capture", "Glacial.exe");
  const target = join(TEST_ROOT, "target", "glacial.exe");
  mkdirSync(dirname(capture), { recursive: true });
  writeFileSync(capture, minimalPe());
  const config = { expectedThumbprint: THUMBPRINT, applicationTarget: target, applicationCapture: capture };
  const event = { path: target, beforeSha256: "C".repeat(64), sha256: sha256(capture), applicationCapturePath: capture, signerThumbprint: THUMBPRINT, canonicalSubject: "CN=ICEFIELDS DEVELOPMENT", timestampThumbprint: "B".repeat(40) };
  assert.equal(requireApplicationCapture([event], config, "CN=ICEFIELDS DEVELOPMENT"), event);
  assert.throws(() => requireApplicationCapture([], config, "CN=ICEFIELDS DEVELOPMENT"), /exactly one/);
  assert.throws(() => requireApplicationCapture([event, event], config, "CN=ICEFIELDS DEVELOPMENT"), /exactly one/);
  assert.throws(() => requireApplicationCapture([{ ...event, path: join(TEST_ROOT, "other.exe") }], config, "CN=ICEFIELDS DEVELOPMENT"), /unrelated/);
  assert.throws(() => requireApplicationCapture([{ ...event, sha256: "D".repeat(64) }], config, "CN=ICEFIELDS DEVELOPMENT"), /hash/);
});

test("Tauri signing evidence requires one transient uninstaller between plugins and final installer", () => {
  const capture = join(TEST_ROOT, "capture-evidence", "Glacial.exe");
  const target = join(TEST_ROOT, "target-evidence", "glacial.exe");
  const installer = join(TEST_ROOT, "bundle", "Glacial_0.6.4_x64-setup.exe");
  mkdirSync(dirname(capture), { recursive: true });
  writeFileSync(capture, minimalPe());
  const config = { expectedThumbprint: THUMBPRINT, applicationTarget: target, applicationCapture: capture };
  const identity = { beforeSha256: "C".repeat(64), signerThumbprint: THUMBPRINT, canonicalSubject: "CN=ICEFIELDS DEVELOPMENT", timestampThumbprint: "B".repeat(40), applicationCapturePath: null };
  const application = { ...identity, path: target, sha256: sha256(capture), applicationCapturePath: capture };
  const plugins = ["NSISdl.dll", "StartMenu.dll", "System.dll", "nsDialogs.dll", "nsis_tauri_utils.dll"].map((name) => ({ ...identity, path: join(TEST_ROOT, "plugins", name), sha256: "D".repeat(64) }));
  const uninstaller = { ...identity, path: "C:\\Users\\Test\\AppData\\Local\\Temp\\nst1234.tmp", sha256: "E".repeat(64) };
  const installerEvent = { ...identity, path: installer, sha256: "F".repeat(64) };
  assert.equal(requireSigningEvents([application, ...plugins, uninstaller, installerEvent], config, installer, "CN=ICEFIELDS DEVELOPMENT").uninstallerEvent, uninstaller);
  assert.throws(() => requireSigningEvents([application, ...plugins, installerEvent], config, installer, "CN=ICEFIELDS DEVELOPMENT"), /transient NSIS uninstaller/);
});

test("production portable ZIP is visible to Windows and extracts identically with Expand-Archive and tar.exe", () => {
  const source = join(PORTABLE_ZIP_TEST_ROOT, "source");
  const archive = join(PORTABLE_ZIP_TEST_ROOT, "Glacial-portable.zip");
  const verificationRoot = join(PORTABLE_ZIP_TEST_ROOT, "verification");
  try {
    mkdirSync(join(source, "_internal", "nested"), { recursive: true });
    writeFileSync(join(source, "Glacial.exe"), minimalPe());
    writeFileSync(join(source, "glacial-backend.exe"), Buffer.concat([minimalPe(), Buffer.from("backend")]));
    writeFileSync(join(source, "_internal", "runtime.dll"), Buffer.from("runtime"));
    writeFileSync(join(source, "_internal", "nested", "data.txt"), Buffer.from("data"));
    const tarPath = resolveSystemExecutable("System32/tar.exe");
    const powershellPath = resolveSystemExecutable("System32/WindowsPowerShell/v1.0/powershell.exe");

    createPortableZip(powershellPath, source, archive);
    const result = verifyPortableArchiveCompatibility(tarPath, powershellPath, archive, source, verificationRoot);
    assert.ok(result.explorerShellItemCount > 0);
    assert.deepEqual(result.entryNames.filter((name) => !name.endsWith("/")).sort(), ["Glacial.exe", "_internal/nested/data.txt", "_internal/runtime.dll", "glacial-backend.exe"].sort());
    assert.ok(result.entryNames.every((name) => !name.startsWith("./")));
    const windowsFiles = new Map(result.windowsFiles);
    const tarFiles = new Map(result.tarFiles);
    for (const relativePath of ["Glacial.exe", "glacial-backend.exe", "_internal/runtime.dll", "_internal/nested/data.txt"]) {
      const sourcePath = join(source, ...relativePath.split("/"));
      assert.equal(windowsFiles.get(relativePath).sha256, sha256(sourcePath));
      assert.equal(tarFiles.get(relativePath).sha256, sha256(sourcePath));
    }
    assert.equal(windowsFiles.get("Glacial.exe").sha256, sha256(join(source, "Glacial.exe")));
    assert.equal(existsSync(verificationRoot), false);
  } finally {
    removeSafeTree(DESKTOP_BUILD_ROOT, PORTABLE_ZIP_TEST_ROOT, { pathInspector: false });
  }
});

test("portable ZIP entry validation rejects empty, hidden-root, absolute, drive-qualified, traversal, and wrapped archives", () => {
  const valid = ["Glacial.exe", "glacial-backend.exe", "_internal/runtime.dll"];
  assert.deepEqual(validatePortableZipEntryNames(valid, 3), valid);
  assert.throws(() => validatePortableZipEntryNames([], 0), /no archive entries/);
  assert.throws(() => validatePortableZipEntryNames(valid, 0), /appears empty/);
  for (const entries of [
    ["./Glacial.exe", "glacial-backend.exe", "_internal/runtime.dll"],
    ["/Glacial.exe", "glacial-backend.exe", "_internal/runtime.dll"],
    ["\\Glacial.exe", "glacial-backend.exe", "_internal/runtime.dll"],
    ["C:/Glacial.exe", "glacial-backend.exe", "_internal/runtime.dll"],
    ["Glacial.exe", "glacial-backend.exe", "_internal/../runtime.dll"],
    ["Glacial.exe", "glacial-backend.exe", "_internal\\..\\runtime.dll"],
    ["wrapper/Glacial.exe", "glacial-backend.exe", "_internal/runtime.dll"],
  ]) assert.throws(() => validatePortableZipEntryNames(entries, 3), /Unsafe|Unexpected/);
});

test("release source revalidation rejects every mutable provenance field", () => {
  const before = sourceState();
  assert.equal(assertSameReleaseSource(before, sourceState()), true);
  for (const changed of [
    { branch: "feature" },
    { commit: "e".repeat(40) },
    { originMain: "e".repeat(40) },
    { status: " M file" },
    { version: "0.6.5" },
    { versions: { packageJson: "0.6.5", tauri: "0.6.4" } },
  ]) assert.throws(() => assertSameReleaseSource(before, sourceState(changed)), /changed/);
});

test("candidate publication is failure-atomic and never overwrites existing candidates", () => {
  const workRoot = join(TEST_ROOT, "release-work", "candidate");
  const finalRoot = join(TEST_ROOT, "release-candidates", "candidate");
  mkdirSync(workRoot, { recursive: true });
  writeFileSync(join(workRoot, "marker"), "candidate");
  let renamed = false;
  assert.throws(() => publishCandidate({ workRoot, finalRoot, sourceBefore: sourceState(), sourceVerifier: () => sourceState({ status: " M changed" }), renamer: () => { renamed = true; }, pathOptions: { pathInspector: false } }), /changed/);
  assert.equal(renamed, false);
  assert.equal(existsSync(workRoot), true);
  mkdirSync(finalRoot, { recursive: true });
  assert.throws(() => publishCandidate({ workRoot, finalRoot, sourceBefore: sourceState(), sourceVerifier: sourceState, renamer: () => { renamed = true; }, pathOptions: { pathInspector: false } }), /overwrite/);
  assert.equal(renamed, false);
});

test("candidate publication verifies final hashes before the last Git check and atomic rename", () => {
  const workRoot = join(TEST_ROOT, "ordered-release-work", "candidate");
  const finalRoot = join(TEST_ROOT, "ordered-release-candidates", "candidate");
  mkdirSync(workRoot, { recursive: true });
  const order = [];
  publishCandidate({
    workRoot,
    finalRoot,
    sourceBefore: sourceState(),
    integrityVerifier: () => order.push("hashes"),
    sourceVerifier: () => { order.push("git"); return sourceState(); },
    renamer: () => order.push("rename"),
    pathOptions: { pathInspector: false },
  });
  assert.deepEqual(order, ["hashes", "git", "rename"]);
});

test("actual release-step executor stops before publication after any failed step", async () => {
  const calls = [];
  await assert.rejects(() => runReleaseSteps([
    { name: "sign", run: () => calls.push("sign") },
    { name: "verify", run: () => { calls.push("verify"); throw new Error("verification failed"); } },
    { name: "publish", run: () => calls.push("publish") },
  ]), /verification failed/);
  assert.deepEqual(calls, ["sign", "verify"]);
});

test("identical Glacial.exe bytes are required for installer and portable inputs", () => {
  const installerInput = join(TEST_ROOT, "target", "glacial.exe");
  const portableInput = join(TEST_ROOT, "portable", "Glacial.exe");
  mkdirSync(dirname(installerInput), { recursive: true });
  mkdirSync(dirname(portableInput), { recursive: true });
  writeFileSync(installerInput, minimalPe());
  copyFileSync(installerInput, portableInput);
  assert.equal(assertFileIdentity(installerInput, portableInput, "Glacial.exe"), true);
  writeFileSync(portableInput, Buffer.concat([minimalPe(), Buffer.from("changed")]));
  assert.throws(() => assertFileIdentity(installerInput, portableInput, "Glacial.exe"), /not identical/);
});

test("manifest and SHA256SUMS verification detects post-packaging mutation", () => {
  const root = join(TEST_ROOT, "hashes");
  const artifacts = join(root, "artifacts");
  mkdirSync(artifacts, { recursive: true });
  const artifact = join(artifacts, "Glacial.zip");
  writeFileSync(artifact, "final bytes");
  const hash = sha256(artifact);
  const manifestPath = join(root, "release-candidate-manifest.json");
  const sumsPath = join(root, "SHA256SUMS.txt");
  writeFileSync(manifestPath, JSON.stringify({ artifacts: [{ filename: "Glacial.zip", path: "artifacts/Glacial.zip", bytes: 11, sha256: hash }] }));
  writeFileSync(sumsPath, `${hash}  Glacial.zip\n`);
  assert.equal(verifyPublishedHashes(root, manifestPath, sumsPath), true);
  writeFileSync(artifact, "mutated");
  assert.throws(() => verifyPublishedHashes(root, manifestPath, sumsPath), /mismatch/);
});

test("repeat provisioning and exact CurrentUser removal guards are documented", () => {
  const docs = readFileSync(join(REPOSITORY, "docs", "windows-release-signing.md"), "utf8");
  assert.match(docs, /Refusing duplicate provisioning/);
  assert.match(docs, /Existing Icefields certificate/);
  assert.match(docs, /foreach \(\$storeName in @\("My", "Root"\)\)/);
  assert.match(docs, /Get-ExactIcefieldsCertificate "My"/);
  assert.match(docs, /Get-ExactIcefieldsCertificate "Root"/);
  assert.doesNotMatch(docs, /LocalMachine\\My|LocalMachine\\Root/);
});

test("ordinary unsigned development plans require neither signing nor PowerShell", () => {
  assert.deepEqual(developmentPlan("build-backend"), ["validate unsigned build tools", "build PyInstaller backend"]);
  const plan = runDevelopmentCommand("build-portable", { dryRun: true });
  assert.equal(plan.signingRequired, false);
  assert.equal(plan.certificateRequired, false);
  const packageJson = JSON.parse(readFileSync(join(REPOSITORY, "frontend", "package.json"), "utf8"));
  assert.match(packageJson.scripts["desktop:backend"], /^node /);
  assert.match(packageJson.scripts["desktop:portable"], /^node /);
  assert.doesNotMatch(packageJson.scripts["desktop:backend"], /ExecutionPolicy|sign/i);
  assert.doesNotMatch(packageJson.scripts["desktop:portable"], /ExecutionPolicy|sign/i);
});

test("npm is launched through the absolute Node executable without a command shell", () => {
  const npm = resolveNpmInvocation(process.env, { forbiddenRoot: REPOSITORY });
  assert.ok(npm.command.toLowerCase().endsWith("node.exe"));
  assert.ok(npm.prefixArgs[0].toLowerCase().endsWith("npm-cli.js"));
  const result = runCommand(npm.command, [...npm.prefixArgs, "--version"], { env: minimalEnvironment(process.env) });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /^\d+\.\d+\.\d+/);
});

test("unsigned development dry-run commands execute without signing configuration", () => {
  for (const command of ["build-backend", "build-portable"]) {
    const result = spawnSync(process.execPath, [join(REPOSITORY, "scripts", "desktop", "desktop-development.mjs"), command, "--dry-run"], { cwd: REPOSITORY, env: minimalEnvironment(process.env), encoding: "utf8", shell: false });
    assert.equal(result.status, 0, result.stderr);
    const plan = JSON.parse(result.stdout);
    assert.equal(plan.signingRequired, false);
    assert.equal(plan.certificateRequired, false);
  }
});

test("historical failed release candidate remains byte-identical during tests", () => {
  if (!existsSync(FAILED_RC)) return;
  const expected = new Map([
    ["Glacial_0.4.0_x64-portable.zip", [19011005, "B07E01C1AC7225E713201782D0BF9B3D397776F509352817C423A3EF5202C427"]],
    ["Glacial_0.4.0_x64-setup.exe", [15952735, "79E0B8BA2CA360A300FFA882F4AF7FF74B1B880F920AECDA2AA18775F251CFA8"]],
  ]);
  for (const [name, [bytes, hash]] of expected) {
    const path = join(FAILED_RC, "artifacts", name);
    assert.equal(readFileSync(path).length, bytes);
    assert.equal(sha256(path), hash);
  }
});
