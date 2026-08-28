import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  existsSync,
  linkSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DESKTOP_BUILD_ROOT,
  assertNoNodeRuntimeInjection,
  assertCertificateIdentity,
  assertSafePath,
  authorizeTauriSigningRequest,
  buildCommandSignArgs,
  buildStoreSignArgs,
  buildTimestampArgs,
  createPowerShellInvocation,
  createTauriSigningOverlay,
  createUnsignedProbeCopy,
  defaultTauriNsisPluginRoot,
  exactSigningAuthorization,
  hasEmbeddedAuthenticode,
  isPortableExecutable,
  loadSigningConfig,
  minimalEnvironment,
  normalizeThumbprint,
  planBackendSigning,
  preflightSigningProvider,
  privacySafePath,
  removeSafeTree,
  resolvePnpmInvocation,
  runCommand,
  sanitizeDiagnosticText,
  sha256,
  signOne,
  signingAuditRecord,
  serializeSigningAuditRecord,
  signingBrokerEnvironment,
  signingEnvironment,
  validateStructuredDigest,
  validateSignedAuthorizationState,
  validateSigningAuthorizationState,
} from "./windows-signing.mjs";
import {
  assertReleaseProfileTrust,
  assertPreparedReleaseInputs,
  assertExpectedTauriRestoration,
  assertExactPackageSet,
  assertInterpreterIdentity,
  assertNsisApplicationSource,
  assertSameReleaseSource,
  buildDryRunPlan,
  canonicalizePackageName,
  normalizeInstalledPackages,
  packageSetDifference,
  parseRequirementsLock,
  parseReleaseArguments,
  parseAuditLog,
  publishCandidate,
  releaseProfileManifestFields,
  requireApplicationCapture,
  requireSigningEvents,
  runAfterSignerPreflight,
  runBrokeredTauriBuild,
  runReleaseSteps,
  tauriSigningEventsAfterBackend,
  tauriBuildArguments,
  verifyPublishedHashes,
} from "./Build-SignedWindowsRelease.mjs";
import { developmentPlan, runDevelopmentCommand } from "./desktop-development.mjs";
import { parseBackendStageAuthority, runTauriBuild } from "./tauri-build.mjs";
import { buildIdentityForProfile, serializeBuildIdentity } from "../release/build-identity.mjs";

const TEST_PATH = fileURLToPath(import.meta.url);
const REPOSITORY = resolve(dirname(TEST_PATH), "..", "..");
const TEST_ROOT = join(DESKTOP_BUILD_ROOT, "release-signing-tests");
const THUMBPRINT = "A".repeat(40);
const RELEASE_ID = "Glacial-0.9.12-ffffffffffff-20260720T120000Z";
const AUDIT_KEY = "9".repeat(64);
const CERTIFICATE_VALIDITY = {
  NotBeforeUtc: "2026-01-01T00:00:00.000Z",
  NotAfterUtc: "2027-01-01T00:00:00.000Z",
  CodeSigningEku: true,
};
const SIGNATURE_VALIDITY = {
  SignerNotBeforeUtc: CERTIFICATE_VALIDITY.NotBeforeUtc,
  SignerNotAfterUtc: CERTIFICATE_VALIDITY.NotAfterUtc,
  CodeSigningEku: true,
};

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
    repositoryIdentity: "github.com/bolizen/glacial",
    authorityDigest: "1".repeat(64),
    authorityId: "G120-test-authority",
    authorityIssuedAtUtc: "2026-08-27T00:00:00.000Z",
    authorityExpiresAtUtc: "2026-09-05T00:00:00.000Z",
    authorizedProfiles: ["signed-preview"],
    authorizedSigningProvider: "store",
    version: "0.9.12",
    status: "",
    versions: { packageJson: "0.9.12", tauri: "0.9.12" },
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
  const valid = { Thumbprint: THUMBPRINT, CanonicalSubject: "CN=ICEFIELDS DEVELOPMENT", HasPrivateKey: true, TrustValid: true, TrustClassification: "self-signed", ...CERTIFICATE_VALIDITY };
  assert.equal(assertCertificateIdentity([valid], config, "CN=ICEFIELDS DEVELOPMENT"), valid);
  assert.throws(() => assertCertificateIdentity([], config, "CN=ICEFIELDS DEVELOPMENT"), /exactly one/);
  assert.throws(() => assertCertificateIdentity([valid, valid], config, "CN=ICEFIELDS DEVELOPMENT"), /exactly one/);
  assert.throws(() => assertCertificateIdentity([{ ...valid, CanonicalSubject: "CN=ICEFIELDS DEVELOPMENT EVIL" }], config, "CN=ICEFIELDS DEVELOPMENT"), /exact canonical/);
  assert.throws(() => assertCertificateIdentity([{ ...valid, Thumbprint: "B".repeat(40) }], config, "CN=ICEFIELDS DEVELOPMENT"), /thumbprint/);
  assert.throws(() => assertCertificateIdentity([{ ...valid, HasPrivateKey: false }], config, "CN=ICEFIELDS DEVELOPMENT"), /private key/);
  assert.throws(() => assertCertificateIdentity([{ ...valid, CodeSigningEku: false }], config, "CN=ICEFIELDS DEVELOPMENT"), /Code Signing EKU/);
  assert.throws(() => assertCertificateIdentity([{ ...valid, NotAfterUtc: "2025-01-01T00:00:00.000Z" }], config, "CN=ICEFIELDS DEVELOPMENT"), /expired/);
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
  const releaseEnvironment = signingEnvironment(source, "Glacial-0.9.12-ffffffffffff-20260719T120000Z", AUDIT_KEY, ["AZURE_CLIENT_ID"]);
  assert.equal(releaseEnvironment.AZURE_CLIENT_ID, "allowed-value");
  assert.equal(releaseEnvironment.GLACIAL_WINDOWS_SIGN_AUDIT_KEY, AUDIT_KEY);
  assert.equal("AZURE_CLIENT_SECRET" in releaseEnvironment, false);
  assert.equal("AWS_SECRET_ACCESS_KEY" in releaseEnvironment, false);
  const config = loadSigningConfig(releaseEnvironment, { dryRun: true });
  assert.deepEqual(buildCommandSignArgs(config, "C:\\a b;&()\\file.exe"), ["sign", "--file", "C:\\a b;&()\\file.exe"]);
  assert.equal(config.providerEnvironment.AZURE_CLIENT_ID, "allowed-value");
  const stageAuthority = JSON.stringify({ schemaVersion: 1, runtime: [] });
  const buildEnvironment = signingBrokerEnvironment(releaseEnvironment, "Glacial-0.9.12-ffffffffffff-20260719T120000Z", 32123, "a".repeat(64), "identity", stageAuthority);
  assert.equal(buildEnvironment.GLACIAL_WINDOWS_SIGN_BROKER_PORT, "32123");
  assert.equal(buildEnvironment.GLACIAL_WINDOWS_SIGN_BROKER_TOKEN, "a".repeat(64));
  assert.equal(buildEnvironment.GLACIAL_BACKEND_STAGE_AUTHORITY_JSON, stageAuthority);
  assert.equal("AZURE_CLIENT_ID" in buildEnvironment, false);
  assert.equal("GLACIAL_WINDOWS_SIGN_COMMAND" in buildEnvironment, false);
  assert.equal("GLACIAL_WINDOWS_SIGN_COMMAND_ENV" in buildEnvironment, false);
  for (const commandArgs of [
    '["sign","--token","literal-secret","{file}"]',
    '["sign","https://provider.example/sign?credential=value","{file}"]',
    '["sign","line\\nbreak","{file}"]',
  ]) assert.throws(() => loadSigningConfig(commandEnvironment({ GLACIAL_WINDOWS_SIGN_COMMAND_ARGS: commandArgs }), { dryRun: true }));
});

test("Tauri packaging requires backend authority supplied outside the stage", () => {
  assert.throws(() => parseBackendStageAuthority({}), /authority is required/);
  assert.throws(() => parseBackendStageAuthority({ GLACIAL_BACKEND_STAGE_AUTHORITY_JSON: "{}" }), /malformed/);
  assert.deepEqual(
    parseBackendStageAuthority({ GLACIAL_BACKEND_STAGE_AUTHORITY_JSON: '{"schemaVersion":1,"runtime":[]}' }),
    { schemaVersion: 1, runtime: [] },
  );
});

test("base child environment excludes unrelated credential variables", () => {
  const environment = minimalEnvironment({ ...process.env, AZURE_CLIENT_SECRET: "secret", GITHUB_TOKEN: "token", CUSTOM_FLAG: "value" });
  assert.equal("AZURE_CLIENT_SECRET" in environment, false);
  assert.equal("GITHUB_TOKEN" in environment, false);
  assert.equal("CUSTOM_FLAG" in environment, false);
  assert.ok(environment.SYSTEMROOT || environment.SystemRoot || environment.WINDIR);
});

test("release-capable children reject Node injection and require the canonical coordinator boundary", () => {
  assert.equal(assertNoNodeRuntimeInjection({}), true);
  assert.throws(() => assertNoNodeRuntimeInjection({ NODE_OPTIONS: "--require attacker.js" }), /NODE_OPTIONS is forbidden/);
  assert.throws(() => assertNoNodeRuntimeInjection({ node_path: "C:\\attacker" }), /NODE_PATH is forbidden/);
  const broker = readFileSync(join(REPOSITORY, "scripts", "desktop", "windows-signing-broker.mjs"), "utf8");
  const tauri = readFileSync(join(REPOSITORY, "scripts", "desktop", "tauri-build.mjs"), "utf8");
  const coordinator = readFileSync(join(REPOSITORY, "scripts", "release", "validate-clean-environment.mjs"), "utf8");
  const cargoVerifier = readFileSync(join(REPOSITORY, "scripts", "security", "verify-glib-backport.mjs"), "utf8");
  assert.match(broker, /assertReleaseCoordinatorParent\(config,/);
  assert.match(tauri, /assertReleaseCoordinatorParent\(config,/);
  assert.match(tauri, /releaseToolEnvironment\(minimalEnvironment\([\s\S]*, tools\)/);
  assert.doesNotMatch(tauri, /GLACIAL_RELEASE_CARGO_AUTHORITY_JSON/);
  assert.match(cargoVerifier, /loadReleaseAuthority\(process\.env, \{ repository: repoRoot \}\)[\s\S]*authenticateReleaseTools\(authority/);
  assert.match(coordinator, /CANONICAL_WORKER_ARGUMENT[\s\S]*runCommand\(process\.execPath, \[scriptPath, CANONICAL_WORKER_ARGUMENT/);
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

test("build and release diagnostics redact fake credentials and private host paths", () => {
  const hexCanaries = [
    "A1".repeat(20),
    "b2".repeat(32),
    "C3d4".repeat(24),
    "e5F6".repeat(32),
  ];
  const hostile = [
    "C:\\Users\\privacy-canary\\AppData\\Local\\Temp\\trace.log",
    "\\\\privacy-server\\share\\trace.log",
    "Authorization: Bearer privacy-bearer-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "password=privacy-password-canary",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB",
    hexCanaries[0],
    `prose ${hexCanaries[1]} after`,
    `evidence/${hexCanaries[2]}.txt`,
    `sha512:${hexCanaries[3]}`,
    "\u001b[31m",
  ].join("\n");
  const sanitized = sanitizeDiagnosticText(hostile);
  for (const forbidden of [
    "privacy-canary",
    "privacy-server",
    "privacy-bearer-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "privacy-password-canary",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB",
    ...hexCanaries,
    "\u001b",
  ]) {
    assert.equal(sanitized.includes(forbidden), false);
  }
  assert.match(sanitized, /\[REDACTED\]/);
  assert.match(sanitized, /<HOST_PATH>|<TEMP_DIR>/);
});

test("PowerShell child diagnostics redact fake standalone hex canaries", () => {
  const canary = "A1".repeat(32);
  const powershell = join(process.env.SystemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  assert.throws(
    () => runCommand(
      powershell,
      ["-NoProfile", "-NonInteractive", "-Command", `[Console]::Error.Write('${canary}'); exit 9`],
      { env: minimalEnvironment(process.env), includeFailureOutput: true },
    ),
    (error) => {
      assert.equal(error.message.includes(canary), false);
      assert.match(error.message, /\[REDACTED\]/);
      return true;
    },
  );
});

test("signing audit preserves only validated structured hashes and sanitizes free text", () => {
  const record = {
    path: join(TEST_ROOT, "Glacial.exe"),
    artifactRole: "application",
    releaseId: RELEASE_ID,
    objectIdentity: "A1:B2",
    beforeSha256: "A1".repeat(32),
    sha256: "b2".repeat(32),
    applicationCapturePath: null,
    signerThumbprint: "C3".repeat(20),
    canonicalSubject: `CN=Release ${"d4".repeat(32)}`,
    timestampThumbprint: "E5".repeat(20),
    trustClassification: "self-signed",
    signedUtc: "2026-07-27T12:00:00.000Z",
  };
  const persisted = signingAuditRecord(record);
  assert.equal(persisted.beforeSha256, record.beforeSha256);
  assert.equal(persisted.sha256, record.sha256);
  assert.equal(persisted.signerThumbprint, record.signerThumbprint);
  assert.equal(persisted.timestampThumbprint, record.timestampThumbprint);
  assert.equal(persisted.canonicalSubject.includes("d4".repeat(32)), false);
  assert.throws(() => signingAuditRecord({ ...record, sha256: "f".repeat(63) }));
  assert.throws(() => signingAuditRecord({ ...record, signerThumbprint: "f".repeat(39) }));
  assert.equal(validateStructuredDigest("a".repeat(40), "git-commit"), "a".repeat(40));
  assert.throws(() => validateStructuredDigest("a".repeat(64), "git-commit"));
});

test("authenticated signing audit JSONL rejects content tampering", () => {
  const auditLog = join(TEST_ROOT, "authenticated-audit", "signing-events.jsonl");
  const record = {
    path: join(TEST_ROOT, "Glacial.exe"), artifactRole: "installer", releaseId: RELEASE_ID,
    objectIdentity: "A1:B2", evidenceObjectIdentity: null, beforeSha256: "A".repeat(64), sha256: "B".repeat(64),
    applicationCapturePath: null, signerThumbprint: THUMBPRINT, canonicalSubject: "CN=ICEFIELDS DEVELOPMENT",
    timestampThumbprint: "E".repeat(40), trustClassification: "self-signed", signedUtc: "2026-07-27T12:00:00.000Z",
  };
  mkdirSync(dirname(auditLog), { recursive: true });
  writeFileSync(auditLog, `${serializeSigningAuditRecord(record, AUDIT_KEY)}\n`);
  assert.equal(parseAuditLog(auditLog, AUDIT_KEY).length, 1);
  writeFileSync(auditLog, readFileSync(auditLog, "utf8").replace(record.sha256, "C".repeat(64)));
  assert.throws(() => parseAuditLog(auditLog, AUDIT_KEY), /authentication failed/);
});

test("Tauri overlay uses object-form direct arguments and no embedded certificate identity", () => {
  const overlay = createTauriSigningOverlay("C:\\Program Files\\nodejs\\node.exe", "C:\\Repo With Space\\windows-signing.mjs");
  assert.deepEqual(overlay.bundle.windows.signCommand, {
    cmd: "C:\\Program Files\\nodejs\\node.exe",
    args: ["C:\\Repo With Space\\windows-signing.mjs", "sign-request", "%1"],
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

test("private-key probe refuses signing without current release authority", () => {
  const probeParent = join(TEST_ROOT, "probe-parent");
  mkdirSync(probeParent, { recursive: true });
  const probeSource = join(TEST_ROOT, "probe-source.exe");
  writeFileSync(probeSource, minimalPe());
  const config = loadSigningConfig(storeEnvironment(), { dryRun: true });
  const calls = [];
  const runner = (command, args, options = {}) => {
    const operation = options.env?.GLACIAL_WINDOWS_HELPER_OPERATION;
    if (operation === "canonical-subject") return { status: 0, stdout: '{"CanonicalSubject":"CN=ICEFIELDS DEVELOPMENT"}', stderr: "" };
    if (operation === "certificate") return { status: 0, stdout: JSON.stringify({ Candidates: [{ Thumbprint: THUMBPRINT, CanonicalSubject: "CN=ICEFIELDS DEVELOPMENT", HasPrivateKey: true, TrustValid: true, TrustClassification: "self-signed", ...CERTIFICATE_VALIDITY }] }), stderr: "" };
    if (operation === "signature") return { status: 0, stdout: JSON.stringify({ Status: "NotSigned", StatusMessage: "The file is not digitally signed.", SignerThumbprint: null, CanonicalSubject: null, TimestampThumbprint: null, TrustValid: false, TrustClassification: "invalid", ChainStatuses: [] }), stderr: "" };
    if (args[0] === "sign") { calls.push("sign"); return { status: 0, stdout: "Successfully signed", stderr: "" }; }
    if (args[0] === "timestamp") { calls.push("timestamp"); throw new Error("timestamp service unavailable"); }
    throw new Error(`Unexpected probe command: ${command}`);
  };
  assert.throws(() => preflightSigningProvider(config, { probeParent, probeSource, runner, pathInspector: false }), /authentic authority-derived signing configuration/);
  assert.deepEqual(calls, []);
  assert.deepEqual(readFileSync(probeSource), minimalPe());
  assert.equal(existsSync(probeParent), true);
  assert.equal(readFileSync(probeSource).length, 256);
  assert.deepEqual(readdirSync(probeParent), []);
});

test("private-key probe cannot be used as an authority-free signing oracle", () => {
  const probeParent = join(TEST_ROOT, "successful-probe-parent");
  mkdirSync(probeParent, { recursive: true });
  const probeSource = join(TEST_ROOT, "successful-probe-source.exe");
  writeFileSync(probeSource, minimalPe());
  const config = loadSigningConfig(storeEnvironment(), { dryRun: true });
  const signature = { Status: "Valid", StatusMessage: "Signature verified.", SignerThumbprint: THUMBPRINT, CanonicalSubject: "CN=ICEFIELDS DEVELOPMENT", TimestampThumbprint: "B".repeat(40), TrustValid: true, TrustClassification: "self-signed", ChainStatuses: [], ...SIGNATURE_VALIDITY };
  const calls = [];
  let signed = false;
  const runner = (command, args, options = {}) => {
    const operation = options.env?.GLACIAL_WINDOWS_HELPER_OPERATION;
    if (operation === "canonical-subject") return { status: 0, stdout: '{"CanonicalSubject":"CN=ICEFIELDS DEVELOPMENT"}', stderr: "" };
    if (operation === "certificate") return { status: 0, stdout: JSON.stringify({ Candidates: [{ Thumbprint: THUMBPRINT, CanonicalSubject: "CN=ICEFIELDS DEVELOPMENT", HasPrivateKey: true, TrustValid: true, TrustClassification: "self-signed", ...CERTIFICATE_VALIDITY }] }), stderr: "" };
    if (operation === "signature") return { status: 0, stdout: JSON.stringify(signed ? signature : { Status: "NotSigned", StatusMessage: "The file is not digitally signed.", SignerThumbprint: null, CanonicalSubject: null, TimestampThumbprint: null, TrustValid: false, TrustClassification: "invalid", ChainStatuses: [] }), stderr: "" };
    if (["sign", "timestamp", "verify"].includes(args[0])) { calls.push(args[0]); if (args[0] === "sign") signed = true; return { status: 0, stdout: "", stderr: "" }; }
    throw new Error(`Unexpected probe command: ${command}`);
  };
  assert.throws(() => preflightSigningProvider(config, { probeParent, probeSource, runner, pathInspector: false }), /authentic authority-derived signing configuration/);
  assert.deepEqual(calls, []);
  assert.deepEqual(readdirSync(probeParent), []);
});

test("application signing cannot reach the provider without current release authority", () => {
  const workingApplication = join(TEST_ROOT, "tauri", "target", "release", "glacial.exe");
  const capture = join(TEST_ROOT, "signing", "application", "Glacial.exe");
  const auditLog = join(TEST_ROOT, "signing", "signing-events.jsonl");
  const nsisScript = join(TEST_ROOT, "tauri", "target", "release", "nsis", "x64", "installer.nsi");
  const failedEvidence = join(TEST_ROOT, "failed-build-evidence.exe");
  mkdirSync(dirname(workingApplication), { recursive: true });
  mkdirSync(dirname(nsisScript), { recursive: true });
  const original = minimalPe();
  writeFileSync(workingApplication, original);
  writeFileSync(failedEvidence, "preserve failed build");
  writeFileSync(nsisScript, `!define MAINBINARYSRCPATH "${workingApplication}"\r\nFile "\${MAINBINARYSRCPATH}"\r\n`);
  const config = {
    ...loadSigningConfig(storeEnvironment({ GLACIAL_WINDOWS_RELEASE_ID: RELEASE_ID, GLACIAL_WINDOWS_SIGN_AUDIT_KEY: AUDIT_KEY }), { dryRun: true }),
    applicationTarget: workingApplication,
    applicationCapture: capture,
    auditLog,
  };
  const signature = { Status: "Valid", StatusMessage: "Signature verified.", SignerThumbprint: THUMBPRINT, CanonicalSubject: "CN=ICEFIELDS DEVELOPMENT", TimestampThumbprint: "B".repeat(40), TrustValid: true, TrustClassification: "self-signed", ChainStatuses: [], ...SIGNATURE_VALIDITY };
  const runner = (command, args, options = {}) => {
    const operation = options.env?.GLACIAL_WINDOWS_HELPER_OPERATION;
    if (operation === "canonical-subject") return { status: 0, stdout: '{"CanonicalSubject":"CN=ICEFIELDS DEVELOPMENT"}', stderr: "" };
    if (operation === "signature") return { status: 0, stdout: JSON.stringify(signature), stderr: "" };
    if (args[0] === "sign") { writeFileSync(args.at(-1), Buffer.concat([readFileSync(args.at(-1)), Buffer.from("signed")])) ; return { status: 0, stdout: "", stderr: "" }; }
    if (["timestamp", "verify"].includes(args[0])) return { status: 0, stdout: "", stderr: "" };
    throw new Error(`Unexpected signing command: ${command}`);
  };

  assert.throws(() => signOne(workingApplication, config, { runner, pathInspector: false, authorization: exactSigningAuthorization(workingApplication, "application", { releaseId: RELEASE_ID, pathInspector: false }) }), /authentic authority-derived signing configuration/);
  assert.deepEqual(readFileSync(workingApplication), original);
  assert.equal(existsSync(capture), false);
  assert.equal(existsSync(auditLog), false);
  assert.equal(assertNsisApplicationSource(nsisScript, workingApplication), workingApplication);
  assert.equal(readFileSync(failedEvidence, "utf8"), "preserve failed build");

  const unrelated = join(TEST_ROOT, "unrelated.exe");
  writeFileSync(unrelated, minimalPe());
  assert.throws(() => signOne(unrelated, config, { runner, pathInspector: false }), /authentic authority-derived signing configuration/);
  assert.throws(() => signOne(unrelated, config, { runner, pathInspector: false, authorization: exactSigningAuthorization(workingApplication, "application", { releaseId: RELEASE_ID, pathInspector: false }) }), /authentic authority-derived signing configuration/);
  assert.equal(existsSync(capture), false);
});

test("Tauri signer authorization binds application and installer roles to canonical paths and digests", () => {
  const root = join(TEST_ROOT, "authorized-tauri");
  const application = join(root, "target", "glacial.exe");
  const installer = join(root, "bundle", "Glacial_0.9.12_x64-setup.exe");
  const generatedPlugin = join(root, "target", "release", "nsis", "x64", "Plugins", "x86-unicode", "NSISdl.dll");
  const generatedAdditionalPlugin = join(dirname(generatedPlugin), "additional", "nsis_tauri_utils.dll");
  const misplacedAdditionalPlugin = join(dirname(generatedPlugin), "nsis_tauri_utils.dll");
  const misplacedDirectPlugin = join(dirname(generatedPlugin), "additional", "NSISdl.dll");
  const cacheSourcePlugin = join(root, "cache", "tauri", "NSIS", "Plugins", "x86-unicode", "NSISdl.dll");
  const unrelated = join(root, "unrelated.exe");
  for (const path of [application, installer, generatedPlugin, generatedAdditionalPlugin, misplacedAdditionalPlugin, misplacedDirectPlugin, cacheSourcePlugin, unrelated]) { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, minimalPe()); }
  const config = { applicationTarget: application, installerTarget: installer, nsisPluginRoot: dirname(generatedPlugin), temporaryRoot: join(root, "temp") };
  assert.equal(defaultTauriNsisPluginRoot(), join(REPOSITORY, "frontend", "src-tauri", "target", "release", "nsis", "x64", "Plugins", "x86-unicode"));
  assert.equal(authorizeTauriSigningRequest(join(dirname(application), ".", basename(application)), config).role, "application");
  assert.equal(authorizeTauriSigningRequest(installer, config).role, "installer");
  assert.equal(authorizeTauriSigningRequest(generatedPlugin, config).role, "nsis-plugin:nsisdl.dll");
  assert.equal(authorizeTauriSigningRequest(generatedAdditionalPlugin, config).role, "nsis-plugin:nsis_tauri_utils.dll");
  assert.throws(() => authorizeTauriSigningRequest(misplacedAdditionalPlugin, config), /authorized Tauri release artifact set/);
  assert.throws(() => authorizeTauriSigningRequest(misplacedDirectPlugin, config), /authorized Tauri release artifact set/);
  assert.throws(() => authorizeTauriSigningRequest(cacheSourcePlugin, config), /authorized Tauri release artifact set/);
  assert.throws(() => authorizeTauriSigningRequest(unrelated, config), /authorized Tauri release artifact set/);
  const authorization = exactSigningAuthorization(application, "application");
  writeFileSync(application, Buffer.concat([readFileSync(application), Buffer.from("substituted")]));
  assert.throws(() => validateSigningAuthorizationState(application, authorization), /pre-signing digest/);
  assert.throws(() => signOne(application, { provider: "store" }, { authorization }), /authentic authority-derived signing configuration/);
});

test("Tauri signer rejects a pre-authorized hardlink alias", () => {
  const root = join(TEST_ROOT, "hardlink-authorization");
  const application = join(root, "target", "glacial.exe");
  const alias = join(root, "retained-alias.exe");
  mkdirSync(dirname(application), { recursive: true });
  writeFileSync(application, minimalPe());
  linkSync(application, alias);
  const config = { applicationTarget: application, releaseId: RELEASE_ID };
  assert.throws(() => authorizeTauriSigningRequest(application, config), /multiple hardlinks/);
});

test("immutable signing plans bind release context and reject object substitution races", () => {
  const target = join(TEST_ROOT, "identity-race.exe");
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, minimalPe());
  const identities = [
    { objectId: "AA:AAAA", linkCount: 1, size: minimalPe().length, reparsePoint: false },
    { objectId: "AA:AAAA", linkCount: 1, size: minimalPe().length, reparsePoint: false },
    { objectId: "AA:BBBB", linkCount: 1, size: minimalPe().length, reparsePoint: false },
  ];
  const objectInspector = () => identities.shift();
  const authorization = exactSigningAuthorization(target, "application", { releaseId: RELEASE_ID, objectInspector });
  assert.equal(Object.isFrozen(authorization), true);
  assert.equal(authorization.releaseId, RELEASE_ID);
  assert.equal(authorization.objectIdentity, "AA:AAAA");
  assert.equal(validateSigningAuthorizationState(target, authorization, { releaseId: RELEASE_ID, objectInspector }), target);
  assert.throws(() => validateSignedAuthorizationState(target, authorization, sha256(target), { objectInspector }), /filesystem object identity changed/);
});

test("direct sign-one, standalone broker, and Tauri wrapper reject invocation-only authority claims", () => {
  const target = join(TEST_ROOT, "direct-entrypoints", "glacial.exe");
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, minimalPe());
  const direct = spawnSync(process.execPath, [join(REPOSITORY, "scripts", "desktop", "windows-signing.mjs"), "sign-one", target], {
    cwd: REPOSITORY,
    env: minimalEnvironment(storeEnvironment()),
    encoding: "utf8",
    shell: false,
  });
  assert.notEqual(direct.status, 0);
  assert.match(direct.stderr, /Direct release-role signing is disabled/);

  const directVerification = spawnSync(process.execPath, [join(REPOSITORY, "scripts", "desktop", "windows-signing.mjs"), "verify-one", target], {
    cwd: REPOSITORY,
    env: minimalEnvironment(storeEnvironment()),
    encoding: "utf8",
    shell: false,
  });
  assert.notEqual(directVerification.status, 0);
  assert.match(directVerification.stderr, /release authority manifest must be an absolute path/);

  const broker = spawnSync(process.execPath, [join(REPOSITORY, "scripts", "desktop", "windows-signing-broker.mjs")], {
    cwd: REPOSITORY,
    env: minimalEnvironment(storeEnvironment({ GLACIAL_WINDOWS_SIGN_BROKER_TOKEN: "a".repeat(64) }), {}, ["GLACIAL_WINDOWS_SIGN_BROKER_TOKEN"]),
    encoding: "utf8",
    shell: false,
    timeout: 10_000,
  });
  assert.notEqual(broker.status, 0);
  assert.match(broker.stderr, /release authority manifest must be an absolute path/);

  const identity = buildIdentityForProfile({
    profile: "signed-preview",
    sourceCommit: "f".repeat(40),
    signerIdentity: { canonicalSubject: "CN=ICEFIELDS DEVELOPMENT", signerThumbprint: THUMBPRINT, trustClassification: "self-signed" },
  });
  const tauriEnvironment = {
    ...process.env,
    GLACIAL_BUILD_IDENTITY_JSON: serializeBuildIdentity(identity),
    GLACIAL_WINDOWS_RELEASE_ID: RELEASE_ID,
    GLACIAL_WINDOWS_SIGN_BROKER_TOKEN: "b".repeat(64),
    GLACIAL_WINDOWS_SIGN_BROKER_PORT: "12345",
    GLACIAL_BACKEND_STAGE_AUTHORITY_JSON: '{"schemaVersion":1,"runtime":[]}',
    GLACIAL_RELEASE_PROFILE: "signed-preview",
  };
  assert.throws(() => runTauriBuild([], tauriEnvironment), /release authority manifest must be an absolute path/);
  assert.deepEqual(readFileSync(target), minimalPe());
});

test("signing rejects same-object byte mutation after the signed hash is captured", () => {
  const target = join(TEST_ROOT, "same-object-byte-race.exe");
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, minimalPe());
  let inspections = 0;
  const objectInspector = () => {
    inspections += 1;
    if (inspections === 2) writeFileSync(target, Buffer.concat([readFileSync(target), Buffer.from("post-hash mutation")]));
    return { objectId: "AA:AAAA", linkCount: 1, size: readFileSync(target).length, reparsePoint: false };
  };
  const authorization = exactSigningAuthorization(target, "installer", { releaseId: RELEASE_ID, objectInspector });
  const signedSha256 = sha256(target);
  assert.throws(() => validateSignedAuthorizationState(target, authorization, signedSha256, { objectInspector }), /signed bytes changed/);
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

test("final signing evidence revalidates the authorized filesystem object", () => {
  const root = join(TEST_ROOT, "final-object-evidence");
  const target = join(root, "glacial.exe");
  const capture = join(root, "Glacial.capture.exe");
  mkdirSync(root, { recursive: true });
  writeFileSync(target, minimalPe());
  writeFileSync(capture, minimalPe());
  const config = { releaseId: RELEASE_ID, expectedThumbprint: THUMBPRINT, applicationTarget: target, applicationCapture: capture };
  const event = {
    path: target,
    artifactRole: "application",
    releaseId: RELEASE_ID,
    objectIdentity: "AA:AAAA",
    evidenceObjectIdentity: "AA:AAAA",
    beforeSha256: "C".repeat(64),
    sha256: sha256(capture),
    applicationCapturePath: capture,
    signerThumbprint: THUMBPRINT,
    canonicalSubject: "CN=ICEFIELDS DEVELOPMENT",
    timestampThumbprint: "B".repeat(40),
  };
  assert.throws(
    () => requireApplicationCapture([event], config, "CN=ICEFIELDS DEVELOPMENT", { objectInspector: () => ({ objectId: "AA:BBBB", linkCount: 1, size: minimalPe().length, reparsePoint: false }) }),
    /object identity changed before final evidence verification/,
  );
});

test("Tauri signing evidence requires one transient uninstaller between plugins and final installer", () => {
  const capture = join(TEST_ROOT, "capture-evidence", "Glacial.exe");
  const target = join(TEST_ROOT, "target-evidence", "glacial.exe");
  const installer = join(TEST_ROOT, "bundle", "Glacial_0.9.12_x64-setup.exe");
  mkdirSync(dirname(capture), { recursive: true });
  writeFileSync(capture, minimalPe());
  const config = { expectedThumbprint: THUMBPRINT, applicationTarget: target, applicationCapture: capture };
  const identity = { beforeSha256: "C".repeat(64), signerThumbprint: THUMBPRINT, canonicalSubject: "CN=ICEFIELDS DEVELOPMENT", timestampThumbprint: "B".repeat(40), applicationCapturePath: null };
  const application = { ...identity, path: target, sha256: sha256(capture), applicationCapturePath: capture };
  const plugins = ["NSISdl.dll", "StartMenu.dll", "System.dll", "nsDialogs.dll", "nsis_tauri_utils.dll"].map((name) => ({ ...identity, path: join(TEST_ROOT, "plugins", name), sha256: "D".repeat(64) }));
  const uninstaller = { ...identity, path: "C:\\Users\\Test\\AppData\\Local\\Temp\\nst1234.tmp", sha256: "E".repeat(64) };
  const installerEvent = { ...identity, path: installer, sha256: "F".repeat(64) };
  assert.equal(requireSigningEvents([application, ...plugins, uninstaller, installerEvent], config, installer, "CN=ICEFIELDS DEVELOPMENT").uninstallerEvent, uninstaller);
  assert.throws(() => requireSigningEvents([application, ...plugins, installerEvent], config, installer, "CN=ICEFIELDS DEVELOPMENT"), /cardinality|transient NSIS uninstaller/);
  assert.throws(() => requireSigningEvents([application, ...plugins, uninstaller, installerEvent, { ...installerEvent, path: join(TEST_ROOT, "extra.exe") }], config, installer, "CN=ICEFIELDS DEVELOPMENT"), /cardinality/);
});

test("Tauri signing evidence binds plugin and installer events to current bytes", () => {
  const root = join(TEST_ROOT, "event-byte-binding");
  const target = join(root, "target", "glacial.exe");
  const capture = join(root, "capture", "Glacial.exe");
  const installer = join(root, "bundle", "Glacial_0.9.12_x64-setup.exe");
  const pluginPaths = ["NSISdl.dll", "StartMenu.dll", "System.dll", "nsDialogs.dll", "nsis_tauri_utils.dll"].map((name) => join(root, "plugins", name));
  for (const path of [target, capture, installer, ...pluginPaths]) { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, minimalPe()); }
  const common = { releaseId: RELEASE_ID, objectIdentity: "AA:AAAA", evidenceObjectIdentity: null, beforeSha256: "C".repeat(64), signerThumbprint: THUMBPRINT, canonicalSubject: "CN=ICEFIELDS DEVELOPMENT", timestampThumbprint: "B".repeat(40), applicationCapturePath: null };
  const application = { ...common, path: target, artifactRole: "application", sha256: sha256(capture), applicationCapturePath: capture, evidenceObjectIdentity: "AA:AAAA" };
  const plugins = pluginPaths.map((path) => ({ ...common, path, artifactRole: `nsis-plugin:${basename(path).toLowerCase()}`, sha256: sha256(path) }));
  const uninstaller = { ...common, path: join(root, "temp", "nst1234.tmp"), artifactRole: "nsis-uninstaller", sha256: "E".repeat(64) };
  const installerEvent = { ...common, path: installer, artifactRole: "installer", sha256: sha256(installer) };
  const config = { releaseId: RELEASE_ID, expectedThumbprint: THUMBPRINT, applicationTarget: target, applicationCapture: capture };
  const options = { objectInspector: () => ({ objectId: "AA:AAAA", linkCount: 1, size: minimalPe().length, reparsePoint: false }) };

  const mismatchedPlugin = plugins.map((event, index) => index === 0 ? { ...event, sha256: "D".repeat(64) } : event);
  assert.throws(() => requireSigningEvents([application, ...mismatchedPlugin, uninstaller, installerEvent], config, installer, "CN=ICEFIELDS DEVELOPMENT", options), /signed bytes do not match the signing event/);

  writeFileSync(installer, Buffer.concat([minimalPe().subarray(0, -1), Buffer.from([1])]));
  assert.throws(() => requireSigningEvents([application, ...plugins, uninstaller, installerEvent], config, installer, "CN=ICEFIELDS DEVELOPMENT", options), /signed bytes do not match the signing event/);
});

test("Tauri signing evidence starts after the immutable backend audit boundary", () => {
  const backend = [{ path: "backend-a" }, { path: "backend-b" }];
  const tauri = [{ path: "application" }, { path: "installer" }];
  assert.deepEqual(tauriSigningEventsAfterBackend([...backend, ...tauri], backend.length), tauri);
  assert.throws(() => tauriSigningEventsAfterBackend([...backend, ...tauri], -1), /audit boundary/);
  assert.throws(() => tauriSigningEventsAfterBackend([...backend, ...tauri], 5), /audit boundary/);
});

test("release source revalidation rejects every mutable provenance field", () => {
  const before = sourceState();
  assert.equal(assertSameReleaseSource(before, sourceState()), true);
  for (const changed of [
    { branch: "feature" },
    { commit: "e".repeat(40) },
    { originMain: "e".repeat(40) },
    { repositoryIdentity: "github.com/attacker/glacial" },
    { authorityDigest: "2".repeat(64) },
    { authorityId: "substituted-authority" },
    { authorityExpiresAtUtc: "2026-09-06T00:00:00.000Z" },
    { authorizedProfiles: ["public-rc"] },
    { authorizedSigningProvider: "command" },
    { status: " M file" },
    { version: "0.9.2" },
    { versions: { packageJson: "0.9.12", tauri: "0.9.4" } },
  ]) assert.throws(() => assertSameReleaseSource(before, sourceState(changed)), /changed/);
});

test("release profile arguments accept only one exact explicit supported profile", () => {
  assert.deepEqual(parseReleaseArguments(["--profile", "signed-preview"]), { profile: "signed-preview", dryRun: false });
  assert.deepEqual(parseReleaseArguments(["--dry-run", "--profile", "public-rc"]), { profile: "public-rc", dryRun: true });
  assert.throws(() => parseReleaseArguments([]), /explicit --profile/);
  assert.throws(() => parseReleaseArguments(["--profile"]), /Unsupported release profile/);
  assert.throws(() => parseReleaseArguments(["--profile", "public"]), /Unsupported release profile/);
  assert.throws(() => parseReleaseArguments(["--profile", "PUBLIC-RC"]), /Unsupported release profile/);
  assert.throws(() => parseReleaseArguments(["--profile=public-rc"]), /Unsupported release argument/);
  assert.throws(() => parseReleaseArguments(["--profile", "public-rc", "--profile", "public-rc"]), /exactly once/);
  assert.throws(() => parseReleaseArguments(["--profile", "public-rc", "--dry-run", "--dry-run"]), /at most once/);
  assert.throws(() => parseReleaseArguments(["--profile", "public-rc", "--bypass-trust"]), /Unsupported release argument/);
});

test("signed construction rejects self-attested primary persistent inputs before use", () => {
  assert.throws(() => assertPreparedReleaseInputs({ schemaVersion: 1 }), /authenticated primary source/);
  assert.throws(
    () => assertPreparedReleaseInputs({
      schemaVersion: 1,
      source: { root: REPOSITORY, branch: "main", commit: "a".repeat(40), originMain: "a".repeat(40) },
    }),
    /exact detached disposable checkout/,
  );
});

test("release profiles accept only their established verified signer trust classifications", () => {
  const selfSigned = { trustClassification: "self-signed" };
  const publiclyTrusted = { trustClassification: "publicly-trusted" };
  assert.equal(assertReleaseProfileTrust("signed-preview", selfSigned), selfSigned);
  assert.equal(assertReleaseProfileTrust("signed-preview", publiclyTrusted), publiclyTrusted);
  assert.equal(assertReleaseProfileTrust("public-rc", publiclyTrusted), publiclyTrusted);
  assert.throws(() => assertReleaseProfileTrust("public-rc", selfSigned), /exactly as publicly-trusted/);
  for (const signerIdentity of [
    undefined,
    {},
    { trustClassification: null },
    { trustClassification: true },
    { trustClassification: "unknown" },
    { trustClassification: "publicly trusted" },
    { trustClassification: "PUBLICLY-TRUSTED" },
  ]) assert.throws(() => assertReleaseProfileTrust("public-rc", signerIdentity), /exactly as publicly-trusted/);
});

test("public trust failure stops immediately after preflight and before every release-producing operation", async () => {
  const operations = [];
  await assert.rejects(() => runAfterSignerPreflight({
    profile: "public-rc",
    preflight: () => {
      operations.push("preflight");
      return { trustClassification: "self-signed" };
    },
    runTrustedSteps: () => operations.push(
      "build",
      "sign",
      "stage",
      "cleanup",
      "tauri",
      "package",
      "copy",
      "metadata",
      "publish",
    ),
  }), /exactly as publicly-trusted/);
  assert.deepEqual(operations, ["preflight"]);
});

test("accepted signer trust reaches release steps only after preflight", async () => {
  for (const [profile, trustClassification] of [
    ["signed-preview", "self-signed"],
    ["signed-preview", "publicly-trusted"],
    ["public-rc", "publicly-trusted"],
  ]) {
    const operations = [];
    const state = await runAfterSignerPreflight({
      profile,
      preflight: () => {
        operations.push("preflight");
        return { trustClassification };
      },
      runTrustedSteps: (releaseState) => {
        operations.push(`run:${releaseState.signerIdentity.trustClassification}`);
      },
    });
    assert.deepEqual(operations, ["preflight", `run:${trustClassification}`]);
    assert.equal(state.signerIdentity.trustClassification, trustClassification);
  }
});

test("dry-run plans and manifest fields report profile trust requirements honestly", () => {
  const config = loadSigningConfig(storeEnvironment(), { dryRun: true });
  const preview = buildDryRunPlan("signed-preview", config);
  const publicRc = buildDryRunPlan("public-rc", config);
  assert.equal(preview.releaseProfile, "signed-preview");
  assert.equal(preview.requiredSignerTrust, "valid-signed-signer");
  assert.equal(publicRc.releaseProfile, "public-rc");
  assert.equal(publicRc.requiredSignerTrust, "publicly-trusted");
  for (const plan of [preview, publicRc]) {
    const preflightIndex = plan.actualSteps.indexOf("preflight-disposable-signature");
    const gateIndex = plan.actualSteps.indexOf("enforce-release-profile-trust");
    const buildIndex = plan.actualSteps.indexOf("build-backend");
    assert.ok(preflightIndex >= 0 && preflightIndex < gateIndex && gateIndex < buildIndex);
    assert.equal(plan.trustGate.after, "preflight-disposable-signature");
    assert.equal(plan.trustGate.before, "build-backend");
  }
  assert.deepEqual(
    releaseProfileManifestFields("signed-preview", { trustClassification: "self-signed" }),
    {
      releaseProfile: "signed-preview",
      requiredSignerTrust: "valid-signed-signer",
      signerTrustClassification: "self-signed",
    },
  );
  assert.deepEqual(
    releaseProfileManifestFields("public-rc", { trustClassification: "publicly-trusted" }),
    {
      releaseProfile: "public-rc",
      requiredSignerTrust: "publicly-trusted",
      signerTrustClassification: "publicly-trusted",
    },
  );
  assert.throws(
    () => releaseProfileManifestFields("public-rc", { trustClassification: "self-signed" }),
    /exactly as publicly-trusted/,
  );
});

test("release package commands and established version sources identify 0.9.12", () => {
  const packageJson = JSON.parse(readFileSync(join(REPOSITORY, "frontend", "package.json"), "utf8"));
  const pnpmLock = readFileSync(join(REPOSITORY, "frontend", "pnpm-lock.yaml"), "utf8");
  const tauri = JSON.parse(readFileSync(join(REPOSITORY, "frontend", "src-tauri", "tauri.conf.json"), "utf8"));
  const cargo = readFileSync(join(REPOSITORY, "frontend", "src-tauri", "Cargo.toml"), "utf8");
  const cargoLock = readFileSync(join(REPOSITORY, "frontend", "src-tauri", "Cargo.lock"), "utf8");
  const releaseTool = readFileSync(join(REPOSITORY, "scripts", "desktop", "Build-SignedWindowsRelease.mjs"), "utf8");
  const signingTool = readFileSync(join(REPOSITORY, "scripts", "desktop", "windows-signing.mjs"), "utf8");
  const backendVersion = readFileSync(join(REPOSITORY, "backend", "app", "version.py"), "utf8");
  const changelog = readFileSync(join(REPOSITORY, "backend", "app", "changelog.py"), "utf8");
  const readme = readFileSync(join(REPOSITORY, "README.md"), "utf8");
  const releaseNotes = readFileSync(join(REPOSITORY, "RELEASE_NOTES.md"), "utf8");
  const signingDocs = readFileSync(join(REPOSITORY, "docs", "windows-release-signing.md"), "utf8");
  const formatPolicy = readFileSync(join(REPOSITORY, "docs", "release", "agent-remediation-format-policy.md"), "utf8");
  const lifecyclePolicy = readFileSync(join(REPOSITORY, "docs", "release", "state-lifecycle-policy.md"), "utf8");
  const readinessAudit = readFileSync(join(REPOSITORY, "docs", "release", "v1.0-gap-audit.md"), "utf8");
  const readinessSnapshot = JSON.parse(readFileSync(join(REPOSITORY, "docs", "release", "v1.0-gap-audit.json"), "utf8"));

  assert.deepEqual({
    signedPreviewPlan: packageJson.scripts["release:windows:signed-preview:plan"],
    signedPreview: packageJson.scripts["release:windows:signed-preview"],
    publicRcPlan: packageJson.scripts["release:windows:public-rc:plan"],
    publicRc: packageJson.scripts["release:windows:public-rc"],
    legacyPlan: packageJson.scripts["release:windows:plan"],
    legacySigned: packageJson.scripts["release:windows:signed"],
  }, {
    signedPreviewPlan: "node ../scripts/desktop/Build-SignedWindowsRelease.mjs --profile signed-preview --dry-run",
    signedPreview: "node ../scripts/release/validate-clean-environment.mjs --profile signed-preview",
    publicRcPlan: "node ../scripts/desktop/Build-SignedWindowsRelease.mjs --profile public-rc --dry-run",
    publicRc: "node ../scripts/release/validate-clean-environment.mjs --profile public-rc",
    legacyPlan: "node ../scripts/desktop/Build-SignedWindowsRelease.mjs --profile signed-preview --dry-run",
    legacySigned: "node ../scripts/release/validate-clean-environment.mjs --profile signed-preview",
  });
  assert.equal(packageJson.scripts.tauri, undefined);
  assert.equal(packageJson.scripts["tauri:build"], undefined);
  assert.equal(tauri.bundle.active, false);
  assert.equal(createTauriSigningOverlay().bundle.active, true);
  assert.match(releaseTool, /Direct signed construction is disabled/);
  assert.deepEqual(
    [packageJson.version, packageJson.packageManager, tauri.version],
    ["0.9.12", "pnpm@11.16.0", "0.9.12"],
  );
  assert.match(pnpmLock, /^lockfileVersion: '9\.0'$/m);
  assert.match(cargo, /^version = "0\.9\.12"$/m);
  assert.match(cargoLock, /\[\[package\]\]\r?\nname = "glacial"\r?\nversion = "0\.9\.12"/);
  assert.match(releaseTool, /expected 0\.9\.12/);
  assert.match(signingTool, /\^Glacial-0\\\.9\\\.12-/);
  assert.match(backendVersion, /^GLACIAL_VERSION = "0\.9\.12"$/m);
  assert.match(changelog, /"version": "0\.9\.12"/);
  assert.match(readme, /Glacial v0\.9\.12 is licensed/);
  assert.match(releaseNotes, /^# Glacial 0\.9\.12 /);
  assert.match(signingDocs, /Glacial v0\.9\.12 is intended/);
  assert.match(formatPolicy, /Glacial application version \| `0\.9\.11`/);
  assert.match(lifecyclePolicy, /Status: v1 policy baseline for Glacial 0\.9\.11\./);
  assert.match(readinessAudit, /Audited product version: `0\.9\.12`/);
  assert.equal(readinessSnapshot.audited_version, "0.9.12");
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
  assert.deepEqual(order, ["hashes", "git", "rename", "hashes"]);
});

test("candidate publication rejects mutation during the atomic rename boundary", () => {
  const workRoot = join(TEST_ROOT, "mutation-release-work", "candidate");
  const finalRoot = join(TEST_ROOT, "mutation-release-candidates", "candidate");
  mkdirSync(workRoot, { recursive: true });
  writeFileSync(join(workRoot, "marker"), "authorized candidate");
  assert.throws(() => publishCandidate({
    workRoot,
    finalRoot,
    sourceBefore: sourceState(),
    integrityVerifier: (root = workRoot) => {
      if (readFileSync(join(root, "marker"), "utf8") !== "authorized candidate") throw new Error("candidate integrity changed");
    },
    sourceVerifier: sourceState,
    renamer: (source, destination) => {
      renameSync(source, destination);
      writeFileSync(join(destination, "marker"), "mutated during publication");
    },
    pathOptions: { pathInspector: false },
  }), /candidate integrity changed/);
});

test("candidate publication rejects an unauthenticated or stale authority before rename", () => {
  const workRoot = join(TEST_ROOT, "authority-release-work", "candidate");
  const finalRoot = join(TEST_ROOT, "authority-release-candidates", "candidate");
  mkdirSync(workRoot, { recursive: true });
  let renamed = false;
  assert.throws(() => publishCandidate({
    workRoot,
    finalRoot,
    sourceBefore: sourceState(),
    sourceVerifier: sourceState,
    releaseAuthority: { authorization: { profiles: ["signed-preview"] } },
    releaseProfile: "signed-preview",
    renamer: () => { renamed = true; },
    pathOptions: { pathInspector: false },
  }), /authentic machine-anchored release authority/);
  assert.equal(renamed, false);
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

test("manifest and SHA256SUMS verification detects post-packaging mutation", () => {
  const root = join(TEST_ROOT, "hashes");
  const artifacts = join(root, "artifacts");
  mkdirSync(artifacts, { recursive: true });
  const artifact = join(artifacts, "Glacial_0.9.12_x64-setup.exe");
  writeFileSync(artifact, "final bytes");
  const hash = sha256(artifact);
  const manifestPath = join(root, "release-candidate-manifest.json");
  const sumsPath = join(root, "SHA256SUMS.txt");
  writeFileSync(manifestPath, JSON.stringify({ artifacts: [{ filename: "Glacial_0.9.12_x64-setup.exe", path: "artifacts/Glacial_0.9.12_x64-setup.exe", bytes: 11, sha256: hash }] }));
  writeFileSync(sumsPath, `${hash}  Glacial_0.9.12_x64-setup.exe\n`);
  assert.equal(verifyPublishedHashes(root, manifestPath, sumsPath), true);
  writeFileSync(manifestPath, JSON.stringify({ artifacts: [{ filename: "Glacial_0.9.12_x64-setup.exe", path: "artifacts/Glacial_0.9.12_x64-setup.exe", bytes: 11, sha256: "f".repeat(63) }] }));
  assert.throws(() => verifyPublishedHashes(root, manifestPath, sumsPath), /sha256 is invalid/);
  writeFileSync(manifestPath, JSON.stringify({ artifacts: [{ filename: "Glacial_0.9.12_x64-setup.exe", path: "artifacts/Glacial_0.9.12_x64-setup.exe", bytes: 11, sha256: hash }] }));
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
  assert.match(docs, /Only the controlled-host administrator may rotate the anchor/);
  assert.match(docs, /out-of-band verification of the new public-key digest/);
  assert.match(docs, /Installing the reviewed key at the protected fixed path is what authorizes the new authority/);
});

test("ordinary unsigned development plans require neither signing nor PowerShell", () => {
  assert.deepEqual(developmentPlan("build-backend"), ["validate unsigned build tools", "build PyInstaller backend"]);
  const plan = runDevelopmentCommand("build-backend", { dryRun: true });
  assert.equal(plan.signingRequired, false);
  assert.equal(plan.certificateRequired, false);
  const packageJson = JSON.parse(readFileSync(join(REPOSITORY, "frontend", "package.json"), "utf8"));
  assert.match(packageJson.scripts["desktop:backend"], /^node /);
  assert.doesNotMatch(packageJson.scripts["desktop:backend"], /ExecutionPolicy|sign/i);
  assert.equal(packageJson.scripts["desktop:portable"], undefined);
  assert.equal(packageJson.scripts["desktop:portable:plan"], undefined);
  assert.throws(() => developmentPlan("build-portable"), /Expected build-backend/);
});

test("pnpm is launched through the absolute Node executable without a command shell", () => {
  const pnpm = resolvePnpmInvocation(process.env, { forbiddenRoot: REPOSITORY });
  assert.ok(pnpm.command.toLowerCase().endsWith("node.exe"));
  assert.match(pnpm.prefixArgs[0], /pnpm.*\.(?:cjs|mjs|js)$/i);
  const result = runCommand(pnpm.command, [...pnpm.prefixArgs, "--version"], { env: minimalEnvironment(process.env) });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /^\d+\.\d+\.\d+/);
});

test("brokered Tauri build passes config without a literal delimiter and preserves both failures", async () => {
  const releaseTool = readFileSync(join(REPOSITORY, "scripts", "desktop", "Build-SignedWindowsRelease.mjs"), "utf8");
  assert.match(releaseTool, /includeFailureOutput: options\.includeFailureOutput === true/);
  assert.match(releaseTool, /includeFailureOutput: true/);
  assert.deepEqual(
    tauriBuildArguments({ prefixArgs: ["C:\\Tools\\pnpm.cjs"] }, "C:\\release\\overlay.json"),
    [join(REPOSITORY, "scripts", "desktop", "tauri-build.mjs"), "--config", "C:\\release\\overlay.json"],
  );
  await assert.rejects(
    runBrokeredTauriBuild(
      () => { throw new Error("underlying Tauri failure"); },
      async () => { throw new Error("incomplete broker sequence"); },
    ),
    /underlying Tauri failure[\s\S]*incomplete broker sequence/,
  );
});

test("unsigned development dry-run commands execute without signing configuration", () => {
  const result = spawnSync(process.execPath, [join(REPOSITORY, "scripts", "desktop", "desktop-development.mjs"), "build-backend", "--dry-run"], { cwd: REPOSITORY, env: minimalEnvironment(process.env), encoding: "utf8", shell: false });
  assert.equal(result.status, 0, result.stderr);
  const plan = JSON.parse(result.stdout);
  assert.equal(plan.signingRequired, false);
  assert.equal(plan.certificateRequired, false);
});
