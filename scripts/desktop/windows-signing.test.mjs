import test from "node:test";
import assert from "node:assert/strict";
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
  createPowerShellInvocation,
  createTauriSigningOverlay,
  isPortableExecutable,
  loadSigningConfig,
  minimalEnvironment,
  normalizeThumbprint,
  planBackendSigning,
  preflightSigningProvider,
  removeSafeTree,
  resolveNpmInvocation,
  runCommand,
  sha256,
  signingEnvironment,
} from "./windows-signing.mjs";
import {
  assertFileIdentity,
  assertSameReleaseSource,
  publishCandidate,
  runReleaseSteps,
  verifyPublishedHashes,
} from "./Build-SignedWindowsRelease.mjs";
import { developmentPlan, runDevelopmentCommand } from "./desktop-development.mjs";

const TEST_PATH = fileURLToPath(import.meta.url);
const REPOSITORY = resolve(dirname(TEST_PATH), "..", "..");
const TEST_ROOT = join(DESKTOP_BUILD_ROOT, "release-signing-tests");
const FAILED_RC = join(DESKTOP_BUILD_ROOT, "release-candidates", "Glacial-0.4.0-fbf96d568350-20260719T065059Z");
const THUMBPRINT = "A".repeat(40);

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

function sourceState(overrides = {}) {
  return {
    root: REPOSITORY,
    branch: "main",
    commit: "f".repeat(40),
    originMain: "f".repeat(40),
    version: "0.4.0",
    status: "",
    versions: { packageJson: "0.4.0", tauri: "0.4.0" },
    ...overrides,
  };
}

test.beforeEach(cleanTestRoot);
test.after(cleanTestRoot);

test("PowerShell helper transports hostile paths only through environment JSON", () => {
  const hostile = "C:\\Repo With Space\\quote' ; & | (payload)\\Glacial.exe";
  const invocation = createPowerShellInvocation("signature", { path: hostile }, process.env);
  assert.ok(invocation.command.toLowerCase().endsWith("powershell.exe"));
  assert.deepEqual(invocation.args.slice(0, 3), ["-NoProfile", "-NonInteractive", "-Command"]);
  assert.equal(invocation.args.some((argument) => argument.includes(hostile)), false);
  assert.equal(JSON.parse(invocation.env.GLACIAL_WINDOWS_HELPER_PAYLOAD).path, hostile);
  assert.equal(invocation.args.some((argument) => argument.includes("GLACIAL_WINDOWS_HELPER_PAYLOAD")), true);
});

test("timestamp URLs are HTTPS and credential/query/fragment free", () => {
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

test("store arguments require SHA-256 and RFC 3161 timestamping", () => {
  const config = loadSigningConfig(storeEnvironment(), { dryRun: true });
  const args = buildStoreSignArgs(config, "C:\\Payload With Space\\Glacial.exe");
  assert.deepEqual(args.slice(0, 6), ["sign", "/fd", "SHA256", "/sha1", THUMBPRINT, "/d"]);
  assert.ok(args.includes("/tr"));
  assert.ok(args.includes("/td"));
  assert.equal(args.at(-1), "C:\\Payload With Space\\Glacial.exe");
});

test("command provider keeps the file as one direct argument and forwards only named environment", () => {
  const source = commandEnvironment({
    GLACIAL_WINDOWS_SIGN_COMMAND_ENV: '["AZURE_CLIENT_ID"]',
    AZURE_CLIENT_ID: "allowed-value",
    AZURE_CLIENT_SECRET: "not-allowed",
    AWS_SECRET_ACCESS_KEY: "not-allowed-either",
  });
  const releaseEnvironment = signingEnvironment(source, "Glacial-0.4.0-ffffffffffff-20260719T120000Z");
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
  const runner = (command, args, options = {}) => {
    const operation = options.env?.GLACIAL_WINDOWS_HELPER_OPERATION;
    if (operation === "canonical-subject") return { status: 0, stdout: '{"CanonicalSubject":"CN=ICEFIELDS DEVELOPMENT"}', stderr: "" };
    if (operation === "certificate") return { status: 0, stdout: JSON.stringify({ Candidates: [{ Thumbprint: THUMBPRINT, CanonicalSubject: "CN=ICEFIELDS DEVELOPMENT", HasPrivateKey: true, TrustValid: true, TrustClassification: "self-signed" }] }), stderr: "" };
    if (args[0] === "sign") throw new Error("timestamp service unavailable");
    throw new Error(`Unexpected probe command: ${command}`);
  };
  assert.throws(() => preflightSigningProvider(config, { probeParent, probeSource, runner, pathInspector: false }), /timestamp service unavailable/);
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
  const runner = (command, args, options = {}) => {
    const operation = options.env?.GLACIAL_WINDOWS_HELPER_OPERATION;
    if (operation === "canonical-subject") return { status: 0, stdout: '{"CanonicalSubject":"CN=ICEFIELDS DEVELOPMENT"}', stderr: "" };
    if (operation === "certificate") return { status: 0, stdout: JSON.stringify({ Candidates: [{ Thumbprint: THUMBPRINT, CanonicalSubject: "CN=ICEFIELDS DEVELOPMENT", HasPrivateKey: true, TrustValid: true, TrustClassification: "self-signed" }] }), stderr: "" };
    if (operation === "signature") return { status: 0, stdout: JSON.stringify(signature), stderr: "" };
    if (args[0] === "sign" || args[0] === "verify") return { status: 0, stdout: "", stderr: "" };
    throw new Error(`Unexpected probe command: ${command}`);
  };
  const identity = preflightSigningProvider(config, { probeParent, probeSource, runner, pathInspector: false });
  assert.equal(identity.signerThumbprint, THUMBPRINT);
  assert.equal(identity.trustClassification, "self-signed");
  assert.deepEqual(readdirSync(probeParent), []);
});

test("release source revalidation rejects every mutable provenance field", () => {
  const before = sourceState();
  assert.equal(assertSameReleaseSource(before, sourceState()), true);
  for (const changed of [
    { branch: "feature" },
    { commit: "e".repeat(40) },
    { originMain: "e".repeat(40) },
    { status: " M file" },
    { version: "0.4.1" },
    { versions: { packageJson: "0.4.1", tauri: "0.4.0" } },
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
