import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, X509Certificate } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  assertAuthenticatedReleaseTool,
  assertDistinctAuthorityPublicKeys,
  assertExecutingNodeTool,
  authenticateReleaseTool,
  authenticateReleaseTools,
  canonicalRepositoryIdentity,
  loadReleaseAuthority,
  parseReleaseAuthority,
  REQUIRED_RELEASE_TOOL_ROLES,
  revalidateReleaseTool,
  releaseToolEnvironment,
  TRUSTED_RELEASE_AUTHORITY_PUBLIC_KEY_PATH,
  validateReleaseAuthorityBundle,
  validateCanonicalReleaseCheckoutObservation,
  validateReleaseAuthorityScope,
  verifyDetachedReleaseAuthoritySignature,
} from "./release-authority.mjs";
import { runCommand } from "../desktop/windows-signing.mjs";
import * as windowsSigning from "../desktop/windows-signing.mjs";
import { assertAuthorizedSourceIdentity } from "../desktop/Build-SignedWindowsRelease.mjs";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const testRoot = join(repository, ".desktop-build", "release-authority-tests");
const ARTIFACT_CERTIFICATE = new X509Certificate(Buffer.from("MIICwTCCAamgAwIBAgIJALsbm4mXf6qaMA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNVBAMTFUljZWZpZWxkcyBEZXZlbG9wbWVudDAeFw0yNjA4MjYxNzI3NDNaFw0zMTA4MjcxNzI3NDNaMCAxHjAcBgNVBAMTFUljZWZpZWxkcyBEZXZlbG9wbWVudDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALogi/FVDefTZ9RmI8IZAN3iVAWhg1FEIIEZ1Ab2YaviMgwnwFBO+NvViU0Rd4lGSYZ2FvfvA00XzD6/NcmnIhiop4Ak59pAm893d3juTcels/pJnBfdJij8CL+7UH+BAPa1J0tZQgOpKcSNRoD2qt0wFF4YIcXaW+0WW9WQdil0+kHsLWp6MgiKIc6xzHGAqelQLcbBLeer6zhsmxzuLvwuizhqp8rGpK7EokJluLQqsLrSwBaUA4tvcgI5LnUU4HOywUqAm8ZzbE4X/LyiilyAlGqKRIkFA4YuoC/Qio0R9I0EGJQeaCyFYFEcREglzhI+INHUCXhBkRHDGfCMfTECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAYjEfXLsfsYSv0VoNOYGDg5BtJ+WXbm9owsHrArIrgOuZhhl8tFjr0Zq4iS8WqQwfcqfxRKd8TA+QaPyOEds2VqmTA2e6cdds3UA8IfAmuXfY8GnFBbSbpwcHAQYgaZ5K2F8y/3vF0tScj8DF6o7FvE3plMGSnoUv4xGpzEy30C96EtabiDwdeTSJRwqPXHc8quZVek31EgCO1WSFI+fVZQ+oaaPStj8XS9M9h2CvEwEmqM+FJF6paHmVFxEkUJPxUXxoJ8RXZUnSu/HLUsDmmCZC3pMgqcWyic41beuF7Hp9D6X6t/Z7BaOA3hvhPH1uw5iKmxoBzinVZhwtBwRCQw==", "base64"));

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function manifest(overrides = {}) {
  const tool = { path: process.execPath, sha256: sha256(process.execPath) };
  const artifactSpki = ARTIFACT_CERTIFICATE.publicKey.export({ type: "spki", format: "der" });
  return {
    schemaVersion: 2,
    authorityId: "G120-test-authority",
    authorization: { issuedAtUtc: "2026-08-27T00:00:00.000Z", expiresAtUtc: "2026-09-05T00:00:00.000Z", profiles: ["signed-preview"] },
    source: { repository: "https://github.com/Bolizen/Glacial.git", commit: "a".repeat(40) },
    tools: Object.fromEntries(REQUIRED_RELEASE_TOOL_ROLES.map((role) => [role, tool])),
    signing: {
      provider: "store",
      expectedSubject: "CN=Icefields Development",
      expectedThumbprint: ARTIFACT_CERTIFICATE.fingerprint,
      artifactSignerSpkiSha256: createHash("sha256").update(artifactSpki).digest("hex"),
      timestampUrl: "https://timestamp.digicert.com/",
      commandArgs: [],
      providerEnvironmentNames: [],
    },
    ...overrides,
  };
}

test.beforeEach(() => {
  rmSync(testRoot, { recursive: true, force: true });
  mkdirSync(testRoot, { recursive: true });
});

test.after(() => rmSync(testRoot, { recursive: true, force: true }));

test("detached authority signature rejects copied, changed, recomputed, and substituted authorization", () => {
  const bytes = Buffer.from(JSON.stringify(manifest()));
  const first = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const second = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const signature = sign("sha256", bytes, first.privateKey);
  assert.equal(verifyDetachedReleaseAuthoritySignature(bytes, signature, first.publicKey), true);
  assert.throws(() => verifyDetachedReleaseAuthoritySignature(Buffer.concat([bytes, Buffer.from(" ")]), signature, first.publicKey), /signature is invalid/);
  assert.throws(() => verifyDetachedReleaseAuthoritySignature(bytes, signature, second.publicKey), /signature is invalid/);
  const substituted = sign("sha256", Buffer.from(JSON.stringify(manifest({ authorityId: "attacker-authority" }))), second.privateKey);
  assert.throws(() => verifyDetachedReleaseAuthoritySignature(bytes, substituted, first.publicKey), /signature is invalid/);
});

test("authority parser binds exactly one intended repository, commit, and complete tool set", () => {
  const authority = parseReleaseAuthority(Buffer.from(JSON.stringify(manifest())));
  assert.equal(authority.source.repository, "github.com/bolizen/glacial");
  assert.equal(authority.source.commit, "a".repeat(40));
  assert.deepEqual(Object.keys(authority.tools), REQUIRED_RELEASE_TOOL_ROLES);
  for (const repositoryUrl of [
    "https://github.com/Bolizen/Glacial.git",
    "git@github.com:Bolizen/Glacial.git",
    "ssh://git@github.com/Bolizen/Glacial.git",
  ]) assert.equal(canonicalRepositoryIdentity(repositoryUrl), "github.com/bolizen/glacial");
  for (const repositoryUrl of [
    "https://github.com/attacker/Glacial.git",
    "https://user@github.com/Bolizen/Glacial.git",
    "file:///C:/Glacial",
  ]) assert.throws(() => canonicalRepositoryIdentity(repositoryUrl), /approved Glacial source/);
  const incomplete = manifest();
  delete incomplete.tools.tar;
  assert.throws(() => parseReleaseAuthority(Buffer.from(JSON.stringify(incomplete))), /exactly the required release tools/);
});

test("production authority inputs fail closed when missing or stored inside the checkout", () => {
  assert.throws(() => loadReleaseAuthority({}, { repository, expectedThumbprint: "A".repeat(40) }), /must be an absolute path/);
  const local = join(testRoot, "authority.json");
  writeFileSync(local, JSON.stringify(manifest()));
  assert.throws(() => loadReleaseAuthority({
    GLACIAL_WINDOWS_RELEASE_AUTHORITY_PATH: local,
    GLACIAL_WINDOWS_RELEASE_AUTHORITY_SIGNATURE_PATH: local,
    GLACIAL_WINDOWS_ARTIFACT_SIGNER_CERTIFICATE_PATH: local,
  }, { repository, expectedThumbprint: "A".repeat(40) }), /must be outside the repository/);
});

test("replacement authority key is rejected even with a self-consistent caller bundle", () => {
  const trusted = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const attacker = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const legitimateBytes = Buffer.from(JSON.stringify(manifest()));
  const legitimateSignature = sign("sha256", legitimateBytes, trusted.privateKey);
  assert.equal(validateReleaseAuthorityBundle({
    manifestBytes: legitimateBytes,
    signatureBytes: legitimateSignature,
    trustedPublicKey: trusted.publicKey,
    artifactCertificate: ARTIFACT_CERTIFICATE,
    now: new Date("2026-08-28T00:00:00.000Z"),
  }).authorityId, "G120-test-authority");
  const attackerBytes = Buffer.from(JSON.stringify(manifest({ authorityId: "attacker-authority" })));
  const attackerSignature = sign("sha256", attackerBytes, attacker.privateKey);
  assert.throws(() => validateReleaseAuthorityBundle({
    manifestBytes: attackerBytes,
    signatureBytes: attackerSignature,
    trustedPublicKey: trusted.publicKey,
    artifactCertificate: ARTIFACT_CERTIFICATE,
    now: new Date("2026-08-28T00:00:00.000Z"),
  }), /signature is invalid/);
  assert.equal(TRUSTED_RELEASE_AUTHORITY_PUBLIC_KEY_PATH, "C:\\Program Files\\Icefields\\Glacial Release Policy\\release-authority-public-key.pem");
});

test("signed release scope rejects stale, future, overlong, and wrong-profile authorization", () => {
  const authority = parseReleaseAuthority(Buffer.from(JSON.stringify(manifest())));
  assert.equal(validateReleaseAuthorityScope(authority, { now: new Date("2026-08-28T00:00:00.000Z"), profile: "signed-preview" }), authority);
  assert.throws(() => validateReleaseAuthorityScope(authority, { now: new Date("2026-09-05T00:00:00.000Z") }), /expired/);
  assert.throws(() => validateReleaseAuthorityScope(authority, { now: new Date("2026-08-01T00:00:00.000Z") }), /not yet valid/);
  assert.throws(() => validateReleaseAuthorityScope(authority, { now: new Date("2026-08-28T00:00:00.000Z"), profile: "public-rc" }), /not authorized/);
  const overlong = manifest({ authorization: { issuedAtUtc: "2026-08-01T00:00:00.000Z", expiresAtUtc: "2026-09-01T00:00:00.000Z", profiles: ["signed-preview"] } });
  assert.throws(() => parseReleaseAuthority(Buffer.from(JSON.stringify(overlong))), /no longer than fourteen days/);
});

test("source authority rejects the artifact signer's public key even under another certificate identity", () => {
  const first = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const second = generateKeyPairSync("rsa", { modulusLength: 2048 });
  assert.equal(assertDistinctAuthorityPublicKeys(first.publicKey, second.publicKey), true);
  assert.throws(() => assertDistinctAuthorityPublicKeys(first.publicKey, first.publicKey), /public key must be independent/);
});

test("source authorization rejects aligned unauthorized refs, stale refs, and wrong repository identity", () => {
  const authority = parseReleaseAuthority(Buffer.from(JSON.stringify(manifest())));
  const approved = { commit: "a".repeat(40), originMain: "a".repeat(40), originUrl: "https://github.com/Bolizen/Glacial.git" };
  assert.equal(assertAuthorizedSourceIdentity(approved, authority), "github.com/bolizen/glacial");
  assert.throws(() => assertAuthorizedSourceIdentity({ ...approved, commit: "b".repeat(40), originMain: "b".repeat(40) }, authority), /not the independently authorized/);
  assert.throws(() => assertAuthorizedSourceIdentity({ ...approved, originMain: "b".repeat(40) }, authority), /does not match origin\/main/);
  assert.throws(() => assertAuthorizedSourceIdentity({ ...approved, originUrl: "https://github.com/attacker/Glacial.git" }, authority), /approved Glacial source/);
});

test("authenticated tools ignore earlier PATH entries and fail on byte or object replacement", () => {
  const approved = join(testRoot, "approved.exe");
  const displaced = join(testRoot, "approved.original.exe");
  const fakeBin = join(testRoot, "fake-bin");
  mkdirSync(fakeBin);
  writeFileSync(approved, "approved tool bytes");
  writeFileSync(join(fakeBin, "git.exe"), "fake git");
  const record = { role: "git", path: approved, sha256: sha256(approved) };
  let tool = authenticateReleaseTool(record);
  assert.equal(revalidateReleaseTool(tool), approved);

  writeFileSync(approved, "same version but modified bytes");
  assert.throws(() => revalidateReleaseTool(tool), /digest does not match/);
  writeFileSync(approved, "approved tool bytes");
  tool = authenticateReleaseTool(record);
  renameSync(approved, displaced);
  writeFileSync(approved, "approved tool bytes");
  assert.throws(() => revalidateReleaseTool(tool), /filesystem identity changed/);
});

test("PowerShell, SignTool, and command-provider substitutions fail the signed tool boundary", () => {
  for (const role of ["powerShell", "signTool", "signingProvider"]) {
    const approved = join(testRoot, `${role}.exe`);
    const replacement = join(testRoot, `${role}.replacement.exe`);
    writeFileSync(approved, `${role} approved bytes`);
    const record = { role, path: approved, sha256: sha256(approved) };
    const tool = authenticateReleaseTool(record);
    writeFileSync(approved, `${role} substituted bytes`);
    assert.throws(() => revalidateReleaseTool(tool), new RegExp(`tool ${role} digest does not match`));
    writeFileSync(approved, `${role} approved bytes`);
    const restored = authenticateReleaseTool(record);
    renameSync(approved, replacement);
    writeFileSync(approved, `${role} approved bytes`);
    assert.throws(() => revalidateReleaseTool(restored), new RegExp(`tool ${role} filesystem identity changed`));
  }
  const combined = ["powerShell", "signTool", "signingProvider"].map((role) => {
    const path = join(testRoot, `combined-${role}.exe`);
    writeFileSync(path, `${role} combined approved bytes`);
    return { role, path, tool: authenticateReleaseTool({ role, path, sha256: sha256(path) }) };
  });
  for (const item of combined) {
    renameSync(item.path, `${item.path}.original`);
    writeFileSync(item.path, `${item.role} combined approved bytes`);
  }
  for (const item of combined) assert.throws(() => revalidateReleaseTool(item.tool), /filesystem identity changed/);
});

test("copied rustup proxies are rejected without relying on a sibling rustup executable", { skip: process.platform !== "win32" }, () => {
  const proxy = resolve(process.env.USERPROFILE ?? "", ".cargo", "bin", "cargo.exe");
  if (!existsSync(proxy)) return;
  const copied = join(testRoot, "cargo.exe");
  copyFileSync(proxy, copied);
  assert.throws(() => authenticateReleaseTool({ role: "cargo", path: copied, sha256: sha256(copied) }), /not a rustup proxy/);
});

test("parsed authority data cannot mint executable tool capabilities", () => {
  const authority = parseReleaseAuthority(Buffer.from(JSON.stringify(manifest())));
  assert.throws(() => authenticateReleaseTools(authority, { node: process.execPath, python: process.execPath }), /authentic machine-anchored release authority/);
  assert.throws(() => releaseToolEnvironment(process.env, { cargo: authenticateReleaseTool({ role: "cargo", path: process.execPath, sha256: sha256(process.execPath) }) }), /authenticated release tool/);
});

test("a legitimate current test authority and signer cannot use the external product-signing import chain", () => {
  const trusted = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const manifestBytes = Buffer.from(JSON.stringify(manifest()));
  const authority = validateReleaseAuthorityBundle({
    manifestBytes,
    signatureBytes: sign("sha256", manifestBytes, trusted.privateKey),
    trustedPublicKey: trusted.publicKey,
    artifactCertificate: ARTIFACT_CERTIFICATE,
    now: new Date("2026-08-28T00:00:00.000Z"),
  });
  assert.equal(validateReleaseAuthorityScope(authority, { now: new Date("2026-08-28T00:00:00.000Z"), profile: "signed-preview" }), authority);
  let signerCalls = 0;
  const signer = () => { signerCalls += 1; };
  assert.throws(() => windowsSigning.loadSigningConfig({
    GLACIAL_WINDOWS_RELEASE_ID: "Glacial-0.9.12-aaaaaaaaaaaa-20260828T000000Z",
    GLACIAL_WINDOWS_SIGN_AUDIT_KEY: "9".repeat(64),
  }, { authority, profile: "signed-preview", signer }), /private to an authenticated release signing session/);
  for (const name of ["exactSigningAuthorization", "signOne", "signBackendTree", "authorizeTauriSigningRequest"]) {
    assert.equal(windowsSigning[name], undefined);
  }
  assert.equal(signerCalls, 0);
});

test("an approved Node record for a different executable cannot authorize the executing runtime", () => {
  const approvedNode = join(testRoot, "approved-node.exe");
  copyFileSync(process.execPath, approvedNode);
  const tool = authenticateReleaseTool({ role: "node", path: approvedNode, sha256: sha256(approvedNode) });
  assert.throws(() => assertExecutingNodeTool(tool), /executing Node runtime is not the signed Node tool/);
});

test("canonical coordinator checkout observations reject sibling and alternate Git relationships", () => {
  const primaryRepository = resolve("Z:\\approved-glacial");
  const releaseRepository = join(primaryRepository, "dist");
  const gitCommonDirectory = join(primaryRepository, ".git");
  const observation = {
    primaryRepository,
    releaseRepository,
    gitCommonDirectory,
    releaseCommonDirectory: gitCommonDirectory,
    primaryGitDirectory: gitCommonDirectory,
    releaseGitDirectory: join(gitCommonDirectory, "worktrees", "dist"),
    coordinatorScript: { sha256: "a".repeat(64) },
    authorizedCoordinatorScript: { sha256: "a".repeat(64) },
  };
  assert.equal(validateCanonicalReleaseCheckoutObservation(observation), observation);
  assert.throws(() => validateCanonicalReleaseCheckoutObservation({
    ...observation,
    releaseRepository: resolve("Z:\\sibling-glacial\\dist"),
  }), /canonical dist worktree/);
  assert.throws(() => validateCanonicalReleaseCheckoutObservation({
    ...observation,
    releaseCommonDirectory: resolve("Z:\\sibling-glacial\\.git"),
  }), /primary\/worktree Git relationship/);
  assert.throws(() => validateCanonicalReleaseCheckoutObservation({
    ...observation,
    authorizedCoordinatorScript: { sha256: "b".repeat(64) },
  }), /exact authorized checkout/);
});
