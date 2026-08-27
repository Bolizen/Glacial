import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  assertAuthenticatedReleaseTool,
  assertDistinctAuthorityPublicKeys,
  authenticateReleaseTool,
  authenticateReleaseTools,
  canonicalRepositoryIdentity,
  loadReleaseAuthority,
  parseReleaseAuthority,
  releaseToolEnvironment,
  verifyDetachedReleaseAuthoritySignature,
} from "./release-authority.mjs";
import { runCommand } from "../desktop/windows-signing.mjs";
import { assertAuthorizedSourceIdentity } from "../desktop/Build-SignedWindowsRelease.mjs";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const testRoot = join(repository, ".desktop-build", "release-authority-tests");

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function manifest(overrides = {}) {
  const tool = { path: process.execPath, sha256: sha256(process.execPath) };
  return {
    schemaVersion: 1,
    authorityId: "G118-test-authority",
    source: { repository: "https://github.com/Bolizen/Glacial.git", commit: "a".repeat(40) },
    tools: Object.fromEntries(["node", "python", "git", "tar", "cargo", "rustc", "linker", "resourceCompiler", "cCompiler", "librarian"].map((role) => [role, tool])),
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
  assert.deepEqual(Object.keys(authority.tools), ["node", "python", "git", "tar", "cargo", "rustc", "linker", "resourceCompiler", "cCompiler", "librarian"]);
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
    GLACIAL_WINDOWS_RELEASE_AUTHORITY_CERTIFICATE_PATH: local,
  }, { repository, expectedThumbprint: "A".repeat(40) }), /must be outside the repository/);
});

test("source authority identity must be distinct from the artifact signer", () => {
  const outsideRepository = resolve(repository, "..", "missing-authority");
  assert.throws(() => loadReleaseAuthority({
    GLACIAL_WINDOWS_RELEASE_AUTHORITY_PATH: outsideRepository,
    GLACIAL_WINDOWS_RELEASE_AUTHORITY_SIGNATURE_PATH: outsideRepository,
    GLACIAL_WINDOWS_RELEASE_AUTHORITY_CERTIFICATE_PATH: outsideRepository,
  }, { repository, expectedThumbprint: "A".repeat(40), forbiddenThumbprint: "A".repeat(40) }), /must be independent/);
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
  const environmentTools = Object.fromEntries(["cargo", "rustc", "linker", "resourceCompiler", "cCompiler", "librarian"]
    .map((role) => [role, authenticateReleaseTool({ role, path: process.execPath, sha256: sha256(process.execPath) })]));
  const environment = releaseToolEnvironment({ PATH: `${fakeBin};${process.env.PATH}` }, environmentTools);
  assert.equal(assertAuthenticatedReleaseTool(tool), approved);
  assert.equal(environment.PATH.split(";")[0], dirname(process.execPath));

  writeFileSync(approved, "same version but modified bytes");
  assert.throws(() => assertAuthenticatedReleaseTool(tool), /digest does not match/);
  writeFileSync(approved, "approved tool bytes");
  tool = authenticateReleaseTool(record);
  renameSync(approved, displaced);
  writeFileSync(approved, "approved tool bytes");
  assert.throws(() => assertAuthenticatedReleaseTool(tool), /filesystem identity changed/);
});

test("copied rustup proxies are rejected without relying on a sibling rustup executable", { skip: process.platform !== "win32" }, () => {
  const proxy = resolve(process.env.USERPROFILE ?? "", ".cargo", "bin", "cargo.exe");
  if (!existsSync(proxy)) return;
  const copied = join(testRoot, "cargo.exe");
  copyFileSync(proxy, copied);
  assert.throws(() => authenticateReleaseTool({ role: "cargo", path: copied, sha256: sha256(copied) }), /not a rustup proxy/);
});

test("legitimate approved Node toolset executes through the shared pre-launch boundary", () => {
  const authority = parseReleaseAuthority(Buffer.from(JSON.stringify(manifest())));
  const tools = authenticateReleaseTools(authority, { node: process.execPath, python: process.execPath });
  const fakeBin = join(testRoot, "hostile-path");
  mkdirSync(fakeBin);
  for (const role of ["git", "tar", "cargo", "rustc"]) writeFileSync(join(fakeBin, `${role}.exe`), `fake ${role}`);
  const environment = releaseToolEnvironment({ ...process.env, PATH: `${fakeBin};${process.env.PATH}` }, tools);
  for (const role of ["git", "tar", "cargo", "rustc"]) {
    const result = runCommand(tools[role], ["-e", `process.stdout.write('${role}')`], { env: environment });
    assert.equal(result.stdout, role);
  }
});
