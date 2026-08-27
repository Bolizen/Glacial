import { spawnSync } from "node:child_process";
import { constants as cryptoConstants, createHash, verify, X509Certificate } from "node:crypto";
import { existsSync, lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

export const GLACIAL_REPOSITORY_IDENTITY = "github.com/bolizen/glacial";
export const REQUIRED_RELEASE_TOOL_ROLES = Object.freeze([
  "node", "python", "git", "tar", "cargo", "rustc", "linker", "resourceCompiler", "cCompiler", "librarian",
]);

function fail(message) {
  throw new Error(`Release authority check failed: ${message}`);
}

function sha256Bytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function normalizedPath(path) {
  return resolve(path).toLowerCase();
}

function isRepositoryChild(repository, target) {
  const child = relative(resolve(repository), resolve(target));
  return !child || (!child.startsWith(`..${sep}`) && child !== ".." && !isAbsolute(child));
}

function requireIndependentFile(path, label, repository) {
  if (typeof path !== "string" || !isAbsolute(path)) fail(`${label} must be an absolute path.`);
  const target = resolve(path);
  if (isRepositoryChild(repository, target)) fail(`${label} must be outside the repository.`);
  let metadata;
  try { metadata = lstatSync(target, { bigint: true }); } catch { fail(`${label} is missing.`); }
  if (!metadata.isFile() || metadata.isSymbolicLink()) fail(`${label} must be a normal file.`);
  let canonical;
  try { canonical = realpathSync.native(target); } catch { fail(`${label} could not be canonicalized.`); }
  if (normalizedPath(canonical) !== normalizedPath(target)) fail(`${label} must not be redirected.`);
  return target;
}

function normalizedThumbprint(value) {
  const normalized = String(value ?? "").replaceAll(/[^0-9A-F]/gi, "").toUpperCase();
  if (!/^[0-9A-F]{40}$/.test(normalized)) fail("the expected signer thumbprint is invalid.");
  return normalized;
}

export function canonicalRepositoryIdentity(value) {
  const text = String(value ?? "").trim();
  if (/^https:\/\/github\.com\/Bolizen\/Glacial(?:\.git)?\/?$/i.test(text)
      || /^git@github\.com:Bolizen\/Glacial(?:\.git)?$/i.test(text)
      || /^ssh:\/\/git@github\.com\/Bolizen\/Glacial(?:\.git)?\/?$/i.test(text)) {
    return GLACIAL_REPOSITORY_IDENTITY;
  }
  fail("the repository identity is not the approved Glacial source.");
}

export function verifyDetachedReleaseAuthoritySignature(manifestBytes, signatureBytes, publicKey) {
  const accepted = verify("sha256", manifestBytes, {
    key: publicKey,
    padding: cryptoConstants.RSA_PKCS1_PADDING,
  }, signatureBytes);
  if (!accepted) fail("the detached authority signature is invalid.");
  return true;
}

export function assertDistinctAuthorityPublicKeys(authorityPublicKey, artifactSignerPublicKey) {
  const authoritySpki = authorityPublicKey.export({ type: "spki", format: "der" });
  const artifactSpki = artifactSignerPublicKey.export({ type: "spki", format: "der" });
  if (authoritySpki.equals(artifactSpki)) fail("the release authority public key must be independent of the artifact signer.");
  return true;
}

function validateToolRecord(role, record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) fail(`tool ${role} is missing.`);
  if (typeof record.path !== "string" || !isAbsolute(record.path)) fail(`tool ${role} path must be absolute.`);
  if (!/^[0-9a-f]{64}$/.test(String(record.sha256 ?? ""))) fail(`tool ${role} SHA-256 is invalid.`);
  return Object.freeze({ role, path: resolve(record.path), sha256: record.sha256 });
}

export function parseReleaseAuthority(manifestBytes) {
  let manifest;
  try { manifest = JSON.parse(Buffer.from(manifestBytes).toString("utf8")); } catch { fail("the authority manifest is malformed JSON."); }
  if (!manifest || manifest.schemaVersion !== 1 || typeof manifest.authorityId !== "string"
      || !/^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/.test(manifest.authorityId)) fail("the authority manifest header is invalid.");
  if (!manifest.source || typeof manifest.source !== "object") fail("source authorization is missing.");
  const repository = canonicalRepositoryIdentity(manifest.source.repository);
  const commit = String(manifest.source.commit ?? "");
  if (!/^[0-9a-f]{40}$/.test(commit)) fail("the authorized source commit is invalid.");
  if (!manifest.tools || typeof manifest.tools !== "object" || Array.isArray(manifest.tools)) fail("tool authorization is missing.");
  const toolNames = Object.keys(manifest.tools).sort();
  if (JSON.stringify(toolNames) !== JSON.stringify([...REQUIRED_RELEASE_TOOL_ROLES].sort())) {
    fail("the authority manifest must contain exactly the required release tools.");
  }
  const tools = Object.fromEntries(REQUIRED_RELEASE_TOOL_ROLES.map((role) => [role, validateToolRecord(role, manifest.tools[role])]));
  return Object.freeze({
    schemaVersion: 1,
    authorityId: manifest.authorityId,
    digest: sha256Bytes(manifestBytes),
    source: Object.freeze({ repository, commit }),
    tools: Object.freeze(tools),
  });
}

export function loadReleaseAuthority(environment, options) {
  const repository = resolve(options?.repository ?? "");
  const authorityThumbprint = normalizedThumbprint(options.expectedThumbprint);
  if (options.forbiddenThumbprint && authorityThumbprint === normalizedThumbprint(options.forbiddenThumbprint)) {
    fail("the release authority must be independent of the artifact-signing certificate.");
  }
  const manifestPath = requireIndependentFile(environment.GLACIAL_WINDOWS_RELEASE_AUTHORITY_PATH, "release authority manifest", repository);
  const signaturePath = requireIndependentFile(environment.GLACIAL_WINDOWS_RELEASE_AUTHORITY_SIGNATURE_PATH, "release authority signature", repository);
  const certificatePath = requireIndependentFile(environment.GLACIAL_WINDOWS_RELEASE_AUTHORITY_CERTIFICATE_PATH, "release authority certificate", repository);
  const artifactCertificatePath = requireIndependentFile(environment.GLACIAL_WINDOWS_ARTIFACT_SIGNER_CERTIFICATE_PATH, "artifact signer public certificate", repository);
  const manifestBytes = readFileSync(manifestPath);
  const signatureBytes = readFileSync(signaturePath);
  let certificate;
  try { certificate = new X509Certificate(readFileSync(certificatePath)); } catch { fail("the release authority certificate is invalid."); }
  let artifactCertificate;
  try { artifactCertificate = new X509Certificate(readFileSync(artifactCertificatePath)); } catch { fail("the artifact signer public certificate is invalid."); }
  if (normalizedThumbprint(certificate.fingerprint) !== authorityThumbprint) {
    fail("the release authority certificate does not match the configured offline authorization identity.");
  }
  if (normalizedThumbprint(artifactCertificate.fingerprint) !== normalizedThumbprint(options.forbiddenThumbprint)) {
    fail("the artifact signer public certificate does not match the configured artifact signer.");
  }
  assertDistinctAuthorityPublicKeys(certificate.publicKey, artifactCertificate.publicKey);
  verifyDetachedReleaseAuthoritySignature(manifestBytes, signatureBytes, certificate.publicKey);
  const authority = parseReleaseAuthority(manifestBytes);
  return Object.freeze({ ...authority, manifestPath, signaturePath, certificatePath });
}

function filesystemIdentity(path) {
  const metadata = statSync(path, { bigint: true });
  return Object.freeze({ dev: String(metadata.dev), ino: String(metadata.ino), size: String(metadata.size) });
}

function assertDirectRustTool(tool) {
  if (!["cargo", "rustc"].includes(tool.role)) return;
  const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.toUpperCase().startsWith("RUSTUP_")));
  environment.RUSTUP_HOME = resolve(tool.path, "..", ".glacial-invalid-rustup-home");
  environment.RUSTUP_TOOLCHAIN = "glacial-invalid-toolchain";
  const result = spawnSync(tool.path, ["--version"], { env: environment, encoding: "utf8", shell: false, windowsHide: true, timeout: 15_000 });
  if (result.error || result.status !== 0) fail(`tool ${tool.role} must identify the actual approved toolchain binary, not a rustup proxy.`);
}

export function authenticateReleaseTool(record, expectedPath = null) {
  const tool = validateToolRecord(record?.role, record);
  if (expectedPath && normalizedPath(tool.path) !== normalizedPath(expectedPath)) {
    fail(`tool ${tool.role} does not match the required executable path.`);
  }
  if (!existsSync(tool.path)) fail(`tool ${tool.role} is missing.`);
  const metadata = lstatSync(tool.path, { bigint: true });
  if (!metadata.isFile() || metadata.isSymbolicLink()) fail(`tool ${tool.role} must be a normal file.`);
  const canonical = realpathSync.native(tool.path);
  if (normalizedPath(canonical) !== normalizedPath(tool.path)) fail(`tool ${tool.role} must not be redirected.`);
  if (sha256Bytes(readFileSync(tool.path)) !== tool.sha256) fail(`tool ${tool.role} digest does not match its signed authority.`);
  assertDirectRustTool(tool);
  return Object.freeze({ ...tool, identity: filesystemIdentity(tool.path), authenticatedReleaseTool: true });
}

export function assertAuthenticatedReleaseTool(tool) {
  if (!tool || tool.authenticatedReleaseTool !== true) fail("an authenticated release tool is required.");
  const current = authenticateReleaseTool(tool);
  if (JSON.stringify(current.identity) !== JSON.stringify(tool.identity)) fail(`tool ${tool.role} filesystem identity changed after authorization.`);
  return tool.path;
}

export function authenticateReleaseTools(authority, expectedPaths = {}) {
  const tools = Object.fromEntries(REQUIRED_RELEASE_TOOL_ROLES.map((role) => [
    role,
    authenticateReleaseTool(authority.tools[role], expectedPaths[role] ?? null),
  ]));
  return Object.freeze(tools);
}

export function releaseToolEnvironment(source, tools) {
  const environment = { ...source };
  environment.CARGO = assertAuthenticatedReleaseTool(tools.cargo);
  environment.RUSTC = assertAuthenticatedReleaseTool(tools.rustc);
  environment.CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = assertAuthenticatedReleaseTool(tools.linker);
  environment.RC = assertAuthenticatedReleaseTool(tools.resourceCompiler);
  environment.RC_x86_64_pc_windows_msvc = environment.RC;
  environment.CC = assertAuthenticatedReleaseTool(tools.cCompiler);
  environment.CC_x86_64_pc_windows_msvc = environment.CC;
  environment.AR = assertAuthenticatedReleaseTool(tools.librarian);
  environment.AR_x86_64_pc_windows_msvc = environment.AR;
  environment.GLACIAL_RELEASE_CARGO_AUTHORITY_JSON = JSON.stringify(tools.cargo);
  const approvedDirectories = [...new Set([
    tools.cargo.path, tools.rustc.path, tools.linker.path, tools.resourceCompiler.path, tools.cCompiler.path, tools.librarian.path,
  ].map((path) => dirname(path)))];
  const existingPath = String(source.PATH ?? "").split(";").filter(Boolean);
  environment.PATH = [...approvedDirectories, ...existingPath.filter((entry) => !approvedDirectories.some((approved) => normalizedPath(entry) === normalizedPath(approved)))].join(";");
  return environment;
}
