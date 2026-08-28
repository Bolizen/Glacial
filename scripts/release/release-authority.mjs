import { spawnSync } from "node:child_process";
import { constants as cryptoConstants, createHash, createPublicKey, verify, X509Certificate } from "node:crypto";
import { existsSync, lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

export const GLACIAL_REPOSITORY_IDENTITY = "github.com/bolizen/glacial";
export const TRUSTED_RELEASE_AUTHORITY_PUBLIC_KEY_PATH = "C:\\Program Files\\Icefields\\Glacial Release Policy\\release-authority-public-key.pem";
export const REQUIRED_RELEASE_TOOL_ROLES = Object.freeze([
  "node", "python", "git", "tar", "cargo", "rustc", "linker", "resourceCompiler", "cCompiler", "librarian",
  "powerShell", "signTool", "signingProvider",
]);
export const RELEASE_AUTHORITY_MAX_LIFETIME_MS = 14 * 24 * 60 * 60 * 1000;
const RELEASE_AUTHORITY_CLOCK_SKEW_MS = 5 * 60 * 1000;
const AUTHENTIC_RELEASE_AUTHORITIES = new WeakSet();
const AUTHENTIC_RELEASE_TOOLS = new WeakSet();

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

function canonicalUtc(value, label) {
  const text = String(value ?? "");
  const timestamp = Date.parse(text);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== text) fail(`${label} must be a canonical UTC timestamp.`);
  return Object.freeze({ text, timestamp });
}

function validateStringArray(value, label, pattern) {
  if (!Array.isArray(value) || !value.length || value.some((item) => typeof item !== "string" || !pattern.test(item))) {
    fail(`${label} is invalid.`);
  }
  if (new Set(value.map((item) => item.toUpperCase())).size !== value.length) fail(`${label} contains duplicate values.`);
  return Object.freeze([...value]);
}

function validateOptionalStringArray(value, label, pattern) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !pattern.test(item))) fail(`${label} is invalid.`);
  if (new Set(value.map((item) => item.toUpperCase())).size !== value.length) fail(`${label} contains duplicate values.`);
  return Object.freeze([...value]);
}

function requireExactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) {
    fail(`${label} has unexpected or missing fields.`);
  }
}

function validateSigningStatement(signing, tools) {
  requireExactKeys(signing, ["provider", "expectedSubject", "expectedThumbprint", "artifactSignerSpkiSha256", "timestampUrl", "commandArgs", "providerEnvironmentNames"], "signing authorization");
  const provider = String(signing.provider ?? "");
  if (provider !== "store" && provider !== "command") fail("the authorized signing provider is invalid.");
  const expectedSubject = String(signing.expectedSubject ?? "").trim();
  if (!expectedSubject || expectedSubject.length > 512) fail("the authorized signer subject is invalid.");
  const expectedThumbprint = normalizedThumbprint(signing.expectedThumbprint);
  const artifactSignerSpkiSha256 = String(signing.artifactSignerSpkiSha256 ?? "");
  if (!/^[0-9a-f]{64}$/.test(artifactSignerSpkiSha256)) fail("the authorized artifact signer public-key digest is invalid.");
  let timestampUrl;
  try { timestampUrl = new URL(String(signing.timestampUrl ?? "")); } catch { fail("the authorized timestamp URL is invalid."); }
  if (timestampUrl.protocol !== "https:" || timestampUrl.username || timestampUrl.password || timestampUrl.search || timestampUrl.hash) {
    fail("the authorized timestamp URL must be credential-free HTTPS.");
  }
  const commandArgs = provider === "command"
    ? validateStringArray(signing.commandArgs, "authorized signing-provider arguments", /^.{1,2048}$/s)
    : Object.freeze([]);
  if (provider === "command" && commandArgs.reduce((count, argument) => count + (argument.match(/\{file\}/g)?.length ?? 0), 0) !== 1) {
    fail("authorized signing-provider arguments must contain exactly one {file} placeholder.");
  }
  if (provider === "command") {
    for (const argument of commandArgs) {
      if (/[\u0000-\u001F\u007F]/.test(argument)
          || /(password|passwd|secret|token|credential|private[-_ ]?key)/i.test(argument)) {
        fail("authorized signing-provider arguments contain unsafe or secret-bearing content.");
      }
      if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(argument)) {
        let url;
        try { url = new URL(argument); } catch { fail("authorized signing-provider arguments contain an invalid URL."); }
        if (url.username || url.password || url.search || url.hash) fail("authorized signing-provider URL arguments must not contain credentials, query strings, or fragments.");
      }
    }
  }
  if (provider === "store" && (signing.commandArgs?.length || signing.providerEnvironmentNames?.length)) {
    fail("store signing authorization must not contain command-provider configuration.");
  }
  const providerEnvironmentNames = provider === "command"
    ? validateOptionalStringArray(signing.providerEnvironmentNames, "authorized signing-provider environment names", /^[A-Za-z_][A-Za-z0-9_]*$/)
    : Object.freeze([]);
  if (provider === "store" && (tools.signingProvider.path.toLowerCase() !== tools.signTool.path.toLowerCase()
      || tools.signingProvider.sha256 !== tools.signTool.sha256)) {
    fail("store signing must identify SignTool as its signing provider executable.");
  }
  return Object.freeze({
    provider,
    expectedSubject,
    expectedThumbprint,
    artifactSignerSpkiSha256,
    timestampUrl: timestampUrl.href,
    commandArgs,
    providerEnvironmentNames,
  });
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

function validateToolRecord(role, record, strict = true) {
  if (strict) requireExactKeys(record, ["path", "sha256"], `tool ${role}`);
  else if (!record || typeof record !== "object" || Array.isArray(record)) fail(`tool ${role} is missing.`);
  if (typeof record.path !== "string" || !isAbsolute(record.path)) fail(`tool ${role} path must be absolute.`);
  if (!/^[0-9a-f]{64}$/.test(String(record.sha256 ?? ""))) fail(`tool ${role} SHA-256 is invalid.`);
  return Object.freeze({ role, path: resolve(record.path), sha256: record.sha256 });
}

export function parseReleaseAuthority(manifestBytes) {
  let manifest;
  try { manifest = JSON.parse(Buffer.from(manifestBytes).toString("utf8")); } catch { fail("the authority manifest is malformed JSON."); }
  if (!manifest || manifest.schemaVersion !== 2 || typeof manifest.authorityId !== "string"
      || !/^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/.test(manifest.authorityId)) fail("the authority manifest header is invalid.");
  requireExactKeys(manifest, ["schemaVersion", "authorityId", "authorization", "source", "tools", "signing"], "authority manifest");
  requireExactKeys(manifest.authorization, ["issuedAtUtc", "expiresAtUtc", "profiles"], "authorization validity");
  const issued = canonicalUtc(manifest.authorization.issuedAtUtc, "authorization issuance");
  const expires = canonicalUtc(manifest.authorization.expiresAtUtc, "authorization expiry");
  if (expires.timestamp <= issued.timestamp || expires.timestamp - issued.timestamp > RELEASE_AUTHORITY_MAX_LIFETIME_MS) {
    fail("authorization validity must be positive and no longer than fourteen days.");
  }
  const profiles = validateStringArray(manifest.authorization.profiles, "authorized release profiles", /^(?:signed-preview|public-rc)$/);
  requireExactKeys(manifest.source, ["repository", "commit"], "source authorization");
  const repository = canonicalRepositoryIdentity(manifest.source.repository);
  const commit = String(manifest.source.commit ?? "");
  if (!/^[0-9a-f]{40}$/.test(commit)) fail("the authorized source commit is invalid.");
  if (!manifest.tools || typeof manifest.tools !== "object" || Array.isArray(manifest.tools)) fail("tool authorization is missing.");
  const toolNames = Object.keys(manifest.tools).sort();
  if (JSON.stringify(toolNames) !== JSON.stringify([...REQUIRED_RELEASE_TOOL_ROLES].sort())) {
    fail("the authority manifest must contain exactly the required release tools.");
  }
  const tools = Object.fromEntries(REQUIRED_RELEASE_TOOL_ROLES.map((role) => [role, validateToolRecord(role, manifest.tools[role])]));
  const signing = validateSigningStatement(manifest.signing, tools);
  return Object.freeze({
    schemaVersion: 2,
    authorityId: manifest.authorityId,
    digest: sha256Bytes(manifestBytes),
    authorization: Object.freeze({ issuedAtUtc: issued.text, expiresAtUtc: expires.text, profiles }),
    source: Object.freeze({ repository, commit }),
    tools: Object.freeze(tools),
    signing,
  });
}

export function validateReleaseAuthorityBundle({ manifestBytes, signatureBytes, trustedPublicKey, artifactCertificate, now = new Date() }) {
  const authorityKey = typeof trustedPublicKey === "string" || Buffer.isBuffer(trustedPublicKey)
    ? createPublicKey(trustedPublicKey)
    : trustedPublicKey;
  verifyDetachedReleaseAuthoritySignature(manifestBytes, signatureBytes, authorityKey);
  const authority = parseReleaseAuthority(manifestBytes);
  const certificate = artifactCertificate instanceof X509Certificate ? artifactCertificate : new X509Certificate(artifactCertificate);
  if (normalizedThumbprint(certificate.fingerprint) !== authority.signing.expectedThumbprint) {
    fail("the artifact signer public certificate does not match the signed authorization.");
  }
  const artifactSpki = certificate.publicKey.export({ type: "spki", format: "der" });
  if (sha256Bytes(artifactSpki) !== authority.signing.artifactSignerSpkiSha256) {
    fail("the artifact signer public key does not match the signed authorization.");
  }
  assertDistinctAuthorityPublicKeys(authorityKey, certificate.publicKey);
  validateReleaseAuthorityScope(authority, { now });
  return authority;
}

export function validateReleaseAuthorityScope(authority, options = {}) {
  if (!authority?.authorization) fail("release authorization validity is missing.");
  const current = options.now instanceof Date ? options.now.getTime() : options.now == null ? Date.now() : Number(options.now);
  if (!Number.isFinite(current)) fail("the release authorization clock is invalid.");
  if (current + RELEASE_AUTHORITY_CLOCK_SKEW_MS < Date.parse(authority.authorization.issuedAtUtc)) fail("the release authorization is not yet valid.");
  if (current >= Date.parse(authority.authorization.expiresAtUtc)) fail("the release authorization is expired.");
  if (options.profile && !authority.authorization.profiles.includes(options.profile)) fail(`release profile ${options.profile} is not authorized.`);
  return authority;
}

export function loadReleaseAuthority(environment, options) {
  const repository = resolve(options?.repository ?? "");
  const manifestPath = requireIndependentFile(environment.GLACIAL_WINDOWS_RELEASE_AUTHORITY_PATH, "release authority manifest", repository);
  const signaturePath = requireIndependentFile(environment.GLACIAL_WINDOWS_RELEASE_AUTHORITY_SIGNATURE_PATH, "release authority signature", repository);
  const artifactCertificatePath = requireIndependentFile(environment.GLACIAL_WINDOWS_ARTIFACT_SIGNER_CERTIFICATE_PATH, "artifact signer public certificate", repository);
  const trustedPublicKeyPath = requireIndependentFile(TRUSTED_RELEASE_AUTHORITY_PUBLIC_KEY_PATH, "machine release-authority trust anchor", repository);
  const manifestBytes = readFileSync(manifestPath);
  const signatureBytes = readFileSync(signaturePath);
  let artifactCertificate;
  try { artifactCertificate = new X509Certificate(readFileSync(artifactCertificatePath)); } catch { fail("the artifact signer public certificate is invalid."); }
  let trustedPublicKey;
  try { trustedPublicKey = createPublicKey(readFileSync(trustedPublicKeyPath)); } catch { fail("the machine release-authority trust anchor is invalid."); }
  const authority = validateReleaseAuthorityBundle({
    manifestBytes,
    signatureBytes,
    trustedPublicKey,
    artifactCertificate,
    now: options?.now ?? new Date(),
  });
  const loaded = Object.freeze({ ...authority, manifestPath, signaturePath, artifactCertificatePath, trustedPublicKeyPath });
  AUTHENTIC_RELEASE_AUTHORITIES.add(loaded);
  return loaded;
}

export function assertCurrentReleaseAuthority(authority, options = {}) {
  if (!authority || !AUTHENTIC_RELEASE_AUTHORITIES.has(authority)) fail("an authentic machine-anchored release authority is required.");
  return validateReleaseAuthorityScope(authority, options);
}

function runAuthenticatedGit(gitTool, repository, args) {
  const command = assertAuthenticatedReleaseTool(gitTool);
  const allowedNames = new Set(["SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "TEMP", "TMP", "USERPROFILE", "HOMEDRIVE", "HOMEPATH"]);
  const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => allowedNames.has(name.toUpperCase())));
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_CONFIG_GLOBAL = "NUL";
  environment.GIT_CONFIG_COUNT = "0";
  const result = spawnSync(command, ["-C", repository, ...args], {
    env: environment,
    encoding: "utf8",
    shell: false,
    windowsHide: true,
    timeout: 30_000,
  });
  if (result.error || result.status !== 0) fail("the authorized release checkout could not be verified.");
  return String(result.stdout ?? "").trim();
}

export function verifyAuthorizedReleaseCheckout(authority, gitTool, repository) {
  assertCurrentReleaseAuthority(authority);
  const root = realpathSync.native(runAuthenticatedGit(gitTool, repository, ["rev-parse", "--show-toplevel"]));
  if (normalizedPath(root) !== normalizedPath(realpathSync.native(repository))) fail("the release checkout root is unexpected.");
  const commit = runAuthenticatedGit(gitTool, repository, ["rev-parse", "HEAD"]);
  const originMain = runAuthenticatedGit(gitTool, repository, ["rev-parse", "origin/main"]);
  if (commit !== authority.source.commit) fail("the release checkout commit is not authorized.");
  if (commit !== originMain) fail("the release checkout does not match origin/main.");
  canonicalRepositoryIdentity(runAuthenticatedGit(gitTool, repository, ["remote", "get-url", "origin"]));
  if (runAuthenticatedGit(gitTool, repository, ["status", "--short"])) fail("the authorized release checkout is not clean.");
  return Object.freeze({ root, commit, originMain });
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

function inspectReleaseTool(record, expectedPath = null) {
  const tool = validateToolRecord(record?.role, record, false);
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
  return Object.freeze({ ...tool, identity: filesystemIdentity(tool.path) });
}

export function authenticateReleaseTool(record, expectedPath = null) {
  return inspectReleaseTool(record, expectedPath);
}

export function assertAuthenticatedReleaseTool(tool) {
  if (!tool || !AUTHENTIC_RELEASE_TOOLS.has(tool)) fail("an authenticated release tool is required.");
  return revalidateReleaseTool(tool);
}

export function revalidateReleaseTool(tool) {
  const current = inspectReleaseTool(tool);
  if (JSON.stringify(current.identity) !== JSON.stringify(tool.identity)) fail(`tool ${tool.role} filesystem identity changed after authorization.`);
  return tool.path;
}

export function authenticateReleaseTools(authority, expectedPaths = {}) {
  assertCurrentReleaseAuthority(authority);
  const tools = Object.fromEntries(REQUIRED_RELEASE_TOOL_ROLES.map((role) => [
    role,
    inspectReleaseTool(authority.tools[role], expectedPaths[role] ?? null),
  ]));
  for (const tool of Object.values(tools)) AUTHENTIC_RELEASE_TOOLS.add(tool);
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
