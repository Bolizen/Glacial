import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import { basename, isAbsolute, join, relative, resolve, sep } from "node:path";

import { WINDOWS_RELEASE_PYTHON } from "./release-contract.mjs";

const digestPattern = /^[0-9a-f]{64}$/;
const scopePaths = Object.freeze({
  "backend-runtime": "backend/requirements.lock.txt",
  "desktop-build": "backend/desktop-build-requirements.lock",
});

function fail(message) {
  throw new Error(message);
}

function canonicalizeName(value) {
  return String(value).toLowerCase().replaceAll(/[-_.]+/g, "-");
}

function sha256Bytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function parseExactRequirements(value) {
  const text = Buffer.isBuffer(value)
    ? (value[0] === 0xff && value[1] === 0xfe ? value.subarray(2).toString("utf16le") : value.toString("utf8").replace(/^\uFEFF/, ""))
    : String(value).replace(/^\uFEFF/, "");
  const seen = new Set();
  return text.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#")).map((line, index) => {
    const match = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)(?:\s+--hash=sha256:[0-9a-fA-F]{64})?$/);
    if (!match) fail(`Python lock entry ${index + 1} is not one exact name==version pin with an optional SHA-256 hash.`);
    const canonicalName = canonicalizeName(match[1]);
    if (seen.has(canonicalName)) fail(`Python lock contains duplicate package ${match[1]}.`);
    seen.add(canonicalName);
    return { name: match[1], canonicalName, version: match[2] };
  });
}

function repositoryPath(root, relativePath, label) {
  if (typeof relativePath !== "string" || !relativePath || isAbsolute(relativePath) || relativePath.includes("\\")) {
    fail(`${label} must be a normalized repository-relative path.`);
  }
  const target = resolve(root, relativePath);
  const child = relative(resolve(root), target);
  if (!child || child === ".." || child.startsWith(`..${sep}`) || isAbsolute(child)) fail(`${label} escapes the repository.`);
  return target;
}

function validateRuntimeContract(value) {
  for (const [key, expected] of Object.entries(WINDOWS_RELEASE_PYTHON)) {
    if (value?.[key] !== expected) fail(`Python artifact manifest runtime contract differs at ${key}.`);
  }
}

function validateBaseDistribution(value) {
  if (value?.filename !== "python-3.13.13-embed-amd64.zip"
      || value?.url !== "https://www.python.org/ftp/python/3.13.13/python-3.13.13-embed-amd64.zip"
      || value?.bytes !== 10950201
      || !digestPattern.test(String(value?.sha256 ?? ""))
      || value?.authority !== "Python.org release SHA-256 and Sigstore publication") {
    fail("Python artifact manifest base distribution is invalid.");
  }
  return { ...value };
}

function validateScope(root, id, value) {
  const expectedLockPath = scopePaths[id];
  if (!expectedLockPath || value?.lockPath !== expectedLockPath) fail(`Python artifact manifest scope ${id} has an invalid lock path.`);
  if (!digestPattern.test(String(value.lockSha256 ?? ""))) fail(`Python artifact manifest scope ${id} has an invalid lock SHA-256.`);
  const lockPath = repositoryPath(root, value.lockPath, `${id} lock`);
  if (!existsSync(lockPath) || !lstatSync(lockPath).isFile() || lstatSync(lockPath).isSymbolicLink()) fail(`${id} lock must be a real file.`);
  const lockBytes = readFileSync(lockPath);
  if (sha256Bytes(lockBytes) !== value.lockSha256) fail(`${id} lock SHA-256 differs from the artifact manifest.`);

  const locked = parseExactRequirements(lockBytes);
  if (!Array.isArray(value.artifacts) || value.artifacts.length !== locked.length) fail(`${id} artifact count differs from its lock.`);
  const byName = new Map();
  const filenames = new Set();
  for (const artifact of value.artifacts) {
    const canonicalName = canonicalizeName(artifact?.name);
    if (!canonicalName || byName.has(canonicalName)) fail(`${id} artifact names must be unique.`);
    if (typeof artifact.version !== "string" || !artifact.version) fail(`${id} artifact ${canonicalName} has no version.`);
    if (typeof artifact.filename !== "string" || basename(artifact.filename) !== artifact.filename || !artifact.filename.endsWith(".whl")) {
      fail(`${id} artifact ${canonicalName} has an unsafe or non-wheel filename.`);
    }
    if (filenames.has(artifact.filename.toLowerCase())) fail(`${id} artifact filenames must be unique.`);
    if (!digestPattern.test(String(artifact.sha256 ?? ""))) fail(`${id} artifact ${canonicalName} has an invalid SHA-256.`);
    filenames.add(artifact.filename.toLowerCase());
    byName.set(canonicalName, { ...artifact, canonicalName });
  }
  for (const requirement of locked) {
    const artifact = byName.get(requirement.canonicalName);
    if (!artifact || artifact.version !== requirement.version) fail(`${id} artifact provenance differs from ${requirement.name}==${requirement.version}.`);
  }
  return { id, lockPath, lockSha256: value.lockSha256, artifacts: locked.map((item) => byName.get(item.canonicalName)) };
}

export function loadPythonArtifactManifest(root, manifestPath = join(root, "docs", "release", "python-artifact-integrity.json")) {
  const canonicalRoot = resolve(root);
  const canonicalManifest = resolve(manifestPath);
  const manifestChild = relative(canonicalRoot, canonicalManifest);
  if (!manifestChild || manifestChild === ".." || manifestChild.startsWith(`..${sep}`) || isAbsolute(manifestChild)) fail("Python artifact manifest must remain inside the repository.");
  if (!existsSync(canonicalManifest) || !lstatSync(canonicalManifest).isFile() || lstatSync(canonicalManifest).isSymbolicLink()) fail("Python artifact manifest must be a real repository file.");
  let manifest;
  try { manifest = JSON.parse(readFileSync(canonicalManifest, "utf8")); } catch { fail("Python artifact manifest is not valid JSON."); }
  if (manifest.schemaVersion !== "1.0.0") fail("Unsupported Python artifact manifest schema.");
  if (manifest.source?.indexUrl !== "https://pypi.org/simple"
      || manifest.source?.metadataApi !== "https://pypi.org/pypi/{name}/{version}/json"
      || manifest.source?.repository !== "Python Package Index (PyPI)") {
    fail("Python artifact manifest must identify the official PyPI source.");
  }
  validateRuntimeContract(manifest.runtimeContract);
  const ids = Object.keys(manifest.scopes ?? {}).sort();
  if (JSON.stringify(ids) !== JSON.stringify(Object.keys(scopePaths).sort())) fail("Python artifact manifest scopes are incomplete or unexpected.");
  return {
    path: canonicalManifest,
    sha256: sha256Bytes(readFileSync(canonicalManifest)),
    source: manifest.source,
    runtimeContract: manifest.runtimeContract,
    baseDistribution: validateBaseDistribution(manifest.baseDistribution),
    scopes: Object.fromEntries(ids.map((id) => [id, validateScope(canonicalRoot, id, manifest.scopes[id])])),
  };
}

export function renderHashedRequirements(scope) {
  return `${scope.artifacts.map((artifact) => `${artifact.name}==${artifact.version} --hash=sha256:${artifact.sha256}`).join("\n")}\n`;
}

export function verifyWheelhouse(scope, wheelhouse) {
  const root = resolve(wheelhouse);
  if (!existsSync(root) || !lstatSync(root).isDirectory() || lstatSync(root).isSymbolicLink()) fail(`${scope.id} wheelhouse must be a real directory.`);
  const entries = readdirSync(root, { withFileTypes: true });
  if (entries.some((entry) => !entry.isFile() || !entry.name.endsWith(".whl"))) fail(`${scope.id} wheelhouse contains a non-wheel or non-file entry.`);
  const expected = new Map(scope.artifacts.map((artifact) => [artifact.filename.toLowerCase(), artifact]));
  const observed = new Map(entries.map((entry) => [entry.name.toLowerCase(), entry]));
  const missing = [...expected.keys()].filter((name) => !observed.has(name));
  const unexpected = [...observed.keys()].filter((name) => !expected.has(name));
  if (missing.length || unexpected.length || expected.size !== observed.size) {
    fail(`${scope.id} wheelhouse artifact set differs from the manifest. Missing: ${missing.join(", ") || "(none)"}; unexpected: ${unexpected.join(", ") || "(none)"}.`);
  }
  const hashes = [];
  for (const artifact of scope.artifacts) {
    const artifactPath = join(root, observed.get(artifact.filename.toLowerCase()).name);
    if (lstatSync(artifactPath).isSymbolicLink()) fail(`${scope.id} wheelhouse contains a symbolic link.`);
    const actual = sha256Bytes(readFileSync(artifactPath));
    if (actual !== artifact.sha256) fail(`${scope.id} artifact SHA-256 mismatch: ${artifact.filename}.`);
    hashes.push({ filename: artifact.filename, sha256: actual });
  }
  return hashes;
}
