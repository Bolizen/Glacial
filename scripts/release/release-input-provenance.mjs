import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
} from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

const DIGEST_PATTERN = /^[0-9A-F]{64}$/;

function fail(message) {
  throw new Error(`Release input provenance check failed: ${message}`);
}

function inside(root, target) {
  const child = relative(root, target);
  return child !== "" && child !== ".." && !child.startsWith(`..${sep}`) && !isAbsolute(child);
}

function logicalPath(root, path) {
  return relative(root, path).replaceAll("\\", "/");
}

function fileDigest(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex").toUpperCase();
}

function addRecord(hash, fields) {
  hash.update(fields.join("\0"));
  hash.update("\n");
}

function inventory(root, directory, hash, totals, ignoredPaths) {
  for (const name of readdirSync(directory).sort((left, right) => left.localeCompare(right))) {
    const path = join(directory, name);
    const logical = logicalPath(root, path);
    if (ignoredPaths.has(logical)) continue;
    const metadata = lstatSync(path);
    if (metadata.isSymbolicLink()) {
      const resolvedTarget = realpathSync.native(path);
      if (!inside(root, resolvedTarget)) fail(`${logical} resolves outside the authenticated input tree.`);
      addRecord(hash, [logical, "link", logicalPath(root, resolvedTarget)]);
      totals.links += 1;
      continue;
    }
    const resolvedEntry = realpathSync.native(path);
    if (!inside(root, resolvedEntry)) fail(`${logical} resolves outside the authenticated input tree.`);
    if (metadata.isDirectory()) {
      addRecord(hash, [logical, "directory"]);
      totals.directories += 1;
      inventory(root, path, hash, totals, ignoredPaths);
      continue;
    }
    if (!metadata.isFile()) fail(`${logical} is not a regular file, directory, or confined link.`);
    const bytes = statSync(path).size;
    addRecord(hash, [logical, "file", String(bytes), fileDigest(path)]);
    totals.files += 1;
    totals.bytes += bytes;
  }
}

export function releaseInputTreeReceipt(root, label) {
  const absoluteRoot = resolve(root);
  if (!existsSync(absoluteRoot)) fail(`${label} is missing.`);
  const metadata = lstatSync(absoluteRoot);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) fail(`${label} root must be a normal directory.`);
  if (realpathSync.native(absoluteRoot).toLowerCase() !== absoluteRoot.toLowerCase()) {
    fail(`${label} root must not traverse a junction or symbolic link.`);
  }
  if (!/^[a-z][a-z0-9-]{2,63}$/.test(label)) fail("input label is malformed.");
  const hash = createHash("sha256");
  const totals = { files: 0, directories: 0, links: 0, bytes: 0 };
  const ignoredPaths = label === "node-modules" ? new Set([".modules.yaml", ".pnpm-workspace-state-v1.json"]) : new Set();
  inventory(absoluteRoot, absoluteRoot, hash, totals, ignoredPaths);
  if (totals.files === 0) fail(`${label} contains no authenticated files.`);
  return {
    schemaVersion: 1,
    label,
    algorithm: "sha256-tree-v1",
    ...totals,
    digest: hash.digest("hex").toUpperCase(),
  };
}

export function assertReleaseInputTree(root, expectedReceipt) {
  if (!expectedReceipt || expectedReceipt.schemaVersion !== 1
      || expectedReceipt.algorithm !== "sha256-tree-v1"
      || !DIGEST_PATTERN.test(String(expectedReceipt.digest ?? ""))) {
    fail("expected input receipt is malformed.");
  }
  const actual = releaseInputTreeReceipt(root, expectedReceipt.label);
  if (JSON.stringify(actual) !== JSON.stringify(expectedReceipt)) {
    fail(`${expectedReceipt.label} changed after authenticated reconstruction.`);
  }
  return actual;
}
