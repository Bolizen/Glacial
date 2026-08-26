import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

export const BACKEND_STAGE_RECEIPT = ".glacial-backend-stage.json";

const COMMIT_PATTERN = /^[0-9a-f]{40}$/;
const VERSION_PATTERN = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

function fail(message) {
  throw new Error(`Backend stage integrity check failed: ${message}`);
}

function digest(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex").toUpperCase();
}

function safeEntry(root, path, kind) {
  const rootPath = resolve(root);
  const entryPath = resolve(path);
  const child = relative(rootPath, entryPath);
  if (!child || child === ".." || child.startsWith(`..${sep}`) || isAbsolute(child)) {
    fail(`${kind} escapes the backend stage.`);
  }
  const metadata = lstatSync(entryPath);
  if (metadata.isSymbolicLink()) fail(`${kind} must not be a symbolic link or junction.`);
  const realRoot = realpathSync(rootPath);
  const realEntry = realpathSync(entryPath);
  const realChild = relative(realRoot, realEntry);
  if (!realChild || realChild === ".." || realChild.startsWith(`..${sep}`) || isAbsolute(realChild)) {
    fail(`${kind} resolves outside the backend stage.`);
  }
  return metadata;
}

function fileRecord(root, path, logicalPath) {
  const metadata = safeEntry(root, path, logicalPath);
  if (!metadata.isFile()) fail(`${logicalPath} is not a regular file.`);
  return {
    path: logicalPath,
    bytes: statSync(path).size,
    sha256: digest(path),
  };
}

function runtimeInventory(root, runtimeRoot, directory = runtimeRoot) {
  const metadata = safeEntry(root, directory, "backend runtime directory");
  if (!metadata.isDirectory()) fail("backend runtime path is not a directory.");
  const records = [];
  for (const name of readdirSync(directory).sort((left, right) => left.localeCompare(right))) {
    const path = join(directory, name);
    const entry = safeEntry(root, path, "backend runtime entry");
    if (entry.isDirectory()) {
      records.push(...runtimeInventory(root, runtimeRoot, path));
      continue;
    }
    if (!entry.isFile()) fail("backend runtime contains a non-file entry.");
    records.push(fileRecord(
      root,
      path,
      relative(root, path).replaceAll("\\", "/"),
    ));
  }
  return records;
}

function validateIdentity(sourceCommit, productVersion) {
  if (!COMMIT_PATTERN.test(sourceCommit)) fail("source commit is malformed.");
  if (!VERSION_PATTERN.test(productVersion)) fail("product version is malformed.");
}

function validateTopLevel(root, executableName, receiptExpected) {
  const metadata = lstatSync(root);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail("backend stage root is not a normal directory.");
  }
  const expected = new Set([executableName, "_internal"]);
  if (receiptExpected) expected.add(BACKEND_STAGE_RECEIPT);
  const actual = readdirSync(root);
  if (actual.length !== expected.size || actual.some((name) => !expected.has(name))) {
    fail("backend stage contains a missing or unexpected top-level entry.");
  }
}

export function backendStageReceipt({
  root,
  executableName,
  sourceCommit,
  productVersion,
  receiptExpected = false,
}) {
  validateIdentity(sourceCommit, productVersion);
  validateTopLevel(root, executableName, receiptExpected);
  const executable = fileRecord(root, join(root, executableName), "backend-executable");
  const runtime = runtimeInventory(root, join(root, "_internal"));
  if (runtime.length === 0) fail("backend runtime inventory is empty.");
  return {
    schemaVersion: 1,
    sourceCommit,
    productVersion,
    executable,
    runtime,
  };
}

export function writeBackendStageReceipt(options, expectedReceipt = null) {
  const receipt = backendStageReceipt(options);
  if (expectedReceipt !== null && JSON.stringify(expectedReceipt) !== JSON.stringify(receipt)) {
    fail("copied backend stage differs from its freshly constructed source payload.");
  }
  writeFileSync(
    join(options.root, BACKEND_STAGE_RECEIPT),
    `${JSON.stringify(receipt, null, 2)}\n`,
    { encoding: "utf8", flag: "wx" },
  );
  return receipt;
}

export function verifyBackendStageReceipt(options, independentlyAuthenticatedReceipt = null) {
  const path = join(options.root, BACKEND_STAGE_RECEIPT);
  if (!existsSync(path)) fail("stage receipt is missing.");
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) fail("stage receipt is not a regular file.");
  let stored;
  try {
    stored = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    fail("stage receipt is malformed.");
  }
  const actual = backendStageReceipt({ ...options, receiptExpected: true });
  if (JSON.stringify(stored) !== JSON.stringify(actual)) {
    fail("stage receipt does not match the current source identity and complete payload.");
  }
  if (independentlyAuthenticatedReceipt === null) {
    fail("independent stage authority is missing.");
  }
  if (JSON.stringify(independentlyAuthenticatedReceipt) !== JSON.stringify(actual)) {
    fail("stage differs from the independently authenticated source payload.");
  }
  return actual;
}
