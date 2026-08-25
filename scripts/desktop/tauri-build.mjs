import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildIdentityForProfile,
  parseInjectedBuildIdentity,
  REPOSITORY,
  serializeBuildIdentity,
} from "../release/build-identity.mjs";
import {
  minimalEnvironment,
  resolveToolExecutable,
  runCommand,
  sanitizeDiagnosticText,
  validateStructuredDigest,
} from "./windows-signing.mjs";
import { verifyBackendStageReceipt } from "./backend-stage-integrity.mjs";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const FRONTEND = join(REPOSITORY, "frontend");
const TAURI_CLI = join(FRONTEND, "node_modules", "@tauri-apps", "cli", "tauri.js");
const GLIB_VERIFIER = join(REPOSITORY, "scripts", "security", "verify-glib-backport.mjs");
const BACKEND_STAGE = join(FRONTEND, "src-tauri", "binaries");
const BACKEND_EXECUTABLE = "glacial-backend-x86_64-pc-windows-msvc.exe";

function gitText(git, args) {
  return String(runCommand(git, args, {
    cwd: REPOSITORY,
    env: minimalEnvironment(process.env),
  }).stdout ?? "").trim();
}

export function resolveProductionBuildIdentity(environment = process.env) {
  const injected = parseInjectedBuildIdentity(environment);
  if (injected) return injected;
  const git = resolveToolExecutable("git.exe", environment, { forbiddenRoot: REPOSITORY });
  const status = gitText(git, ["status", "--short"]);
  if (status) throw new Error("Internal-evidence construction requires a clean source tree.");
  const commit = validateStructuredDigest(gitText(git, ["rev-parse", "HEAD"]), "git-commit");
  return buildIdentityForProfile({ profile: "internal-evidence", sourceCommit: commit });
}

export function runTauriBuild(args = process.argv.slice(2), environment = process.env) {
  if (!existsSync(TAURI_CLI) || !readFileSync(TAURI_CLI, "utf8").includes("run")) {
    throw new Error("The locked Tauri CLI is unavailable.");
  }
  const identity = resolveProductionBuildIdentity(environment);
  const receiptOptions = {
    root: BACKEND_STAGE,
    executableName: BACKEND_EXECUTABLE,
    sourceCommit: identity.sourceCommit,
    productVersion: identity.productVersion,
  };
  verifyBackendStageReceipt(receiptOptions);
  const buildEnvironment = minimalEnvironment(environment, {
    GLACIAL_BUILD_IDENTITY_JSON: serializeBuildIdentity(identity),
  }, ["GLACIAL_BUILD_IDENTITY_JSON", "GLACIAL_WINDOWS_RELEASE_ID",
    "GLACIAL_WINDOWS_SIGN_BROKER_PORT", "GLACIAL_WINDOWS_SIGN_BROKER_TOKEN"]);
  runCommand(process.execPath, [GLIB_VERIFIER], {
    cwd: REPOSITORY,
    env: minimalEnvironment(environment),
    timeoutMs: 300_000,
    includeFailureOutput: true,
  });
  const result = runCommand(process.execPath, [TAURI_CLI, "build", ...args], {
    cwd: FRONTEND,
    env: buildEnvironment,
    timeoutMs: 900_000,
    includeFailureOutput: true,
  });
  verifyBackendStageReceipt(receiptOptions);
  return result;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(SCRIPT_PATH)) {
  try {
    const result = runTauriBuild();
    if (result.stdout) process.stdout.write(sanitizeDiagnosticText(result.stdout));
    if (result.stderr) process.stderr.write(sanitizeDiagnosticText(result.stderr));
  } catch (error) {
    process.stderr.write(`${sanitizeDiagnosticText(error.message)}\n`);
    process.exitCode = 1;
  }
}
