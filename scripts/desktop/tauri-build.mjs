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
  assertNoNodeRuntimeInjection,
  assertCanonicalReleaseChildProcess,
  minimalEnvironment,
  resolveToolExecutable,
  runCommand,
  sanitizeDiagnosticText,
  validateStructuredDigest,
} from "./windows-signing.mjs";
import {
  assertAuthenticatedReleaseTool,
  authenticateReleaseTools,
  loadReleaseAuthority,
  releaseToolEnvironment,
  verifyAuthorizedReleaseCheckout,
} from "../release/release-authority.mjs";
import { verifyBackendStageReceipt } from "./backend-stage-integrity.mjs";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const FRONTEND = join(REPOSITORY, "frontend");
const TAURI_CLI = join(FRONTEND, "node_modules", "@tauri-apps", "cli", "tauri.js");
const GLIB_VERIFIER = join(REPOSITORY, "scripts", "security", "verify-glib-backport.mjs");
const BACKEND_STAGE = join(FRONTEND, "src-tauri", "binaries");
const BACKEND_EXECUTABLE = "glacial-backend-x86_64-pc-windows-msvc.exe";

export function parseBackendStageAuthority(environment = process.env) {
  const serialized = environment.GLACIAL_BACKEND_STAGE_AUTHORITY_JSON;
  if (typeof serialized !== "string" || serialized.length < 2 || serialized.length > 16 * 1024 * 1024) {
    throw new Error("Independent backend stage authority is required for Tauri packaging.");
  }
  let receipt;
  try { receipt = JSON.parse(serialized); } catch { throw new Error("Independent backend stage authority is malformed."); }
  if (!receipt || receipt.schemaVersion !== 1 || !Array.isArray(receipt.runtime)) {
    throw new Error("Independent backend stage authority is malformed.");
  }
  return receipt;
}

function gitText(git, args) {
  return String(runCommand(git, args, {
    cwd: REPOSITORY,
    env: minimalEnvironment(process.env),
  }).stdout ?? "").trim();
}

export function resolveProductionBuildIdentity(environment = process.env) {
  const injected = parseInjectedBuildIdentity(environment);
  if (injected) {
    if (injected.buildProfile !== "internal-evidence"
        && (!environment.GLACIAL_WINDOWS_SIGN_BROKER_TOKEN || !environment.GLACIAL_WINDOWS_RELEASE_ID
          || !environment.GLACIAL_BACKEND_STAGE_AUTHORITY_JSON)) {
      throw new Error("Signed build identity requires the authenticated signed-release coordinator.");
    }
    return injected;
  }
  const git = resolveToolExecutable("git.exe", environment, { forbiddenRoot: REPOSITORY });
  const status = gitText(git, ["status", "--short"]);
  if (status) throw new Error("Internal-evidence construction requires a clean source tree.");
  const commit = validateStructuredDigest(gitText(git, ["rev-parse", "HEAD"]), "git-commit");
  return buildIdentityForProfile({ profile: "internal-evidence", sourceCommit: commit });
}

export function runTauriBuild(args = process.argv.slice(2), environment = process.env) {
  assertNoNodeRuntimeInjection(environment);
  if (!existsSync(TAURI_CLI) || !readFileSync(TAURI_CLI, "utf8").includes("run")) {
    throw new Error("The locked Tauri CLI is unavailable.");
  }
  const identity = resolveProductionBuildIdentity(environment);
  if (!new Set(["signed-preview", "public-rc"]).has(identity.buildProfile)) {
    throw new Error("Direct internal Tauri packaging is disabled; only the authenticated signed-release coordinator may package an application.");
  }
  const authority = loadReleaseAuthority(environment, { repository: REPOSITORY });
  const tools = authenticateReleaseTools(authority, { node: process.execPath });
  verifyAuthorizedReleaseCheckout(authority, tools.git, REPOSITORY);
  if (identity.sourceCommit !== authority.source.commit) throw new Error("The Tauri build identity is not authorized for this source commit.");
  const profile = String(environment.GLACIAL_RELEASE_PROFILE ?? "");
  if (profile !== identity.buildProfile) throw new Error("The Tauri release profile is inconsistent.");
  assertCanonicalReleaseChildProcess(environment, { authority, tools, profile });
  if (!/^Glacial-0\.9\.12-[0-9a-f]{12}-\d{8}T\d{6}Z$/.test(String(environment.GLACIAL_WINDOWS_RELEASE_ID ?? ""))
      || !/^[0-9a-f]{64}$/.test(String(environment.GLACIAL_WINDOWS_SIGN_BROKER_TOKEN ?? ""))
      || !Number.isInteger(Number(environment.GLACIAL_WINDOWS_SIGN_BROKER_PORT))) {
    throw new Error("The authenticated signed-release coordinator is unavailable.");
  }
  const receiptOptions = {
    root: BACKEND_STAGE,
    executableName: BACKEND_EXECUTABLE,
    sourceCommit: identity.sourceCommit,
    productVersion: identity.productVersion,
  };
  const stageAuthority = parseBackendStageAuthority(environment);
  verifyBackendStageReceipt(receiptOptions, stageAuthority);
  const buildEnvironment = releaseToolEnvironment(minimalEnvironment(environment, {
    GLACIAL_BUILD_IDENTITY_JSON: serializeBuildIdentity(identity),
  }, ["GLACIAL_BUILD_IDENTITY_JSON", "GLACIAL_BACKEND_STAGE_AUTHORITY_JSON", "GLACIAL_WINDOWS_RELEASE_ID",
    "CARGO_HOME", "CARGO_NET_OFFLINE", "CARGO_TARGET_DIR",
    "GLACIAL_WINDOWS_SIGN_BROKER_PORT", "GLACIAL_WINDOWS_SIGN_BROKER_TOKEN", "GLACIAL_RELEASE_PROFILE",
    "GLACIAL_WINDOWS_RELEASE_AUTHORITY_PATH", "GLACIAL_WINDOWS_RELEASE_AUTHORITY_SIGNATURE_PATH",
    "GLACIAL_WINDOWS_ARTIFACT_SIGNER_CERTIFICATE_PATH"]), tools);
  const nodePath = assertAuthenticatedReleaseTool(tools.node);
  runCommand(nodePath, [GLIB_VERIFIER], {
    cwd: REPOSITORY,
    env: buildEnvironment,
    timeoutMs: 300_000,
    includeFailureOutput: true,
  });
  const result = runCommand(nodePath, [TAURI_CLI, "build", ...args], {
    cwd: FRONTEND,
    env: buildEnvironment,
    timeoutMs: 900_000,
    includeFailureOutput: true,
  });
  verifyBackendStageReceipt(receiptOptions, stageAuthority);
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
