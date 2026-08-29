import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { assertReleaseProfileTrust } from "./Build-SignedWindowsRelease.mjs";
import {
  DESKTOP_BUILD_ROOT,
  REPOSITORY_ROOT,
  assertNoNodeRuntimeInjection,
  ensureSafeDirectory,
  removeSafeTree,
  runCommand,
  runAuthorizedSignerPreflight,
  sanitizeDiagnosticText,
} from "./windows-signing.mjs";
import {
  authenticateReleaseTools,
  loadReleaseAuthority,
  verifyAuthorizedReleaseCheckout,
} from "../release/release-authority.mjs";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const PROFILES = new Set(["signed-preview", "public-rc"]);
const PREFLIGHT_WORKER_ARGUMENT = "--glacial-authorized-signer-preflight-worker";

export function parseSignerPreflightArguments(args) {
  if (args.length !== 2 || args[0] !== "--profile" || !PROFILES.has(args[1])) {
    throw new Error("Signer preflight requires --profile signed-preview or --profile public-rc.");
  }
  return { profile: args[1] };
}

async function runSignerPreflight(profile, options = {}) {
  if (!PROFILES.has(profile)) throw new Error(`Unsupported signer preflight profile: ${profile}.`);
  const sessionRoot = join(DESKTOP_BUILD_ROOT, "signer-preflight", `session-${process.pid}-${Date.now()}`);
  let cleanup = true;
  let result = null;
  let failure = null;
  try {
    ensureSafeDirectory(DESKTOP_BUILD_ROOT, sessionRoot, options.pathOptions);
    const environment = options.environment ?? process.env;
    let config;
    let identity;
    if (options.loadConfig) {
      config = options.loadConfig(environment);
      identity = await options.preflight(config, {
        probeParent: join(sessionRoot, "probe"),
        ...(options.preflightOptions ?? {}),
      });
    } else {
      const authority = loadReleaseAuthority(environment, { repository: REPOSITORY_ROOT });
      const tools = authenticateReleaseTools(authority, { node: process.execPath });
      verifyAuthorizedReleaseCheckout(authority, tools.git, REPOSITORY_ROOT);
      const preflight = runAuthorizedSignerPreflight(environment, {
        authority,
        tools,
        profile,
        probeParent: join(sessionRoot, "probe"),
      });
      config = preflight.config;
      identity = preflight.identity;
    }
    (options.assertTrust ?? assertReleaseProfileTrust)(profile, identity);
    result = {
      selectedProfile: profile,
      providerType: config.provider,
      expectedSignerSubject: config.expectedSubject,
      expectedSignerThumbprint: config.expectedThumbprint,
      observedSignerSubject: identity.canonicalSubject,
      observedSignerThumbprint: identity.signerThumbprint,
      trustClassification: identity.trustClassification,
      certificateNotBeforeUtc: identity.signerNotBeforeUtc,
      certificateNotAfterUtc: identity.signerNotAfterUtc,
      codeSigningEku: identity.codeSigningEku === true,
      timestampOrigin: new URL(config.timestampUrl).origin,
      timestampPresent: Boolean(identity.timestampThumbprint),
      verificationResult: "passed",
      disposableCleanup: "passed",
    };
  } catch (error) {
    failure = error;
  } finally {
    try {
      if (existsSync(sessionRoot)) removeSafeTree(DESKTOP_BUILD_ROOT, sessionRoot, options.pathOptions);
      cleanup = !existsSync(sessionRoot);
    } catch {
      cleanup = false;
    }
  }
  if (failure) {
    failure.disposableCleanup = cleanup ? "passed" : "failed";
    throw failure;
  }
  if (!cleanup) throw new Error("Disposable signer-preflight cleanup failed.");
  return result;
}

export async function runSignerPreflightWithMocks(profile, options = {}) {
  if (typeof options.loadConfig !== "function" || typeof options.preflight !== "function") {
    throw new Error("Programmatic signer preflight is test-only and requires explicit mocked configuration and signer boundaries.");
  }
  return runSignerPreflight(profile, options);
}

async function main() {
  const argv = process.argv.slice(2);
  const workerCount = argv.filter((argument) => argument === PREFLIGHT_WORKER_ARGUMENT).length;
  if (workerCount > 1) throw new Error("The signer-preflight worker marker may be provided only once.");
  const worker = workerCount === 1;
  const cleanArguments = argv.filter((argument) => argument !== PREFLIGHT_WORKER_ARGUMENT);
  const { profile } = parseSignerPreflightArguments(cleanArguments);
  if (!worker) {
    assertNoNodeRuntimeInjection(process.env);
    const environment = { ...process.env };
    for (const name of Object.keys(environment)) {
      if (new Set(["NODE_OPTIONS", "NODE_PATH"]).has(name.toUpperCase())) delete environment[name];
    }
    const result = runCommand(process.execPath, [SCRIPT_PATH, PREFLIGHT_WORKER_ARGUMENT, ...cleanArguments], {
      cwd: REPOSITORY_ROOT,
      env: environment,
      includeFailureOutput: true,
      timeoutMs: 300_000,
    });
    if (result.stdout) process.stdout.write(sanitizeDiagnosticText(result.stdout));
    if (result.stderr) process.stderr.write(sanitizeDiagnosticText(result.stderr));
    return;
  }
  try {
    const result = await runSignerPreflight(profile);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      selectedProfile: profile,
      verificationResult: "failed",
      disposableCleanup: error.disposableCleanup ?? "not-started",
      error: sanitizeDiagnosticText(error.message),
    }, null, 2)}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(SCRIPT_PATH)) {
  main().catch((error) => {
    process.stderr.write(`${sanitizeDiagnosticText(error.message)}\n`);
    process.exitCode = 1;
  });
}
