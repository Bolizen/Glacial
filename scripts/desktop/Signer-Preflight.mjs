import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { assertReleaseProfileTrust } from "./Build-SignedWindowsRelease.mjs";
import {
  DESKTOP_BUILD_ROOT,
  REPOSITORY_ROOT,
  ensureSafeDirectory,
  loadSigningConfig,
  preflightSigningProvider,
  removeSafeTree,
  sanitizeDiagnosticText,
} from "./windows-signing.mjs";
import {
  authenticateReleaseTools,
  loadReleaseAuthority,
  verifyAuthorizedReleaseCheckout,
} from "../release/release-authority.mjs";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const PROFILES = new Set(["signed-preview", "public-rc"]);

export function parseSignerPreflightArguments(args) {
  if (args.length !== 2 || args[0] !== "--profile" || !PROFILES.has(args[1])) {
    throw new Error("Signer preflight requires --profile signed-preview or --profile public-rc.");
  }
  return { profile: args[1] };
}

export async function runSignerPreflight(profile, options = {}) {
  if (!PROFILES.has(profile)) throw new Error(`Unsupported signer preflight profile: ${profile}.`);
  const sessionRoot = join(DESKTOP_BUILD_ROOT, "signer-preflight", `session-${process.pid}-${Date.now()}`);
  let cleanup = true;
  let result = null;
  let failure = null;
  try {
    ensureSafeDirectory(DESKTOP_BUILD_ROOT, sessionRoot, options.pathOptions);
    const environment = options.environment ?? process.env;
    let config;
    if (options.loadConfig) {
      config = options.loadConfig(environment);
    } else {
      const authority = loadReleaseAuthority(environment, { repository: REPOSITORY_ROOT });
      const tools = authenticateReleaseTools(authority, { node: process.execPath });
      verifyAuthorizedReleaseCheckout(authority, tools.git, REPOSITORY_ROOT);
      config = loadSigningConfig(environment, { authority, tools, profile });
    }
    const identity = await (options.preflight ?? preflightSigningProvider)(config, {
      probeParent: join(sessionRoot, "probe"),
      ...(options.preflightOptions ?? {}),
    });
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

async function main() {
  const { profile } = parseSignerPreflightArguments(process.argv.slice(2));
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
