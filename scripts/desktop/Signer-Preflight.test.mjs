import assert from "node:assert/strict";
import test from "node:test";

import { parseSignerPreflightArguments, runSignerPreflight } from "./Signer-Preflight.mjs";

const PUBLIC_IDENTITY = {
  canonicalSubject: "CN=ICEFIELDS DEVELOPMENT",
  signerThumbprint: "A".repeat(40),
  trustClassification: "publicly-trusted",
  signerNotBeforeUtc: "2026-01-01T00:00:00.000Z",
  signerNotAfterUtc: "2027-01-01T00:00:00.000Z",
  codeSigningEku: true,
  timestampThumbprint: "B".repeat(40),
};
const CONFIG = {
  provider: "store",
  expectedSubject: "CN=Icefields Development",
  expectedThumbprint: "A".repeat(40),
  timestampUrl: "https://timestamp.example.test/",
};

test("signer preflight accepts only exact supported profile arguments", () => {
  assert.deepEqual(parseSignerPreflightArguments(["--profile", "public-rc"]), { profile: "public-rc" });
  assert.throws(() => parseSignerPreflightArguments(["--profile", "stable"]), /requires/);
  assert.throws(() => parseSignerPreflightArguments(["--dry-run"]), /requires/);
});

test("public signer preflight reports bounded observed evidence", async () => {
  const result = await runSignerPreflight("public-rc", {
    loadConfig: () => CONFIG,
    preflight: async () => PUBLIC_IDENTITY,
    pathOptions: { pathInspector: false },
  });
  assert.equal(result.verificationResult, "passed");
  assert.equal(result.trustClassification, "publicly-trusted");
  assert.equal(result.codeSigningEku, true);
  assert.equal(result.timestampPresent, true);
  assert.equal(result.disposableCleanup, "passed");
  assert.equal(JSON.stringify(result).includes("Users"), false);
});

test("public RC rejects self-signed trust before product construction", async () => {
  await assert.rejects(() => runSignerPreflight("public-rc", {
    loadConfig: () => CONFIG,
    preflight: async () => ({ ...PUBLIC_IDENTITY, trustClassification: "self-signed" }),
    pathOptions: { pathInspector: false },
  }), /publicly-trusted/);
});

