import assert from "node:assert/strict";
import test from "node:test";

import {
  redactSecretValues,
  replaceAbsolutePaths,
  safeErrorMessage,
  sanitizeDisclosureText,
  validateStructuredDigest,
} from "./privacy.js";


const HOSTILE = [
  "C:\\Users\\privacy-canary\\AppData\\Local\\Temp\\trace.txt",
  "\\\\privacy-server\\private-share\\trace.txt",
  "D:\\Utilisateurs\\Renée\\秘密\\trace.txt",
  "Authorization: Bearer privacy-bearer-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  "password=privacy-password-canary",
  "SERVICE_API_KEY=privacy-env-value-0123456789",
  "postgresql://privacy-user:privacy-db-password@localhost/private",
  "AKIAIOSFODNN7EXAMPLE",
  "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB",
  "-----BEGIN PRIVATE KEY-----",
  "ZmFrZS1wcml2YXRlLWtleS1tYXRlcmlhbA==",
  "-----END PRIVATE KEY-----",
  "terminal=\u001b[31mred\u0000",
].join("\n");

const FORBIDDEN = [
  "privacy-canary",
  "privacy-server",
  "Renée",
  "privacy-bearer-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  "privacy-password-canary",
  "privacy-env-value-0123456789",
  "privacy-db-password",
  "AKIAIOSFODNN7EXAMPLE",
  "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB",
  "ZmFrZS1wcml2YXRlLWtleS1tYXRlcmlhbA==",
  "\u001b",
  "\u0000",
];
const HEX_CANARIES = [
  "A1".repeat(20),
  "b2".repeat(32),
  "C3d4".repeat(24),
  "e5F6".repeat(32),
];


test("frontend disclosure helpers redact hostile credentials paths and controls", () => {
  const result = sanitizeDisclosureText(HOSTILE, 4000, { preserveLines: true });
  for (const value of FORBIDDEN) assert.equal(result.includes(value), false);
  assert.match(result, /\[REDACTED/);
  assert.match(result, /<HOST_PATH>|<TEMP_DIR>/);
});


test("frontend disclosure helpers preserve useful ordinary metadata", () => {
  const value = sanitizeDisclosureText(
    "scanner.suspicious-text-pattern src/ordinary.js line 17 react 19.0.0",
  );
  assert.equal(
    value,
    "scanner.suspicious-text-pattern src/ordinary.js line 17 react 19.0.0",
  );
  assert.equal(redactSecretValues("ordinary-value"), "ordinary-value");
  assert.equal(replaceAbsolutePaths("src/ordinary.js"), "src/ordinary.js");
});


test("frontend error messages are bounded and sanitize backend legacy detail", () => {
  const message = safeErrorMessage(`Failure at ${HOSTILE}`);
  assert.ok(message.length <= 300);
  for (const value of FORBIDDEN) assert.equal(message.includes(value), false);
  assert.match(message, /Failure at/);
});


test("frontend generic disclosure redacts hex canaries while typed digests remain exact", () => {
  const disclosure = sanitizeDisclosureText([
    HEX_CANARIES[0],
    `prose ${HEX_CANARIES[1]} after`,
    `evidence/${HEX_CANARIES[2]}.txt`,
    `sha512:${HEX_CANARIES[3]}`,
  ].join("\n"), 4000, { preserveLines: true });
  for (const canary of HEX_CANARIES) assert.equal(disclosure.includes(canary), false);
  assert.equal((disclosure.match(/\[REDACTED\]/g) || []).length, 4);
  assert.equal(safeErrorMessage(`API failed: ${HEX_CANARIES[1]}`).includes(HEX_CANARIES[1]), false);

  const commit = "1a".repeat(20);
  const checksum = "B2".repeat(32);
  const fingerprint = `cf1_${"c3".repeat(32)}`;
  assert.equal(validateStructuredDigest(commit, "git-commit"), commit);
  assert.equal(validateStructuredDigest(checksum, "sha256"), checksum);
  assert.equal(validateStructuredDigest(fingerprint, "fingerprint"), fingerprint);
  assert.throws(() => validateStructuredDigest("f".repeat(39), "git-commit"));
  assert.throws(() => validateStructuredDigest("f".repeat(63), "sha256"));
  assert.throws(() => validateStructuredDigest("f".repeat(64), "fingerprint"));
});
