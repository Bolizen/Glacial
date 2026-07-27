import assert from "node:assert/strict";
import test from "node:test";

import {
  redactSecretValues,
  replaceAbsolutePaths,
  safeErrorMessage,
  sanitizeDisclosureText,
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
