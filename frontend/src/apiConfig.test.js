import assert from "node:assert/strict";
import test from "node:test";

import { DEFAULT_API_BASE_URL, resolveApiBaseUrl } from "./apiConfig.js";

test("API base URL defaults to the local backend", () => {
  assert.equal(resolveApiBaseUrl(), DEFAULT_API_BASE_URL);
  assert.equal(resolveApiBaseUrl("   "), DEFAULT_API_BASE_URL);
});

test("API base URL accepts a configured value without duplicate separators", () => {
  assert.equal(resolveApiBaseUrl("  http://127.0.0.1:8010///  "), "http://127.0.0.1:8010");
  assert.equal(resolveApiBaseUrl("https://codexforge.example.test/api"), "https://codexforge.example.test/api");
});
