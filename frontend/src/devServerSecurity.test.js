import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import viteConfig from "../vite.config.js";

const tauriConfig = JSON.parse(
  readFileSync(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"),
);

test("Tauri development uses Vite's fixed fail-closed loopback port", () => {
  const devUrl = new URL(tauriConfig.build.devUrl);

  assert.equal(tauriConfig.build.beforeDevCommand.cwd, "..");
  assert.equal(tauriConfig.build.beforeDevCommand.script, "pnpm run dev");
  assert.equal(devUrl.protocol, "http:");
  assert.equal(devUrl.hostname, viteConfig.server.host);
  assert.equal(Number(devUrl.port), viteConfig.server.port);
  assert.equal(viteConfig.server.strictPort, true);
  assert.equal(viteConfig.preview.strictPort, false);
});
