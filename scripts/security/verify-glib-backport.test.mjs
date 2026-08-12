import test from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPOSITORY = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const VERIFIER = join(REPOSITORY, "scripts", "security", "verify-glib-backport.mjs");
const TEST_ROOT = join(REPOSITORY, ".desktop-build", "glib-verifier-tests");

function fixture() {
  mkdirSync(TEST_ROOT, { recursive: true });
  const root = mkdtempSync(join(TEST_ROOT, "candidate-"));
  mkdirSync(join(root, "frontend", "src-tauri"), { recursive: true });
  mkdirSync(join(root, "third_party", "rust"), { recursive: true });
  cpSync(join(REPOSITORY, "frontend", "src-tauri", "Cargo.toml"), join(root, "frontend", "src-tauri", "Cargo.toml"));
  cpSync(join(REPOSITORY, "frontend", "src-tauri", "Cargo.lock"), join(root, "frontend", "src-tauri", "Cargo.lock"));
  cpSync(join(REPOSITORY, "third_party", "rust", "glib-0.18.5-patched"), join(root, "third_party", "rust", "glib-0.18.5-patched"), { recursive: true });
  return root;
}

function verify(root) {
  return spawnSync(process.execPath, [VERIFIER, "--repo-root", root], { cwd: REPOSITORY, encoding: "utf8", shell: false });
}

function withFixture(run) {
  const root = fixture();
  try { return run(root); } finally { rmSync(root, { recursive: true, force: true }); }
}

test("valid semantic Cargo configuration and complete vendored tree pass", () => withFixture((root) => {
  const result = verify(root);
  assert.equal(result.status, 0, result.stderr);
}));

test("quoted-key and multiline patch-path decoys are rejected", () => withFixture((root) => {
  writeFileSync(join(root, "frontend", "src-tauri", "Cargo.toml"), `[package]\nname = "glacial"\nversion = "0.9.12"\ndescription = """\nglib = { path = "../../third_party/rust/glib-0.18.5-patched" }\n"""\n[patch.crates-io]\n"glib" = { path = "../../third_party/rust/other" }\n`);
  const result = verify(root);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /glib override must point/);
}));

test("quoted semantic Cargo.lock registry provenance defeats multiline decoys", () => withFixture((root) => {
  writeFileSync(join(root, "frontend", "src-tauri", "Cargo.lock"), `version = 4\n[[package]]\ndescription = """\nname = "glib"\nversion = "0.18.5"\n"""\n"name" = "glib"\n"version" = "0.18.5"\n"source" = "registry+https://github.com/rust-lang/crates.io-index"\n"checksum" = "${"a".repeat(64)}"\n`);
  const result = verify(root);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /registry source/);
}));

test("vendored package identity uses effective quoted fields", () => withFixture((root) => {
  const path = join(root, "third_party", "rust", "glib-0.18.5-patched", "Cargo.toml");
  writeFileSync(path, `[package]\ndescription = """\nname = "glib"\nversion = "0.18.5"\n"""\n"name" = "not-glib"\n"version" = "9.9.9"\n`);
  const result = verify(root);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /package name changed/);
}));

test("contradictory structured provenance is rejected even when expected tokens remain", () => withFixture((root) => {
  const path = join(root, "third_party", "rust", "glib-0.18.5-patched", "PROVENANCE.json");
  const provenance = JSON.parse(readFileSync(path, "utf8"));
  provenance.status = "rejected-backport";
  writeFileSync(path, `${JSON.stringify(provenance, null, 2)}\n`);
  const result = verify(root);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /status is not affirmative/);
}));

for (const [name, mutate] of [
  ["modification", (root) => writeFileSync(join(root, "third_party", "rust", "glib-0.18.5-patched", "src", "lib.rs"), "attacker-controlled source\n")],
  ["addition", (root) => writeFileSync(join(root, "third_party", "rust", "glib-0.18.5-patched", "build.rs"), "fn main() {}\n")],
]) test(`complete vendored-tree attestation rejects executable ${name}`, () => withFixture((root) => {
  mutate(root);
  const result = verify(root);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /complete vendored crate tree/);
}));
