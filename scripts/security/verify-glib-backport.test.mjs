import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, copyFileSync, cpSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseTomlData } from "./toml-data.mjs";
import {
  canonicalPathsEqual,
  captureTrustedCargoExecutable,
  revalidateTrustedCargoExecutable,
  sameFilesystemObject,
} from "./path-identity.mjs";

const REPOSITORY = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const VERIFIER = join(REPOSITORY, "scripts", "security", "verify-glib-backport.mjs");
const TEST_ROOT = join(REPOSITORY, ".desktop-build", "glib-verifier-tests");

function fixture(parent = TEST_ROOT) {
  mkdirSync(parent, { recursive: true });
  const root = mkdtempSync(join(parent, "candidate-"));
  mkdirSync(join(root, "frontend", "src-tauri"), { recursive: true });
  mkdirSync(join(root, "frontend", "src-tauri", "src"), { recursive: true });
  mkdirSync(join(root, "third_party", "rust"), { recursive: true });
  cpSync(join(REPOSITORY, "frontend", "src-tauri", "Cargo.toml"), join(root, "frontend", "src-tauri", "Cargo.toml"));
  cpSync(join(REPOSITORY, "frontend", "src-tauri", "Cargo.lock"), join(root, "frontend", "src-tauri", "Cargo.lock"));
  writeFileSync(join(root, "frontend", "src-tauri", "src", "main.rs"), "fn main() {}\n");
  cpSync(join(REPOSITORY, "third_party", "rust", "glib-0.18.5-patched"), join(root, "third_party", "rust", "glib-0.18.5-patched"), { recursive: true });
  return root;
}

function verify(root, environment = process.env) {
  return spawnSync(process.execPath, [VERIFIER, "--repo-root", root], { cwd: REPOSITORY, encoding: "utf8", env: environment, shell: false });
}

function withFixture(run) {
  const root = fixture();
  try { return run(root); } finally { rmSync(root, { recursive: true, force: true }); }
}

function filesystemMetadata(kind, device, inode) {
  return {
    dev: BigInt(device),
    ino: BigInt(inode),
    isDirectory: () => kind === "directory",
    isFile: () => kind === "file",
    isSymbolicLink: () => kind === "symlink",
  };
}

function simulatedCargoTrustLayout() {
  const cargoHome = resolve(TEST_ROOT, "simulated-cargo-home");
  const bin = join(cargoHome, "bin");
  const cargo = join(bin, process.platform === "win32" ? "cargo.exe" : "cargo");
  const rustup = join(bin, process.platform === "win32" ? "rustup.exe" : "rustup");
  const state = {
    binKind: "directory",
    cargoLinkInode: 3,
    cargoTargetInode: 4,
    linkTarget: process.platform === "win32" ? "rustup.exe" : "rustup",
    rustupTargetInode: 4,
  };
  const inspectLink = (path) => {
    if (path === cargoHome) return filesystemMetadata("directory", 1, 1);
    if (path === bin) return filesystemMetadata(state.binKind, 1, 2);
    if (path === cargo) return filesystemMetadata("symlink", 1, state.cargoLinkInode);
    if (path === rustup) return filesystemMetadata("file", 1, state.rustupTargetInode);
    throw new Error(`unexpected simulated lstat path: ${path}`);
  };
  const inspectTarget = (path) => {
    if (path === cargo) return filesystemMetadata("file", 1, state.cargoTargetInode);
    if (path === rustup) return filesystemMetadata("file", 1, state.rustupTargetInode);
    throw new Error(`unexpected simulated stat path: ${path}`);
  };
  const readLink = (path) => {
    if (path === cargo) return state.linkTarget;
    throw new Error(`unexpected simulated readlink path: ${path}`);
  };
  return { cargoHome, cargo, inspectLink, inspectTarget, readLink, state };
}

test("trusted rustup Cargo symlink proxy resolves to the authenticated sibling rustup object", () => {
  const layout = simulatedCargoTrustLayout();
  const record = captureTrustedCargoExecutable(layout.cargoHome, layout);
  assert.equal(record.path, layout.cargo);
  assert.equal(record.kind, "rustup-symlink-proxy");
  assert.equal(revalidateTrustedCargoExecutable(record, layout.cargoHome, layout), layout.cargo);
});

test("real Unix rustup Cargo symlink proxy is accepted without allowing parent indirection", { skip: process.platform === "win32" }, () => {
  mkdirSync(TEST_ROOT, { recursive: true });
  const cargoHome = mkdtempSync(join(TEST_ROOT, "rustup-home-"));
  const bin = join(cargoHome, "bin");
  const rustup = join(bin, "rustup");
  const cargo = join(bin, "cargo");
  try {
    mkdirSync(bin);
    copyFileSync(process.execPath, rustup);
    chmodSync(rustup, 0o755);
    symlinkSync("rustup", cargo, "file");
    const record = captureTrustedCargoExecutable(cargoHome);
    assert.equal(record.kind, "rustup-symlink-proxy");
    assert.equal(record.path, cargo);
    assert.equal(revalidateTrustedCargoExecutable(record, cargoHome), cargo);
  } finally {
    rmSync(cargoHome, { recursive: true, force: true });
  }
});

test("Cargo symlink redirected to an arbitrary executable is rejected", () => {
  const layout = simulatedCargoTrustLayout();
  layout.state.cargoTargetInode = 99;
  assert.throws(
    () => captureTrustedCargoExecutable(layout.cargoHome, layout),
    /must resolve to the sibling rustup executable object/,
  );
});

test("unexpected intermediate symlink in the trusted Cargo path is rejected", () => {
  const layout = simulatedCargoTrustLayout();
  layout.state.linkTarget = join("proxy-chain", process.platform === "win32" ? "rustup.exe" : "rustup");
  assert.throws(
    () => captureTrustedCargoExecutable(layout.cargoHome, layout),
    /trusted Cargo symlink proxy must point directly to the sibling rustup executable/,
  );
  layout.state.linkTarget = process.platform === "win32" ? "rustup.exe" : "rustup";
  layout.state.binKind = "symlink";
  assert.throws(
    () => captureTrustedCargoExecutable(layout.cargoHome, layout),
    /trusted Cargo executable parent path must not contain symbolic links/,
  );
});

test("trusted Cargo proxy or target replacement after selection is rejected", () => {
  const layout = simulatedCargoTrustLayout();
  const record = captureTrustedCargoExecutable(layout.cargoHome, layout);
  layout.state.rustupTargetInode = 5;
  layout.state.cargoTargetInode = 5;
  assert.throws(
    () => revalidateTrustedCargoExecutable(record, layout.cargoHome, layout),
    /trusted Cargo executable identity changed after selection/,
  );
  layout.state.rustupTargetInode = 4;
  layout.state.cargoTargetInode = 4;
  layout.state.cargoLinkInode = 6;
  assert.throws(
    () => revalidateTrustedCargoExecutable(record, layout.cargoHome, layout),
    /trusted Cargo executable identity changed after selection/,
  );
});

test("valid semantic Cargo configuration and complete vendored tree pass", () => withFixture((root) => {
  const result = verify(root);
  assert.equal(result.status, 0, result.stderr);
}));

test("trusted Cargo metadata ignores a PATH-selected fake cargo executable", () => withFixture((root) => {
  const fakeBin = join(root, "fake-bin");
  const fakeCargo = join(fakeBin, process.platform === "win32" ? "cargo.exe" : "cargo");
  mkdirSync(fakeBin, { recursive: true });
  copyFileSync(process.execPath, fakeCargo);
  chmodSync(fakeCargo, 0o755);
  const result = verify(root, { ...process.env, PATH: `${fakeBin}${process.platform === "win32" ? ";" : ":"}${process.env.PATH ?? ""}` });
  assert.equal(result.status, 0, result.stderr);
}));

test("hostile Cargo environment variables cannot redirect trusted resolution", () => withFixture((root) => {
  const hostile = join(root, "hostile-cargo-home");
  const result = verify(root, {
    ...process.env,
    CARGO_HOME: hostile,
    CARGO_TARGET_DIR: join(hostile, "target"),
    CARGO_BUILD_TARGET: "attacker-controlled-target",
    RUSTFLAGS: "--cfg attacker_controlled",
  });
  assert.equal(result.status, 0, result.stderr);
}));

test("serialized Cargo records cannot replace independently reloaded release authority", () => withFixture((root) => {
  const result = verify(root, {
    ...process.env,
    CARGO: process.execPath,
    GLACIAL_RELEASE_CARGO_AUTHORITY_JSON: JSON.stringify({ role: "cargo", path: process.execPath, sha256: "0".repeat(64) }),
  });
  assert.equal(result.status, 0, result.stderr);
}));

test("partial signed-release authority context fails before Cargo execution", () => withFixture((root) => {
  const result = verify(root, { ...process.env, GLACIAL_RELEASE_PROFILE: "signed-preview" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /signed-release authority context is incomplete/);
}));

test("user Cargo resolution configuration is rejected", () => withFixture((root) => {
  const userHome = join(root, "hostile-user-home");
  const config = join(userHome, ".cargo", "config.toml");
  mkdirSync(dirname(config), { recursive: true });
  writeFileSync(config, '[source.crates-io]\nreplace-with = "attacker"\n');
  const result = verify(root, { ...process.env, HOME: userHome, USERPROFILE: userHome });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /trusted Cargo home must not contain dependency-resolution configuration/);
}));

test("workspace-ancestor Cargo resolution configuration is rejected", () => {
  mkdirSync(TEST_ROOT, { recursive: true });
  const workspace = mkdtempSync(join(TEST_ROOT, "workspace-"));
  const root = fixture(workspace);
  try {
    const config = join(workspace, ".cargo", "config.toml");
    mkdirSync(dirname(config), { recursive: true });
    writeFileSync(config, '[patch.crates-io]\nglib = { path = "attacker" }\n');
    const result = verify(root);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /project Cargo configuration is forbidden/);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
});

test("vendored path substitution through a symbolic link is rejected", () => withFixture((root) => {
  const vendored = join(root, "third_party", "rust", "glib-0.18.5-patched");
  const retained = join(root, "third_party", "rust", "retained-glib");
  cpSync(vendored, retained, { recursive: true });
  rmSync(vendored, { recursive: true, force: true });
  symlinkSync(retained, vendored, process.platform === "win32" ? "junction" : "dir");
  const result = verify(root);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /must not be a symbolic link/);
}));

test("canonical manifest comparison preserves platform case semantics", () => {
  const canonicalize = (path) => path;
  assert.equal(canonicalPathsEqual("/trusted/Cargo.toml", "/trusted/cargo.toml", { canonicalize, platform: "linux" }), false);
  assert.equal(canonicalPathsEqual("C:\\TRUSTED\\Cargo.toml", "c:\\trusted\\cargo.toml", { canonicalize, platform: "win32" }), true);
});

test("expected manifest identity accepts a hardlink and rejects a copied object", () => withFixture((root) => {
  const manifest = join(root, "third_party", "rust", "glib-0.18.5-patched", "Cargo.toml");
  const alias = join(root, "manifest-hardlink.toml");
  const copy = join(root, "manifest-copy.toml");
  linkSync(manifest, alias);
  copyFileSync(manifest, copy);
  assert.equal(sameFilesystemObject(manifest, alias), true);
  assert.equal(sameFilesystemObject(manifest, copy), false);
}));

test("TOML mappings retain prototype-sensitive keys as own data only", () => {
  const parsed = parseTomlData('__proto__.patch."crates-io".glib = { path = "vendor/glib" }\n');
  assert.equal(Object.getPrototypeOf(parsed), null);
  assert.equal(Object.hasOwn(parsed, "__proto__"), true);
  assert.equal(Object.hasOwn(parsed, "patch"), false);
  assert.equal(Object.getPrototypeOf(parsed.__proto__), null);
  assert.equal(parsed.__proto__.patch["crates-io"].glib.path, "vendor/glib");
});

test("prototype-bearing TOML cannot synthesize the trusted glib override", () => withFixture((root) => {
  const path = join(root, "frontend", "src-tauri", "Cargo.toml");
  const manifest = readFileSync(path, "utf8").replace(
    '[patch.crates-io]\nglib = { path = "../../third_party/rust/glib-0.18.5-patched" }',
    '["__proto__".patch.crates-io]\nglib = { path = "../../third_party/rust/glib-0.18.5-patched" }',
  );
  writeFileSync(path, manifest);
  const result = verify(root);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /expected one semantic glib crates\.io override/);
}));

for (const [relativeConfig, content] of [
  [join(".cargo", "config.toml"), '[source.crates-io]\nreplace-with = "alternate"\n[source.alternate]\ndirectory = "alternate-vendor"\n'],
  [join("frontend", "src-tauri", ".cargo", "config"), 'paths = ["../../../../alternate-glib"]\n'],
]) test(`project Cargo resolution configuration is rejected: ${relativeConfig}`, () => withFixture((root) => {
  const config = join(root, relativeConfig);
  mkdirSync(dirname(config), { recursive: true });
  writeFileSync(config, content);
  const result = verify(root);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /project Cargo configuration is forbidden/);
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
