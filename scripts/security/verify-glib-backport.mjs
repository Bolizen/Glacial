import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseTomlData } from "./toml-data.mjs";

const defaultRepoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const repoRoot = parseRepoRoot(process.argv.slice(2));
const tauriRoot = resolve(repoRoot, "frontend", "src-tauri");
const vendoredRoot = resolve(repoRoot, "third_party", "rust", "glib-0.18.5-patched");

const expected = {
  archiveSha256: "233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5",
  copyrightSha256: "dae402989de65164815b7e2b6bc2b9576285434c3785934c8b6ece0fa055960d",
  licenseSha256: "8cf56d10131ce201cf69ab74b111d3ebac1acca3833d7efb39ae357224b70edb",
  patchSha256: "982b07f58864aad3d0aa0421cdd8ddc7438bb862b93e7b6b34da96b4147f8add",
  patchedVariantIterSha256: "a0f5ee8acb8faa089bcdfbc9a57372609fce7654026ccef7d9a224d05a654ccc",
  vendoredTreeSha256: "7ad973f2e697cdb8ce96c750ddcb634c1c53a3d83f1e915a7c25641d1d2607b2",
  patchPath: "../../third_party/rust/glib-0.18.5-patched",
  version: "0.18.5",
};

function fail(message) {
  throw new Error(`glib backport verification failed: ${message}`);
}

function parseRepoRoot(args) {
  if (args.length === 0) {
    return requireRepoRoot(defaultRepoRoot);
  }
  if (
    args.length !== 2 ||
    args[0] !== "--repo-root" ||
    args[1].length === 0 ||
    args[1].startsWith("--")
  ) {
    fail("usage: node verify-glib-backport.mjs [--repo-root <path>]");
  }
  return requireRepoRoot(resolve(args[1]));
}

function requireRepoRoot(path) {
  let metadata;
  try {
    metadata = lstatSync(path);
  } catch {
    fail("selected repository root does not exist");
  }
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    fail("selected repository root must be a real directory, not a symbolic link");
  }
  return path;
}

function requireText(...parts) {
  let path = repoRoot;
  for (let index = 0; index < parts.length; index += 1) {
    path = resolve(path, parts[index]);
    const displayPath = parts.slice(0, index + 1).join("/");
    let metadata;
    try {
      metadata = lstatSync(path);
    } catch {
      fail(`required path is absent: ${displayPath}`);
    }
    if (metadata.isSymbolicLink()) {
      fail(`required path must not be a symbolic link: ${displayPath}`);
    }
    const isFinalPart = index === parts.length - 1;
    if (isFinalPart ? !metadata.isFile() : !metadata.isDirectory()) {
      fail(`required path has the wrong type: ${displayPath}`);
    }
  }
  return readFileSync(path, "utf8").replaceAll("\r\n", "\n");
}

function sha256(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function parseToml(text, label) {
  try { return parseTomlData(text); }
  catch (error) { fail(`${label} is not valid supported TOML: ${error.message}`); }
}

function vendoredTreeSha256(root) {
  const files = [];
  function walk(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name, "en"))) {
      const path = resolve(directory, entry.name);
      const metadata = lstatSync(path);
      if (metadata.isSymbolicLink()) fail(`vendored tree contains a symbolic link: ${relative(root, path)}`);
      if (entry.isDirectory()) walk(path);
      else if (entry.isFile()) files.push(path);
      else fail(`vendored tree contains an unsupported entry: ${relative(root, path)}`);
    }
  }
  walk(root);
  const hash = createHash("sha256");
  for (const path of files) {
    const name = relative(root, path).replaceAll("\\", "/");
    const nameBytes = Buffer.from(name, "utf8");
    const content = readFileSync(path);
    const header = Buffer.alloc(12);
    header.writeUInt32BE(nameBytes.length, 0);
    header.writeBigUInt64BE(BigInt(content.length), 4);
    hash.update(header).update(nameBytes).update(createHash("sha256").update(content).digest());
  }
  return hash.digest("hex");
}

const tauriManifest = requireText("frontend", "src-tauri", "Cargo.toml");
const tauriData = parseToml(tauriManifest, "frontend/src-tauri/Cargo.toml");
const glibOverride = tauriData.patch?.["crates-io"]?.glib;
assert(glibOverride && typeof glibOverride === "object" && !Array.isArray(glibOverride), "expected one semantic glib crates.io override");
assert(Object.keys(glibOverride).length === 1 && typeof glibOverride.path === "string", "glib override must contain only a path field");
assert(
  glibOverride.path === expected.patchPath,
  `glib override must point to ${expected.patchPath}`,
);
assert(
  resolve(tauriRoot, glibOverride.path) === vendoredRoot,
  "glib override does not resolve to the documented vendored directory",
);

const vendoredManifest = requireText(
  "third_party",
  "rust",
  "glib-0.18.5-patched",
  "Cargo.toml",
);
const vendoredData = parseToml(vendoredManifest, "vendored Cargo.toml");
assert(vendoredData.package?.name === "glib", "vendored package name changed");
assert(vendoredData.package?.version === expected.version, `vendored package version must remain ${expected.version}`);

const lockfile = requireText("frontend", "src-tauri", "Cargo.lock");
const lockData = parseToml(lockfile, "Cargo.lock");
assert(Array.isArray(lockData.package), "Cargo.lock has no semantic package array");
const glibLockPackages = lockData.package.filter((entry) => entry?.name === "glib");
assert(glibLockPackages.length === 1, "expected exactly one glib package in Cargo.lock");
assert(
  glibLockPackages[0].version === expected.version,
  `Cargo.lock glib version must remain ${expected.version}`,
);
assert(
  !Object.hasOwn(glibLockPackages[0], "source") && !Object.hasOwn(glibLockPackages[0], "checksum"),
  "Cargo.lock glib entry unexpectedly resolves to a registry source",
);

const variantIter = requireText(
  "third_party",
  "rust",
  "glib-0.18.5-patched",
  "src",
  "variant_iter.rs",
);
assert(
  variantIter.includes("let mut p: *mut libc::c_char = std::ptr::null_mut();"),
  "the mutable pointer binding correction is missing",
);
assert(
  variantIter.includes("\n                &mut p,\n"),
  "the mutable FFI out-argument correction is missing",
);
assert(
  !variantIter.includes("let p: *mut libc::c_char = std::ptr::null_mut();") &&
    !variantIter.includes("\n                &p,\n"),
  "the original unsound pointer form is present",
);
assert(
  sha256(variantIter) === expected.patchedVariantIterSha256,
  "src/variant_iter.rs differs from the documented patched baseline",
);

const patch = requireText(
  "third_party",
  "rust",
  "glib-0.18.5-patched",
  "GHSA-wrw7-89jp-8q8g.patch",
);
assert(sha256(patch) === expected.patchSha256, "the recorded upstream patch changed");

const license = requireText("third_party", "rust", "glib-0.18.5-patched", "LICENSE");
const copyright = requireText("third_party", "rust", "glib-0.18.5-patched", "COPYRIGHT");
assert(sha256(license) === expected.licenseSha256, "the preserved MIT LICENSE changed");
assert(sha256(copyright) === expected.copyrightSha256, "the preserved COPYRIGHT changed");

const provenanceText = requireText(
  "third_party",
  "rust",
  "glib-0.18.5-patched",
  "PROVENANCE.json",
);
let provenance;
try { provenance = JSON.parse(provenanceText); } catch { fail("PROVENANCE.json is malformed"); }
assert(provenance.schemaVersion === 1 && provenance.status === "accepted-backport", "provenance status is not affirmative");
assert(provenance.package?.name === "glib" && provenance.package?.version === expected.version, "provenance package identity changed");
assert(provenance.origin?.repository === "https://github.com/gtk-rs/gtk-rs-core", "provenance repository changed");
assert(provenance.origin?.archiveSha256 === expected.archiveSha256, "provenance archive hash changed");
assert(provenance.origin?.upstreamPatchCommit === "b5a4071e439bef2b5eea76c3aa25e5ae84839e34", "provenance patch commit changed");
assert(provenance.origin?.glacialBackportCommit === "57383649f2766e6752170811286d89d393b318c6", "provenance backport commit changed");
assert(JSON.stringify(provenance.advisories) === JSON.stringify(["GHSA-wrw7-89jp-8q8g", "RUSTSEC-2024-0429"]), "provenance advisories changed");
assert(provenance.patchedVariantIterSha256 === expected.patchedVariantIterSha256, "provenance patched source hash changed");
assert(provenance.preservedFiles?.LICENSE === expected.licenseSha256 && provenance.preservedFiles?.COPYRIGHT === expected.copyrightSha256, "provenance preserved-file hashes changed");
assert(JSON.stringify(provenance.intentionalDeviations) === JSON.stringify(["src/variant_iter.rs", "GHSA-wrw7-89jp-8q8g.patch", "PROVENANCE.md", "PROVENANCE.json"]), "provenance deviation list changed");

const actualVendoredTreeSha256 = vendoredTreeSha256(vendoredRoot);
assert(actualVendoredTreeSha256 === expected.vendoredTreeSha256, "complete vendored crate tree differs from the attested baseline");

console.log(
  [
    "glib 0.18.5 backport verification passed:",
    `- crates.io override: ${expected.patchPath}`,
    "- Cargo.lock: one path-resolved glib 0.18.5 package",
    `- complete vendored tree baseline: ${expected.vendoredTreeSha256}`,
    "- semantic Cargo/TOML identity and structured provenance verified",
  ].join("\n"),
);
