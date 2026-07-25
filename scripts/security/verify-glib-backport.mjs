import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const tauriRoot = resolve(repoRoot, "frontend", "src-tauri");
const vendoredRoot = resolve(repoRoot, "third_party", "rust", "glib-0.18.5-patched");

const expected = {
  archiveSha256: "233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5",
  copyrightSha256: "dae402989de65164815b7e2b6bc2b9576285434c3785934c8b6ece0fa055960d",
  licenseSha256: "8cf56d10131ce201cf69ab74b111d3ebac1acca3833d7efb39ae357224b70edb",
  patchSha256: "982b07f58864aad3d0aa0421cdd8ddc7438bb862b93e7b6b34da96b4147f8add",
  patchedVariantIterSha256: "a0f5ee8acb8faa089bcdfbc9a57372609fce7654026ccef7d9a224d05a654ccc",
  patchPath: "../../third_party/rust/glib-0.18.5-patched",
  version: "0.18.5",
};

function fail(message) {
  throw new Error(`glib backport verification failed: ${message}`);
}

function requireText(path) {
  if (!existsSync(path) || !statSync(path).isFile()) {
    fail(`required file is absent: ${path}`);
  }
  return readFileSync(path, "utf8").replaceAll("\r\n", "\n");
}

function sha256(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function section(text, name) {
  const lines = text.split("\n");
  const start = lines.findIndex((line) => line.trim() === `[${name}]`);
  if (start < 0) fail(`missing [${name}] section`);
  const relativeEnd = lines
    .slice(start + 1)
    .findIndex((line) => line.trimStart().startsWith("["));
  const end = relativeEnd < 0 ? lines.length : start + 1 + relativeEnd;
  return lines.slice(start + 1, end).join("\n");
}

const tauriManifest = requireText(resolve(tauriRoot, "Cargo.toml"));
const patchSection = section(tauriManifest, "patch.crates-io");
const glibOverrides = [
  ...patchSection.matchAll(
    /^\s*glib\s*=\s*\{\s*path\s*=\s*"([^"]+)"\s*\}\s*$/gm,
  ),
];
assert(glibOverrides.length === 1, "expected exactly one glib crates.io path override");
assert(
  glibOverrides[0][1] === expected.patchPath,
  `glib override must point to ${expected.patchPath}`,
);
assert(
  resolve(tauriRoot, glibOverrides[0][1]) === vendoredRoot,
  "glib override does not resolve to the documented vendored directory",
);

const vendoredManifest = requireText(resolve(vendoredRoot, "Cargo.toml"));
const packageSection = section(vendoredManifest, "package");
assert(/^name\s*=\s*"glib"\s*$/m.test(packageSection), "vendored package name changed");
assert(
  new RegExp(`^version\\s*=\\s*"${expected.version.replaceAll(".", "\\.")}"\\s*$`, "m").test(
    packageSection,
  ),
  `vendored package version must remain ${expected.version}`,
);

const lockfile = requireText(resolve(tauriRoot, "Cargo.lock"));
const glibLockPackages = lockfile
  .split("[[package]]")
  .slice(1)
  .filter((block) => /^name\s*=\s*"glib"\s*$/m.test(block));
assert(glibLockPackages.length === 1, "expected exactly one glib package in Cargo.lock");
assert(
  new RegExp(`^version\\s*=\\s*"${expected.version.replaceAll(".", "\\.")}"\\s*$`, "m").test(
    glibLockPackages[0],
  ),
  `Cargo.lock glib version must remain ${expected.version}`,
);
assert(
  !/^source\s*=/m.test(glibLockPackages[0]) && !/^checksum\s*=/m.test(glibLockPackages[0]),
  "Cargo.lock glib entry unexpectedly resolves to a registry source",
);

const variantIter = requireText(resolve(vendoredRoot, "src", "variant_iter.rs"));
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

const patch = requireText(resolve(vendoredRoot, "GHSA-wrw7-89jp-8q8g.patch"));
assert(sha256(patch) === expected.patchSha256, "the recorded upstream patch changed");

const license = requireText(resolve(vendoredRoot, "LICENSE"));
const copyright = requireText(resolve(vendoredRoot, "COPYRIGHT"));
assert(sha256(license) === expected.licenseSha256, "the preserved MIT LICENSE changed");
assert(sha256(copyright) === expected.copyrightSha256, "the preserved COPYRIGHT changed");

const provenance = requireText(resolve(vendoredRoot, "PROVENANCE.md"));
for (const required of [
  "glib",
  expected.version,
  expected.archiveSha256,
  "GHSA-wrw7-89jp-8q8g",
  "RUSTSEC-2024-0429",
  "https://github.com/gtk-rs/gtk-rs-core",
  "b5a4071e439bef2b5eea76c3aa25e5ae84839e34",
  "57383649f2766e6752170811286d89d393b318c6",
  expected.patchedVariantIterSha256,
  "LICENSE",
  "COPYRIGHT",
  "Complete intentional deviation list",
]) {
  assert(provenance.includes(required), `PROVENANCE.md is missing required value: ${required}`);
}

console.log(
  [
    "glib 0.18.5 backport verification passed:",
    `- crates.io override: ${expected.patchPath}`,
    "- Cargo.lock: one path-resolved glib 0.18.5 package",
    `- patched source baseline: ${expected.patchedVariantIterSha256}`,
    "- upstream patch, provenance, MIT licence, and copyright records present",
  ].join("\n"),
);
