import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const outputPath = join(repository, "docs", "release", "third-party-runtime-inventory.json");
const cargoManifest = join(repository, "frontend", "src-tauri", "Cargo.toml");
const packageLockPath = join(repository, "frontend", "package-lock.json");
const requirementsPath = join(repository, "backend", "requirements.lock.txt");
const pythonSitePackages = join(repository, "backend", ".venv", "Lib", "site-packages");
const cargoRegistry = join(process.env.USERPROFILE ?? "", ".cargo", "registry", "src");

function fail(message) {
  throw new Error(message);
}

function normalizeName(value) {
  return value.toLowerCase().replaceAll("-", "_").replaceAll(".", "_");
}

function readText(path) {
  const bytes = readFileSync(path);
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return bytes.subarray(2).toString("utf16le");
  return bytes.toString("utf8").replace(/^\uFEFF/, "");
}

function packageSection(text) {
  const start = text.indexOf("[package]");
  if (start === -1) return "";
  const rest = text.slice(start + "[package]".length);
  const next = rest.search(/\r?\n\[/);
  return next === -1 ? rest : rest.slice(0, next);
}

function declaredLicense(manifestPath) {
  const section = packageSection(readFileSync(manifestPath, "utf8"));
  const expression = section.match(/^\s*license\s*=\s*"([^"]+)"/m)?.[1];
  if (expression) return expression;
  const licenseFile = section.match(/^\s*license-file\s*=\s*"([^"]+)"/m)?.[1];
  if (licenseFile) return `LicenseRef-upstream-file:${licenseFile}`;
  return "NOASSERTION";
}

function cargoManifestIndex() {
  if (!existsSync(cargoRegistry)) fail(`Cargo registry source cache is unavailable: ${cargoRegistry}`);
  const index = new Map();
  for (const registry of readdirSync(cargoRegistry, { withFileTypes: true }).filter((entry) => entry.isDirectory())) {
    const root = join(cargoRegistry, registry.name);
    for (const entry of readdirSync(root, { withFileTypes: true }).filter((item) => item.isDirectory())) {
      const manifest = join(root, entry.name, "Cargo.toml");
      if (existsSync(manifest)) index.set(entry.name, manifest);
    }
  }
  return index;
}

function rustRuntime() {
  const cargo = process.platform === "win32" ? "cargo.exe" : "cargo";
  const output = execFileSync(cargo, [
    "tree",
    "--manifest-path", cargoManifest,
    "--target", "x86_64-pc-windows-msvc",
    "--locked",
    "--offline",
    "--edges", "normal",
    "--prefix", "none",
    "--format", "{p}",
  ], { cwd: repository, encoding: "utf8" });

  const packages = new Map();
  for (const rawLine of output.split(/\r?\n/)) {
    const line = rawLine.replace(/\s+\(\*\)$/, "").trim();
    const match = line.match(/^(.+)\sv(\S+?)(?:\s+\(.+\))?$/);
    if (!match || match[1] === "glacial") continue;
    packages.set(`${match[1]}@${match[2]}`, { name: match[1], version: match[2] });
  }

  const manifests = cargoManifestIndex();
  const vendoredGlib = join(repository, "third_party", "rust", "glib-0.18.5-patched", "Cargo.toml");
  return [...packages.values()].map((entry) => {
    const manifest = entry.name === "glib" && entry.version === "0.18.5"
      ? vendoredGlib
      : manifests.get(`${entry.name}-${entry.version}`);
    if (!manifest) fail(`No cached Cargo manifest found for ${entry.name} ${entry.version}`);
    return { ...entry, license: declaredLicense(manifest) };
  }).sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
}

function npmRuntime() {
  const lock = JSON.parse(readFileSync(packageLockPath, "utf8"));
  const names = ["@tauri-apps/api", "react", "react-dom", "scheduler"];
  return names.map((name) => {
    const entry = lock.packages[`node_modules/${name}`];
    if (!entry?.version || !entry?.license) fail(`Incomplete npm notice metadata for ${name}`);
    return { name, version: entry.version, license: entry.license };
  });
}

function metadataValue(text, key) {
  return text.match(new RegExp(`^${key}:\\s*(.+)$`, "mi"))?.[1]?.trim() ?? "";
}

function pythonMetadataIndex() {
  if (!existsSync(pythonSitePackages)) fail(`Python site-packages is unavailable: ${pythonSitePackages}`);
  const index = new Map();
  for (const entry of readdirSync(pythonSitePackages, { withFileTypes: true })) {
    if (!entry.isDirectory() || !entry.name.endsWith(".dist-info")) continue;
    const metadataPath = join(pythonSitePackages, entry.name, "METADATA");
    if (!existsSync(metadataPath)) continue;
    const text = readFileSync(metadataPath, "utf8");
    const name = metadataValue(text, "Name");
    if (name) index.set(normalizeName(name), { text, metadataPath });
  }
  return index;
}

function pythonRuntime() {
  const fallbackLicenses = new Map([
    ["annotated_types", "MIT"],
    ["colorama", "BSD-3-Clause"],
    ["h11", "MIT"],
    ["setuptools", "MIT"],
  ]);
  const requirements = readText(requirementsPath)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const match = line.match(/^([^=]+)==(.+)$/);
      if (!match) fail(`Unsupported requirements entry: ${line}`);
      return { name: match[1], version: match[2] };
    });
  const metadata = pythonMetadataIndex();
  const runtime = requirements.map((entry) => {
    const normalized = normalizeName(entry.name);
    const record = metadata.get(normalized);
    if (!record) fail(`No Python metadata found for ${entry.name}`);
    const observedVersion = metadataValue(record.text, "Version");
    if (observedVersion !== entry.version) fail(`${entry.name} metadata is ${observedVersion}; expected ${entry.version}`);
    const license = metadataValue(record.text, "License-Expression") || fallbackLicenses.get(normalized);
    if (!license) fail(`No concise license expression found for ${entry.name}`);
    return { ...entry, license };
  });
  runtime.push({ name: "setuptools", version: "83.0.0", license: "MIT" });
  return runtime.sort((a, b) => a.name.localeCompare(b.name));
}

function inventory() {
  return {
    schemaVersion: "1.0.0",
    productVersion: "0.9.10",
    target: "Windows x64 current-user NSIS installed application",
    reviewedAt: "2026-07-28",
    sources: [
      "frontend/package-lock.json",
      "backend/requirements.lock.txt",
      "backend/.venv installed metadata",
      "cargo tree --target x86_64-pc-windows-msvc --edges normal --locked --offline",
      "frontend/src-tauri/tauri.conf.json",
      "G050 PyInstaller and installed payload readback",
    ],
    frontendRuntime: npmRuntime(),
    pythonRuntime: pythonRuntime(),
    rustRuntime: rustRuntime(),
    bundledNativeRuntime: [
      { name: "CPython", version: "3.13.13", license: "PSF-2.0" },
      { name: "OpenSSL", version: "3.0.19", license: "Apache-2.0" },
      { name: "SQLite", version: "3.50.4", license: "blessing" },
      { name: "libffi", version: "8 ABI", license: "MIT" },
      { name: "Microsoft Visual C++ Runtime", version: "14.42.34438.0", license: "LicenseRef-Microsoft-Redistributable" },
      { name: "PyInstaller bootloader", version: "6.21.0", license: "GPL-2.0-or-later WITH Bootloader-exception" },
      { name: "NSIS", version: "3.11", license: "Zlib" },
    ],
    prerequisiteNotBundled: [
      { name: "Microsoft Edge WebView2 Evergreen Runtime", version: "system managed", license: "LicenseRef-Microsoft-WebView2" },
    ],
    buildOnlyExamples: [
      "@vitejs/plugin-react",
      "Vite",
      "@tauri-apps/cli",
      "PyInstaller Python package and hooks",
      "Cargo and Rust toolchains",
      "npm",
      "test dependencies",
    ],
  };
}

const rendered = `${JSON.stringify(inventory(), null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (!existsSync(outputPath)) fail(`Inventory is missing: ${outputPath}`);
  if (readFileSync(outputPath, "utf8") !== rendered) fail("Third-party runtime inventory is stale.");
  console.log("Third-party runtime inventory matches locked Windows runtime inputs.");
} else {
  writeFileSync(outputPath, rendered, { flag: "w" });
  console.log(`Wrote ${outputPath}`);
}
