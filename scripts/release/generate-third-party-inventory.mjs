import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { packageVersionKeys } from "./pnpm-lock.mjs";
import {
  WINDOWS_RELEASE_PYTHON,
  assertWindowsReleasePythonIdentity,
  currentProductVersion,
} from "./release-contract.mjs";

const scriptPath = fileURLToPath(import.meta.url);
const repository = resolve(dirname(scriptPath), "..", "..");
const frontend = join(repository, "frontend");
const outputPath = join(repository, "docs", "release", "third-party-runtime-inventory.json");
const cargoManifest = join(repository, "frontend", "src-tauri", "Cargo.toml");
const pnpmLockPath = join(frontend, "pnpm-lock.yaml");
const requirementsPath = join(repository, "backend", "requirements.lock.txt");
const defaultPythonSitePackages = join(repository, "backend", ".venv", "Lib", "site-packages");
const cargoRegistry = join(process.env.USERPROFILE ?? "", ".cargo", "registry", "src");

function fail(message) {
  throw new Error(message);
}

function normalizeName(value) {
  return value.toLowerCase().replaceAll("-", "_").replaceAll(".", "_");
}

function repositoryChild(path, label) {
  const resolved = resolve(path);
  const child = relative(repository, resolved);
  if (!child || child === ".." || child.startsWith(`..${sep}`) || isAbsolute(child)) {
    fail(`${label} must remain inside the repository.`);
  }
  return resolved;
}

export function resolvePythonSitePackages(value = defaultPythonSitePackages) {
  const resolved = repositoryChild(value, "Python site-packages");
  if (!existsSync(resolved)) fail(`Python site-packages is unavailable: ${resolved}`);
  if (!lstatSync(resolved).isDirectory() || lstatSync(resolved).isSymbolicLink()) {
    fail(`Python site-packages must be a real directory: ${resolved}`);
  }
  const canonicalRepository = realpathSync.native(repository);
  const canonical = realpathSync.native(resolved);
  const child = relative(canonicalRepository, canonical);
  if (!child || child === ".." || child.startsWith(`..${sep}`) || isAbsolute(child)) {
    fail(`Python site-packages escapes the repository: ${resolved}`);
  }
  return resolved;
}

export function parseInventoryArguments(argv) {
  let check = false;
  let pythonSitePackages;
  let pythonRuntime;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--check") {
      check = true;
    } else if (argument === "--python-site-packages") {
      if (pythonSitePackages !== undefined) fail("--python-site-packages may be provided only once.");
      pythonSitePackages = argv[index + 1];
      if (!pythonSitePackages || pythonSitePackages.startsWith("--")) fail("--python-site-packages requires a path.");
      index += 1;
    } else if (argument === "--python-runtime") {
      if (pythonRuntime !== undefined) fail("--python-runtime may be provided only once.");
      pythonRuntime = argv[index + 1];
      if (!pythonRuntime || pythonRuntime.startsWith("--")) fail("--python-runtime requires an executable path.");
      index += 1;
    } else {
      fail(`Unknown inventory argument: ${argument}`);
    }
  }
  return { check, pythonSitePackages: resolvePythonSitePackages(pythonSitePackages), pythonRuntimePath: pythonRuntime };
}

function verifyPythonRuntime(value) {
  if (value === undefined) return;
  const resolved = repositoryChild(value, "Python runtime");
  if (!existsSync(resolved) || !lstatSync(resolved).isFile() || lstatSync(resolved).isSymbolicLink()) {
    fail(`Python runtime must be a real executable file: ${resolved}`);
  }
  const canonicalRepository = realpathSync.native(repository);
  const canonical = realpathSync.native(resolved);
  const child = relative(canonicalRepository, canonical);
  if (!child || child === ".." || child.startsWith(`..${sep}`) || isAbsolute(child)) {
    fail(`Python runtime escapes the repository: ${resolved}`);
  }
  const identity = JSON.parse(execFileSync(canonical, [
    "-c",
    "import json, platform, struct, sys; print(json.dumps({'executable': sys.executable, 'implementation': sys.implementation.name, 'version': platform.python_version(), 'platform': sys.platform, 'bits': struct.calcsize('P') * 8, 'machine': platform.machine()}))",
  ], { cwd: repository, encoding: "utf8", windowsHide: true }));
  if (realpathSync.native(identity.executable).toLowerCase() !== canonical.toLowerCase()) {
    fail("Python runtime identity does not match --python-runtime.");
  }
  assertWindowsReleasePythonIdentity(identity);
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

function nodePackageManifest(name) {
  const segments = name.split("/");
  const candidates = [
    join(frontend, "node_modules", ...segments, "package.json"),
    join(frontend, "node_modules", ".pnpm", "node_modules", ...segments, "package.json"),
  ];
  const path = candidates.find((candidate) => existsSync(candidate));
  if (!path) fail(`Installed pnpm package metadata is unavailable for ${name}`);
  return JSON.parse(readFileSync(path, "utf8"));
}

function nodeRuntime() {
  const locked = packageVersionKeys(readFileSync(pnpmLockPath, "utf8"));
  const names = ["@tauri-apps/api", "react", "react-dom", "scheduler"];
  return names.map((name) => {
    const manifest = nodePackageManifest(name);
    if (!manifest.version || !manifest.license || !locked.has(`${name}@${manifest.version}`)) {
      fail(`Incomplete or unlocked pnpm notice metadata for ${name}`);
    }
    return { name, version: manifest.version, license: manifest.license };
  });
}

function metadataValue(text, key) {
  return text.match(new RegExp(`^${key}:\\s*(.+)$`, "mi"))?.[1]?.trim() ?? "";
}

function pythonMetadataIndex(pythonSitePackages) {
  const index = new Map();
  for (const entry of readdirSync(pythonSitePackages, { withFileTypes: true })) {
    if (!entry.isDirectory() || !entry.name.endsWith(".dist-info")) continue;
    const metadataPath = join(pythonSitePackages, entry.name, "METADATA");
    if (!existsSync(metadataPath)) continue;
    const text = readFileSync(metadataPath, "utf8");
    const name = metadataValue(text, "Name");
    if (!name) continue;
    const normalized = normalizeName(name);
    if (index.has(normalized)) fail(`Duplicate Python metadata found for ${name}`);
    index.set(normalized, { text, metadataPath });
  }
  return index;
}

export function parseLockedPythonRequirements(text) {
  const seen = new Set();
  return readTextBuffer(text)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line, index) => {
      const match = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)$/);
      if (!match) fail(`Unsupported requirements entry ${index + 1}: ${line}`);
      const normalized = normalizeName(match[1]);
      if (seen.has(normalized)) fail(`Duplicate requirements entry: ${match[1]}`);
      seen.add(normalized);
      return { name: match[1], normalized, version: match[2] };
    });
}

function readTextBuffer(value) {
  if (Buffer.isBuffer(value)) {
    if (value[0] === 0xff && value[1] === 0xfe) return value.subarray(2).toString("utf16le");
    return value.toString("utf8").replace(/^\uFEFF/, "");
  }
  return String(value).replace(/^\uFEFF/, "");
}

export function pythonRuntime(pythonSitePackages, requirementsText = readFileSync(requirementsPath)) {
  const fallbackLicenses = new Map([
    ["annotated_types", "MIT"],
    ["colorama", "BSD-3-Clause"],
    ["h11", "MIT"],
  ]);
  const requirements = parseLockedPythonRequirements(requirementsText);
  const metadata = pythonMetadataIndex(resolvePythonSitePackages(pythonSitePackages));
  const expected = new Set(requirements.map((entry) => entry.normalized));
  const unexpected = [...metadata.keys()].filter((name) => name !== "pip" && !expected.has(name)).sort();
  if (unexpected.length) fail(`Unexpected Python metadata found: ${unexpected.join(", ")}`);
  const runtime = requirements.map((entry) => {
    const record = metadata.get(entry.normalized);
    if (!record) fail(`No Python metadata found for ${entry.name}`);
    const observedVersion = metadataValue(record.text, "Version");
    if (observedVersion !== entry.version) fail(`${entry.name} metadata is ${observedVersion}; expected ${entry.version}`);
    const license = metadataValue(record.text, "License-Expression") || fallbackLicenses.get(entry.normalized);
    if (!license) fail(`No concise license expression found for ${entry.name}`);
    return { name: entry.name, version: entry.version, license };
  });
  return runtime.sort((a, b) => a.name.localeCompare(b.name));
}

export function inventory({ pythonSitePackages = defaultPythonSitePackages, pythonRuntimePath } = {}) {
  verifyPythonRuntime(pythonRuntimePath);
  return {
    schemaVersion: "1.0.0",
    productVersion: currentProductVersion(),
    target: "Windows x64 current-user NSIS installed application",
    reviewedAt: "2026-07-28",
    sources: [
      "frontend/pnpm-lock.yaml",
      "frontend/node_modules installed pnpm metadata",
      "backend/requirements.lock.txt",
      "explicit installed Python metadata from backend/requirements.lock.txt",
      "explicit CPython runtime identity against scripts/release/release-contract.mjs",
      "cargo tree --target x86_64-pc-windows-msvc --edges normal --locked --offline",
      "frontend/src-tauri/tauri.conf.json",
      "G050 PyInstaller and installed payload readback",
    ],
    frontendRuntime: nodeRuntime(),
    pythonRuntime: pythonRuntime(pythonSitePackages),
    rustRuntime: rustRuntime(),
    bundledNativeRuntime: [
      { name: WINDOWS_RELEASE_PYTHON.name, version: WINDOWS_RELEASE_PYTHON.version, license: "PSF-2.0" },
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
      "pnpm",
      "test dependencies",
    ],
  };
}

export function runInventory(argv = process.argv.slice(2)) {
  const options = parseInventoryArguments(argv);
  const rendered = `${JSON.stringify(inventory(options), null, 2)}\n`;
  if (options.check) {
    if (!existsSync(outputPath)) fail(`Inventory is missing: ${outputPath}`);
    if (readFileSync(outputPath, "utf8") !== rendered) fail("Third-party runtime inventory is stale.");
    console.log("Third-party runtime inventory matches locked Windows runtime inputs.");
  } else {
    writeFileSync(outputPath, rendered, { flag: "w" });
    console.log(`Wrote ${outputPath}`);
  }
  return rendered;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(scriptPath)) {
  runInventory();
}
