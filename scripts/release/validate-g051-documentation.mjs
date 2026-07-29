import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const expectedVersion = "0.9.11";

function fail(message) {
  console.error(`G051 documentation validation failed: ${message}`);
  process.exitCode = 1;
}

function read(relative) {
  return readFileSync(join(repository, relative), "utf8");
}

function markdownFiles(root) {
  const result = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (entry.name === ".git" || entry.name === "node_modules" || entry.name === ".desktop-build") continue;
    const path = join(root, entry.name);
    if (entry.isDirectory()) result.push(...markdownFiles(path));
    else if (entry.isFile() && extname(entry.name).toLowerCase() === ".md") result.push(path);
  }
  return result;
}

function targetPath(source, rawTarget) {
  const target = rawTarget.trim().replace(/^<|>$/g, "");
  if (!target || target.startsWith("#") || /^[a-z]+:/i.test(target)) return null;
  const pathPart = decodeURIComponent(target.split("#", 1)[0]).replaceAll("/", "\\");
  return resolve(dirname(source), pathPart);
}

const projectMarkdown = [
  ...markdownFiles(join(repository, "docs")),
  ...readdirSync(repository, { withFileTypes: true })
    .filter((entry) => entry.isFile() && extname(entry.name).toLowerCase() === ".md")
    .map((entry) => join(repository, entry.name)),
];
for (const source of projectMarkdown) {
  const text = readFileSync(source, "utf8");
  for (const match of text.matchAll(/!?\[[^\]]*]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)) {
    const target = targetPath(source, match[1]);
    if (!target) continue;
    if (!target.toLowerCase().startsWith(repository.toLowerCase())) {
      fail(`${source} has an escaping link target: ${match[1]}`);
      continue;
    }
    if (!existsSync(target)) fail(`${source} has a missing link target: ${match[1]}`);
  }
}

const requiredDocuments = [
  "docs/installed-windows-lifecycle.md",
  "docs/evidence-and-remediation.md",
  "docs/supported-environments.md",
  "docs/privacy-and-network.md",
  "docs/support.md",
  "SECURITY.md",
  "THIRD_PARTY_NOTICES.md",
];
for (const document of requiredDocuments) {
  const path = join(repository, document);
  if (!existsSync(path) || !statSync(path).isFile()) fail(`required document is missing: ${document}`);
  if (!readFileSync(path, "utf8").trim()) fail(`required document is empty: ${document}`);
}

const requiredPhrases = new Map([
  ["docs/installed-windows-lifecycle.md", [
    "RESET GLACIAL APPLICATION DATA",
    "Delete the application data",
    "glacial-pre-migration-v<SOURCE>-to-v2-<UTC timestamp>-<random suffix>.db",
    "glacial-before-reset-<UTC timestamp>-<random suffix>.db",
    "%LOCALAPPDATA%\\com.glacial.desktop",
    "%APPDATA%\\com.glacial.desktop",
  ]],
  ["docs/evidence-and-remediation.md", [
    "Complete",
    "Incomplete",
    "Unknown",
    "Reviewed as expected",
    "Reopen",
    "100 unresolved findings",
    "does not edit project code",
  ]],
  ["docs/supported-environments.md", [
    "Windows 11 Pro x64",
    "10.0.26200",
    "960 × 640",
    "WebView2 Evergreen Runtime",
    "Automatic updater",
    "Downgrade",
    "Windows on ARM",
  ]],
  ["docs/privacy-and-network.md", [
    "authenticated loopback",
    "download bootstrapper",
    "no runtime updater",
    "Review every report",
    "Registered project",
  ]],
  ["docs/support.md", [
    "14 calendar days",
    "security",
    "Modified, copied, relocated",
  ]],
  ["SECURITY.md", [
    "https://github.com/Bolizen/Glacial/security/advisories/new",
    "7 calendar days",
    "30 calendar days",
    "Do not report an undisclosed vulnerability in a public GitHub issue",
  ]],
]);
for (const [document, phrases] of requiredPhrases) {
  const text = read(document);
  for (const phrase of phrases) if (!text.includes(phrase)) fail(`${document} is missing required text: ${phrase}`);
}

const packageJson = JSON.parse(read("frontend/package.json"));
const packageLock = JSON.parse(read("frontend/package-lock.json"));
const tauri = JSON.parse(read("frontend/src-tauri/tauri.conf.json"));
const cargoToml = read("frontend/src-tauri/Cargo.toml");
const cargoLock = read("frontend/src-tauri/Cargo.lock");
const backendVersion = read("backend/app/version.py").trim();
const changelog = read("backend/app/changelog.py");
const releaseNotes = read("RELEASE_NOTES.md");
const readme = read("README.md");
const readiness = JSON.parse(read("docs/release/v1.0-gap-audit.json"));

const versions = [
  ["frontend/package.json", packageJson.version],
  ["frontend/package-lock.json", packageLock.version],
  ["frontend/package-lock.json root", packageLock.packages[""].version],
  ["frontend/src-tauri/tauri.conf.json", tauri.version],
  ["frontend/src-tauri/Cargo.toml", cargoToml.match(/^version = "([^"]+)"/m)?.[1]],
  ["frontend/src-tauri/Cargo.lock", cargoLock.match(/name = "glacial"\r?\nversion = "([^"]+)"/)?.[1]],
  ["backend/app/version.py", backendVersion.match(/^GLACIAL_VERSION = "([^"]+)"$/)?.[1]],
  ["docs/release/v1.0-gap-audit.json", readiness.audited_version],
];
for (const [source, version] of versions) {
  if (version !== expectedVersion) fail(`${source} identifies ${version ?? "no version"}; expected ${expectedVersion}`);
}
for (const [source, text] of [
  ["backend/app/changelog.py", changelog],
  ["RELEASE_NOTES.md", releaseNotes],
  ["README.md", readme],
]) {
  if (!text.includes(expectedVersion)) fail(`${source} does not identify ${expectedVersion}`);
}

if (tauri.bundle?.targets?.length !== 1 || tauri.bundle.targets[0] !== "nsis") fail("Tauri does not declare exactly the NSIS target");
if (tauri.bundle?.windows?.nsis?.installMode !== "currentUser") fail("Tauri NSIS install mode is not currentUser");
if (tauri.bundle?.createUpdaterArtifacts !== false) fail("Tauri updater artifacts are not disabled");
if (tauri.app?.windows?.[0]?.minWidth !== 960 || tauri.app?.windows?.[0]?.minHeight !== 640) fail("documented minimum window differs from Tauri configuration");

try {
  execFileSync(process.execPath, [join(repository, "scripts", "release", "generate-third-party-inventory.mjs"), "--check"], {
    cwd: repository,
    stdio: "inherit",
  });
} catch {
  fail("third-party runtime inventory validation failed");
}

if (!process.exitCode) {
  console.log(`Validated ${requiredDocuments.length} public documents, internal Markdown links, required G051 content, ${versions.length} version sources, Tauri support boundaries, and the locked third-party runtime inventory.`);
}
