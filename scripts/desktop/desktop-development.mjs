import { existsSync, lstatSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DESKTOP_BUILD_ROOT,
  ensureSafeDirectory,
  minimalEnvironment,
  removeSafeTree,
  runCommand,
} from "./windows-signing.mjs";
import { validateDesktopBuildEnvironment } from "./Build-SignedWindowsRelease.mjs";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const REPOSITORY = resolve(dirname(SCRIPT_PATH), "..", "..");
const PYINSTALLER_ROOT = join(DESKTOP_BUILD_ROOT, "pyinstaller");
const BACKEND_PAYLOAD = join(PYINSTALLER_ROOT, "dist", "glacial-backend");

function runVisible(command, args, options = {}) {
  const result = runCommand(command, args, { cwd: options.cwd, env: options.env, timeoutMs: options.timeoutMs ?? 900_000 });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  return result;
}

function requireFile(path, label) {
  if (!existsSync(path) || !lstatSync(path).isFile()) throw new Error(`${label} is missing.`);
  return path;
}

function buildBackend() {
  const python = validateDesktopBuildEnvironment({ validateRuntime: false });
  removeSafeTree(DESKTOP_BUILD_ROOT, PYINSTALLER_ROOT);
  ensureSafeDirectory(DESKTOP_BUILD_ROOT, PYINSTALLER_ROOT);
  const environment = minimalEnvironment(process.env, { PYINSTALLER_CONFIG_DIR: join(PYINSTALLER_ROOT, "cache") });
  runVisible(python, ["-m", "PyInstaller", "--noconfirm", "--clean", "--distpath", join(PYINSTALLER_ROOT, "dist"), "--workpath", join(PYINSTALLER_ROOT, "work"), join(REPOSITORY, "backend", "glacial-backend.spec")], { env: environment });
  requireFile(join(BACKEND_PAYLOAD, "glacial-backend.exe"), "Packaged backend");
  if (!existsSync(join(BACKEND_PAYLOAD, "_internal"))) throw new Error("Packaged backend runtime is missing.");
}

export function developmentPlan(command) {
  if (command === "build-backend") return ["validate unsigned build tools", "build PyInstaller backend"];
  throw new Error("Expected build-backend.");
}

export function runDevelopmentCommand(command, options = {}) {
  const plan = developmentPlan(command);
  if (options.dryRun) return { command, signingRequired: false, certificateRequired: false, plan };
  buildBackend();
  return { command, signingRequired: false, certificateRequired: false, plan };
}

function main() {
  const command = process.argv[2];
  const result = runDevelopmentCommand(command, { dryRun: process.argv.includes("--dry-run") });
  if (process.argv.includes("--dry-run")) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(SCRIPT_PATH)) {
  try { main(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
