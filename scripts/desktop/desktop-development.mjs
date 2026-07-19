import { copyFileSync, cpSync, existsSync, lstatSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DESKTOP_BUILD_ROOT,
  ensureSafeDirectory,
  minimalEnvironment,
  removeSafeTree,
  resolveNpmInvocation,
  resolveToolExecutable,
  runCommand,
} from "./windows-signing.mjs";
import { validateDesktopBuildEnvironment } from "./Build-SignedWindowsRelease.mjs";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const REPOSITORY = resolve(dirname(SCRIPT_PATH), "..", "..");
const FRONTEND = join(REPOSITORY, "frontend");
const PYINSTALLER_ROOT = join(DESKTOP_BUILD_ROOT, "pyinstaller");
const BACKEND_PAYLOAD = join(PYINSTALLER_ROOT, "dist", "glacial-backend");
const SIDECAR_STAGE = join(FRONTEND, "src-tauri", "binaries");
const APPLICATION = join(FRONTEND, "src-tauri", "target", "release", "glacial.exe");
const PORTABLE_ROOT = join(DESKTOP_BUILD_ROOT, "portable", "Glacial");

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

function stageBackend(rustc) {
  const triple = String(runCommand(rustc, ["--print", "host-tuple"], { env: minimalEnvironment(process.env) }).stdout ?? "").trim();
  if (triple !== "x86_64-pc-windows-msvc") throw new Error(`Expected x86_64-pc-windows-msvc; found ${triple}.`);
  removeSafeTree(REPOSITORY, SIDECAR_STAGE);
  ensureSafeDirectory(REPOSITORY, SIDECAR_STAGE);
  copyFileSync(join(BACKEND_PAYLOAD, "glacial-backend.exe"), join(SIDECAR_STAGE, `glacial-backend-${triple}.exe`));
  cpSync(join(BACKEND_PAYLOAD, "_internal"), join(SIDECAR_STAGE, "_internal"), { recursive: true, errorOnExist: true });
}

function assemblePortable() {
  requireFile(APPLICATION, "Unsigned Tauri release executable");
  requireFile(join(SIDECAR_STAGE, "glacial-backend-x86_64-pc-windows-msvc.exe"), "Staged backend");
  removeSafeTree(DESKTOP_BUILD_ROOT, PORTABLE_ROOT);
  ensureSafeDirectory(DESKTOP_BUILD_ROOT, PORTABLE_ROOT);
  copyFileSync(APPLICATION, join(PORTABLE_ROOT, "Glacial.exe"));
  copyFileSync(join(SIDECAR_STAGE, "glacial-backend-x86_64-pc-windows-msvc.exe"), join(PORTABLE_ROOT, "glacial-backend.exe"));
  cpSync(join(SIDECAR_STAGE, "_internal"), join(PORTABLE_ROOT, "_internal"), { recursive: true, errorOnExist: true });
  process.stdout.write(`${PORTABLE_ROOT}\n`);
}

export function developmentPlan(command) {
  if (command === "build-backend") return ["validate unsigned build tools", "build PyInstaller backend"];
  if (command === "build-portable") return ["build PyInstaller backend", "stage unsigned sidecar", "build frontend", "build unsigned Tauri executable", "assemble portable directory"];
  throw new Error("Expected build-backend or build-portable.");
}

export function runDevelopmentCommand(command, options = {}) {
  const plan = developmentPlan(command);
  if (options.dryRun) return { command, signingRequired: false, certificateRequired: false, plan };
  buildBackend();
  if (command === "build-portable") {
    const rustc = resolveToolExecutable("rustc.exe", process.env, { forbiddenRoot: REPOSITORY });
    const npm = resolveNpmInvocation(process.env, { forbiddenRoot: REPOSITORY });
    stageBackend(rustc);
    const environment = minimalEnvironment(process.env);
    runVisible(npm.command, [...npm.prefixArgs, "run", "build"], { cwd: FRONTEND, env: environment });
    runVisible(npm.command, [...npm.prefixArgs, "run", "tauri:build", "--", "--no-bundle"], { cwd: FRONTEND, env: environment });
    assemblePortable();
  }
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
