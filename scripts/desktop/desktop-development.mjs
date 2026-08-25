import { existsSync, lstatSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DESKTOP_BUILD_ROOT,
  ensureSafeDirectory,
  minimalEnvironment,
  removeSafeTree,
  resolveToolExecutable,
  runCommand,
  sanitizeDiagnosticText,
} from "./windows-signing.mjs";
import { validateDesktopBuildEnvironment } from "./Build-SignedWindowsRelease.mjs";
import { writeBackendStageReceipt } from "./backend-stage-integrity.mjs";
import { currentProductVersion } from "../release/release-contract.mjs";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const REPOSITORY = resolve(dirname(SCRIPT_PATH), "..", "..");
const PYINSTALLER_ROOT = join(DESKTOP_BUILD_ROOT, "pyinstaller");
const BACKEND_PAYLOAD = join(PYINSTALLER_ROOT, "dist", "glacial-backend");

function runVisible(command, args, options = {}) {
  const result = runCommand(command, args, { cwd: options.cwd, env: options.env, timeoutMs: options.timeoutMs ?? 900_000 });
  if (result.stdout) process.stdout.write(sanitizeDiagnosticText(result.stdout));
  if (result.stderr) process.stderr.write(sanitizeDiagnosticText(result.stderr));
  return result;
}

function requireFile(path, label) {
  if (!existsSync(path) || !lstatSync(path).isFile()) throw new Error(`${label} is missing.`);
  return path;
}

function currentCleanSourceCommit() {
  const environment = minimalEnvironment(process.env);
  const git = resolveToolExecutable("git.exe", process.env, { forbiddenRoot: REPOSITORY });
  const status = String(runCommand(git, ["status", "--short"], {
    cwd: REPOSITORY,
    env: environment,
  }).stdout ?? "").trim();
  if (status) throw new Error("Backend evidence construction requires a clean source tree.");
  const commit = String(runCommand(git, ["rev-parse", "HEAD"], {
    cwd: REPOSITORY,
    env: environment,
  }).stdout ?? "").trim();
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error("The backend source commit is unavailable.");
  return commit;
}

function buildBackend() {
  const sourceCommit = currentCleanSourceCommit();
  const python = validateDesktopBuildEnvironment({ validateRuntime: false });
  removeSafeTree(DESKTOP_BUILD_ROOT, PYINSTALLER_ROOT);
  ensureSafeDirectory(DESKTOP_BUILD_ROOT, PYINSTALLER_ROOT);
  const environment = minimalEnvironment(process.env, { PYINSTALLER_CONFIG_DIR: join(PYINSTALLER_ROOT, "cache") });
  runVisible(python, ["-m", "PyInstaller", "--noconfirm", "--clean", "--distpath", join(PYINSTALLER_ROOT, "dist"), "--workpath", join(PYINSTALLER_ROOT, "work"), join(REPOSITORY, "backend", "glacial-backend.spec")], { env: environment });
  requireFile(join(BACKEND_PAYLOAD, "glacial-backend.exe"), "Packaged backend");
  if (!existsSync(join(BACKEND_PAYLOAD, "_internal"))) throw new Error("Packaged backend runtime is missing.");
  writeBackendStageReceipt({
    root: BACKEND_PAYLOAD,
    executableName: "glacial-backend.exe",
    sourceCommit,
    productVersion: currentProductVersion(REPOSITORY),
  });
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
  try { main(); } catch (error) { process.stderr.write(`${sanitizeDiagnosticText(error.message)}\n`); process.exitCode = 1; }
}
