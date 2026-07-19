import {
  appendFileSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const DEFAULT_SIGNER_SUBJECT = "CN=Icefields Development";
export const SIGNING_SCRIPT_PATH = fileURLToPath(import.meta.url);
export const REPOSITORY_ROOT = resolve(dirname(SIGNING_SCRIPT_PATH), "..", "..");
export const DESKTOP_BUILD_ROOT = resolve(REPOSITORY_ROOT, ".desktop-build");

const BASE_ENVIRONMENT_NAMES = [
  "APPDATA",
  "COMSPEC",
  "HOMEDRIVE",
  "HOMEPATH",
  "LOCALAPPDATA",
  "NUMBER_OF_PROCESSORS",
  "OS",
  "PATH",
  "PATHEXT",
  "PROCESSOR_ARCHITECTURE",
  "PROGRAMDATA",
  "SYSTEMDRIVE",
  "SYSTEMROOT",
  "TEMP",
  "TMP",
  "USERPROFILE",
  "WINDIR",
];

const INTERNAL_ENVIRONMENT_NAMES = [
  "GLACIAL_WINDOWS_CERTIFICATE_THUMBPRINT",
  "GLACIAL_WINDOWS_EXPECTED_SUBJECT",
  "GLACIAL_WINDOWS_EXPECTED_THUMBPRINT",
  "GLACIAL_WINDOWS_RELEASE_ID",
  "GLACIAL_WINDOWS_REQUIRE_TIMESTAMP",
  "GLACIAL_WINDOWS_SIGNING_PROVIDER",
  "GLACIAL_WINDOWS_SIGNTOOL_PATH",
  "GLACIAL_WINDOWS_SIGN_COMMAND",
  "GLACIAL_WINDOWS_SIGN_COMMAND_ARGS",
  "GLACIAL_WINDOWS_SIGN_COMMAND_ENV",
  "GLACIAL_WINDOWS_TIMESTAMP_URL",
];

// This is the only PowerShell command text used by the signing pipeline. Dynamic
// values are JSON in GLACIAL_WINDOWS_HELPER_PAYLOAD and never enter command text.
export const WINDOWS_SIGNING_POWERSHELL_HELPER_COMMAND = [
  "$ErrorActionPreference = 'Stop'",
  "$payload = $env:GLACIAL_WINDOWS_HELPER_PAYLOAD | ConvertFrom-Json",
  "function Canonical-Dn([System.Security.Cryptography.X509Certificates.X500DistinguishedName] $Name) {",
  "  $flags = [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseCommas -bor [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::Reversed -bor [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::DoNotUseQuotes -bor [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::DoNotUsePlusSign -bor [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseUTF8Encoding",
  "  return $Name.Decode($flags).Trim().ToUpperInvariant()",
  "}",
  "function Thumb([string] $Value) { return ($Value -replace '\\s', '').ToUpperInvariant() }",
  "function Trust-Info([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate) {",
  "  $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()",
  "  $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck",
  "  $valid = $chain.Build($Certificate)",
  "  $statuses = @($chain.ChainStatus | ForEach-Object { $_.Status.ToString() })",
  "  $selfSigned = [Convert]::ToBase64String($Certificate.SubjectName.RawData) -eq [Convert]::ToBase64String($Certificate.IssuerName.RawData)",
  "  $classification = 'invalid'",
  "  if ($valid -and $selfSigned) { $classification = 'self-signed' }",
  "  elseif ($valid -and $chain.ChainElements.Count -gt 1) {",
  "    $rootThumbprint = Thumb $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Thumbprint",
  "    $authRoots = @()",
  "    foreach ($storePath in @('Cert:\\CurrentUser\\AuthRoot', 'Cert:\\LocalMachine\\AuthRoot')) {",
  "      if (Test-Path -LiteralPath $storePath) { $authRoots += @(Get-ChildItem -LiteralPath $storePath | Where-Object { (Thumb $_.Thumbprint) -eq $rootThumbprint }) }",
  "    }",
  "    if ($authRoots.Count -gt 0) { $classification = 'publicly-trusted' } else { $classification = 'private-trusted' }",
  "  }",
  "  return [pscustomobject]@{ Valid = $valid; Classification = $classification; Statuses = $statuses }",
  "}",
  "switch ([string]$env:GLACIAL_WINDOWS_HELPER_OPERATION) {",
  "  'canonical-subject' {",
  "    $name = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new([string]$payload.subject)",
  "    [pscustomobject]@{ CanonicalSubject = Canonical-Dn $name } | ConvertTo-Json -Compress",
  "  }",
  "  'certificate' {",
  "    $wanted = Thumb ([string]$payload.thumbprint)",
  "    $expectedName = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new([string]$payload.expectedSubject)",
  "    $expectedCanonical = Canonical-Dn $expectedName",
  "    $matches = @(Get-ChildItem -LiteralPath 'Cert:\\CurrentUser\\My' | Where-Object { (Thumb $_.Thumbprint) -eq $wanted -or (Canonical-Dn $_.SubjectName) -eq $expectedCanonical })",
  "    $candidates = @($matches | ForEach-Object {",
  "      $trust = Trust-Info $_",
  "      [pscustomobject]@{ Thumbprint = Thumb $_.Thumbprint; CanonicalSubject = Canonical-Dn $_.SubjectName; HasPrivateKey = $_.HasPrivateKey; TrustValid = $trust.Valid; TrustClassification = $trust.Classification; ChainStatuses = $trust.Statuses }",
  "    })",
  "    [pscustomobject]@{ Candidates = $candidates } | ConvertTo-Json -Compress -Depth 5",
  "  }",
  "  'signature' {",
  "    $signature = Get-AuthenticodeSignature -LiteralPath ([string]$payload.path)",
  "    $trust = if ($signature.SignerCertificate) { Trust-Info $signature.SignerCertificate } else { $null }",
  "    [pscustomobject]@{ Status = $signature.Status.ToString(); StatusMessage = $signature.StatusMessage; SignerThumbprint = if ($signature.SignerCertificate) { Thumb $signature.SignerCertificate.Thumbprint } else { $null }; CanonicalSubject = if ($signature.SignerCertificate) { Canonical-Dn $signature.SignerCertificate.SubjectName } else { $null }; TimestampThumbprint = if ($signature.TimeStamperCertificate) { Thumb $signature.TimeStamperCertificate.Thumbprint } else { $null }; TrustValid = if ($trust) { $trust.Valid } else { $false }; TrustClassification = if ($trust) { $trust.Classification } else { 'invalid' }; ChainStatuses = if ($trust) { $trust.Statuses } else { @() } } | ConvertTo-Json -Compress -Depth 5",
  "  }",
  "  'path-info' {",
  "    $items = @($payload.paths | ForEach-Object {",
  "      $path = [System.IO.Path]::GetFullPath([string]$_)",
  "      if (Test-Path -LiteralPath $path) { $item = Get-Item -LiteralPath $path -Force; [pscustomobject]@{ Path = $path; Exists = $true; ReparsePoint = (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0); Attributes = $item.Attributes.ToString() } }",
  "      else { [pscustomobject]@{ Path = $path; Exists = $false; ReparsePoint = $false; Attributes = '' } }",
  "    })",
  "    [pscustomobject]@{ Items = $items } | ConvertTo-Json -Compress -Depth 4",
  "  }",
  "  'tree-reparse-check' {",
  "    $root = [System.IO.DirectoryInfo]::new([System.IO.Path]::GetFullPath([string]$payload.root))",
  "    if (($root.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Tree root is a reparse point.' }",
  "    $stack = [System.Collections.Generic.Stack[System.IO.DirectoryInfo]]::new()",
  "    $stack.Push($root)",
  "    while ($stack.Count -gt 0) {",
  "      $directory = $stack.Pop()",
  "      foreach ($item in $directory.EnumerateFileSystemInfos()) {",
  "        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Tree contains a reparse point.' }",
  "        if (($item.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) { $stack.Push([System.IO.DirectoryInfo]$item) }",
  "      }",
  "    }",
  "    [pscustomobject]@{ Safe = $true } | ConvertTo-Json -Compress",
  "  }",
  "  default { throw 'Unknown signing-helper operation.' }",
  "}",
].join("\n");

function getEnvironmentValue(source, name) {
  const key = Object.keys(source).find((candidate) => candidate.toUpperCase() === name.toUpperCase());
  return key ? source[key] : undefined;
}

export function minimalEnvironment(source = process.env, extras = {}, allowedNames = []) {
  const result = {};
  for (const name of [...BASE_ENVIRONMENT_NAMES, ...allowedNames]) {
    const value = getEnvironmentValue(source, name);
    if (value !== undefined) result[name] = value;
  }
  for (const [name, value] of Object.entries(extras)) {
    if (value !== undefined && value !== null) result[name] = String(value);
  }
  return result;
}

function commandFailure(command, result) {
  const reason = result.signal ? `signal ${result.signal}` : `status ${result.status ?? "unknown"}`;
  return new Error(`${basename(command)} failed with ${reason}; child output was suppressed.`);
}

export function runCommand(command, args, options = {}) {
  if (!isAbsolute(command)) throw new Error(`Refusing to launch a non-absolute executable: ${command}`);
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env,
    encoding: "utf8",
    maxBuffer: options.maxBuffer ?? 64 * 1024 * 1024,
    timeout: options.timeoutMs ?? 120_000,
    windowsHide: false,
    shell: false,
  });
  if (result.error) throw new Error(`${basename(command)} could not be started: ${result.error.code ?? "unknown error"}.`);
  if (result.status !== 0) throw commandFailure(command, result);
  return result;
}

export function normalizeThumbprint(value, name = "certificate thumbprint") {
  const normalized = String(value ?? "").replaceAll(/\s/g, "").toUpperCase();
  if (!/^[0-9A-F]{40}$/.test(normalized)) throw new Error(`${name} must be a 40-character SHA-1 certificate thumbprint.`);
  return normalized;
}

function parseTimestampUrl(value) {
  if (!value) throw new Error("GLACIAL_WINDOWS_TIMESTAMP_URL is required for signed releases.");
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error("GLACIAL_WINDOWS_TIMESTAMP_URL is invalid."); }
  if (parsed.protocol !== "https:") throw new Error("GLACIAL_WINDOWS_TIMESTAMP_URL must use HTTPS.");
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("GLACIAL_WINDOWS_TIMESTAMP_URL must not contain credentials, a query string, or a fragment.");
  }
  return parsed.toString();
}

function parseCommandArguments(value) {
  let args;
  try { args = JSON.parse(value ?? ""); } catch { throw new Error("GLACIAL_WINDOWS_SIGN_COMMAND_ARGS must be a JSON array of strings."); }
  if (!Array.isArray(args) || args.some((argument) => typeof argument !== "string")) {
    throw new Error("GLACIAL_WINDOWS_SIGN_COMMAND_ARGS must be a JSON array of strings.");
  }
  for (const argument of args) {
    if (/[\u0000-\u001F\u007F]/.test(argument)) throw new Error("Signing command arguments must not contain control characters.");
    if (/(password|passwd|secret|token|credential|private[-_ ]?key)/i.test(argument)) {
      throw new Error("Signing command arguments must not contain secret-bearing values or switches; pass credentials only through an explicitly allowlisted environment variable.");
    }
    if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(argument)) {
      let url;
      try { url = new URL(argument); } catch { throw new Error("Signing command arguments contain an invalid URL."); }
      if (url.username || url.password || url.search || url.hash) throw new Error("Signing command URL arguments must not contain credentials, a query string, or a fragment.");
    }
  }
  const placeholders = args.reduce((count, argument) => count + (argument.match(/\{file\}/g)?.length ?? 0), 0);
  if (placeholders !== 1) throw new Error("GLACIAL_WINDOWS_SIGN_COMMAND_ARGS must contain exactly one {file} placeholder.");
  return args;
}

function parseEnvironmentNames(value) {
  if (!value) return [];
  let names;
  try { names = JSON.parse(value); } catch { throw new Error("GLACIAL_WINDOWS_SIGN_COMMAND_ENV must be a JSON array of environment-variable names."); }
  if (!Array.isArray(names) || names.some((name) => typeof name !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name))) {
    throw new Error("GLACIAL_WINDOWS_SIGN_COMMAND_ENV must be a JSON array of environment-variable names.");
  }
  const upper = names.map((name) => name.toUpperCase());
  if (new Set(upper).size !== upper.length) throw new Error("GLACIAL_WINDOWS_SIGN_COMMAND_ENV contains duplicate names.");
  return names;
}

function requireAbsoluteFile(path, name, dryRun) {
  const value = String(path ?? "").trim();
  if (!isAbsolute(value)) throw new Error(`${name} must be an absolute path.`);
  if (!dryRun && (!existsSync(value) || !lstatSync(value).isFile())) throw new Error(`${name} was not found.`);
  return resolve(value);
}

function validateReleaseId(value) {
  if (!value) return null;
  if (!/^Glacial-0\.4\.0-[0-9a-f]{12}-[0-9]{8}T[0-9]{6}Z$/i.test(value)) throw new Error("Invalid internal release id.");
  return value;
}

export function loadSigningConfig(env = process.env, options = {}) {
  const dryRun = options.dryRun === true;
  const provider = String(env.GLACIAL_WINDOWS_SIGNING_PROVIDER ?? "").toLowerCase();
  if (provider !== "store" && provider !== "command") throw new Error("GLACIAL_WINDOWS_SIGNING_PROVIDER must be store or command.");
  if (!/^(1|true)$/i.test(String(env.GLACIAL_WINDOWS_REQUIRE_TIMESTAMP ?? ""))) {
    throw new Error("GLACIAL_WINDOWS_REQUIRE_TIMESTAMP must be 1 for signed releases.");
  }
  const expectedSubject = String(env.GLACIAL_WINDOWS_EXPECTED_SUBJECT ?? DEFAULT_SIGNER_SUBJECT).trim();
  if (!expectedSubject) throw new Error("GLACIAL_WINDOWS_EXPECTED_SUBJECT must not be empty.");
  const signToolPath = requireAbsoluteFile(env.GLACIAL_WINDOWS_SIGNTOOL_PATH, "GLACIAL_WINDOWS_SIGNTOOL_PATH", dryRun);
  const timestampUrl = parseTimestampUrl(env.GLACIAL_WINDOWS_TIMESTAMP_URL);
  const releaseId = validateReleaseId(env.GLACIAL_WINDOWS_RELEASE_ID);
  const auditLog = releaseId ? resolve(DESKTOP_BUILD_ROOT, "signing", releaseId, "signing-events.jsonl") : null;

  if (provider === "store") {
    const thumbprint = normalizeThumbprint(env.GLACIAL_WINDOWS_CERTIFICATE_THUMBPRINT);
    return { provider, expectedSubject, expectedThumbprint: thumbprint, certificateThumbprint: thumbprint, signToolPath, timestampUrl, requireTimestamp: true, releaseId, auditLog };
  }
  const command = requireAbsoluteFile(env.GLACIAL_WINDOWS_SIGN_COMMAND, "GLACIAL_WINDOWS_SIGN_COMMAND", dryRun);
  const providerEnvironmentNames = parseEnvironmentNames(env.GLACIAL_WINDOWS_SIGN_COMMAND_ENV);
  const providerEnvironment = minimalEnvironment(env, {}, providerEnvironmentNames);
  return {
    provider,
    expectedSubject,
    expectedThumbprint: normalizeThumbprint(env.GLACIAL_WINDOWS_EXPECTED_THUMBPRINT, "GLACIAL_WINDOWS_EXPECTED_THUMBPRINT"),
    signToolPath,
    timestampUrl,
    requireTimestamp: true,
    command,
    commandArgs: parseCommandArguments(env.GLACIAL_WINDOWS_SIGN_COMMAND_ARGS),
    providerEnvironmentNames,
    providerEnvironment,
    releaseId,
    auditLog,
  };
}

function systemExecutable(relativePath, env = process.env) {
  const systemRoot = getEnvironmentValue(env, "SYSTEMROOT") ?? getEnvironmentValue(env, "WINDIR");
  if (!systemRoot || !isAbsolute(systemRoot)) throw new Error("SYSTEMROOT is unavailable.");
  const executable = resolve(systemRoot, relativePath);
  if (!existsSync(executable) || !lstatSync(executable).isFile()) throw new Error(`Required Windows executable is missing: ${relativePath}`);
  return executable;
}

export function resolveSystemExecutable(relativePath, env = process.env) {
  return systemExecutable(relativePath, env);
}

export function resolveToolExecutable(name, env = process.env, options = {}) {
  if (!/^[A-Za-z0-9_.-]+$/.test(name)) throw new Error("Invalid executable name.");
  const where = systemExecutable("System32/where.exe", env);
  const result = runCommand(where, [name], { env: minimalEnvironment(env), timeoutMs: 15_000 });
  const matches = String(result.stdout ?? "")
    .split(/\r?\n/)
    .map((value) => value.trim())
    .filter(Boolean)
    .map((value) => resolve(value))
    .filter((value, index, values) => values.findIndex((candidate) => candidate.toLowerCase() === value.toLowerCase()) === index)
    .filter((value) => existsSync(value) && lstatSync(value).isFile());
  if (!matches.length) throw new Error(`Could not resolve ${name} to an absolute executable.`);
  const selected = matches[0];
  const forbiddenRoot = options.forbiddenRoot ? resolve(options.forbiddenRoot) : null;
  if (forbiddenRoot) {
    const rel = relative(forbiddenRoot, selected);
    if (!rel || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel))) {
      throw new Error(`Refusing repository-local executable resolution for ${name}.`);
    }
  }
  if (lstatSync(selected).isSymbolicLink()) throw new Error(`Refusing a symbolic-link executable for ${name}.`);
  return selected;
}

export function resolveNpmInvocation(env = process.env, options = {}) {
  const command = resolveToolExecutable("node.exe", env, options);
  const npmLauncher = resolveToolExecutable("npm.cmd", env, options);
  const npmCli = resolve(dirname(npmLauncher), "node_modules", "npm", "bin", "npm-cli.js");
  if (!existsSync(npmCli) || !lstatSync(npmCli).isFile() || lstatSync(npmCli).isSymbolicLink()) {
    throw new Error("Could not resolve npm to a direct JavaScript CLI entrypoint.");
  }
  const forbiddenRoot = options.forbiddenRoot ? resolve(options.forbiddenRoot) : null;
  if (forbiddenRoot) {
    const rel = relative(forbiddenRoot, npmCli);
    if (!rel || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel))) {
      throw new Error("Refusing a repository-local npm CLI entrypoint.");
    }
  }
  return { command, prefixArgs: [npmCli] };
}

export function createPowerShellInvocation(operation, payload, env = process.env) {
  return {
    command: systemExecutable("System32/WindowsPowerShell/v1.0/powershell.exe", env),
    args: ["-NoProfile", "-NonInteractive", "-Command", WINDOWS_SIGNING_POWERSHELL_HELPER_COMMAND],
    env: minimalEnvironment(env, {
      GLACIAL_WINDOWS_HELPER_OPERATION: operation,
      GLACIAL_WINDOWS_HELPER_PAYLOAD: JSON.stringify(payload),
    }),
  };
}

function invokeWindowsHelper(operation, payload, runner = runCommand, env = process.env) {
  const invocation = createPowerShellInvocation(operation, payload, env);
  const result = runner(invocation.command, invocation.args, { env: invocation.env, timeoutMs: 30_000 });
  const output = String(result.stdout ?? "").trim();
  if (!output) throw new Error(`Windows signing helper returned no ${operation} result.`);
  try { return JSON.parse(output); } catch { throw new Error(`Windows signing helper returned malformed ${operation} data.`); }
}

export function canonicalizeDistinguishedName(subject, runner = runCommand, env = process.env) {
  const result = invokeWindowsHelper("canonical-subject", { subject }, runner, env);
  const canonical = String(result.CanonicalSubject ?? "").trim().toUpperCase();
  if (!canonical) throw new Error("Could not canonicalize the expected certificate subject.");
  return canonical;
}

export function assertCertificateIdentity(candidates, config, expectedCanonicalSubject) {
  if (!Array.isArray(candidates) || candidates.length !== 1) {
    throw new Error(`Expected exactly one CurrentUser certificate candidate; found ${Array.isArray(candidates) ? candidates.length : 0}.`);
  }
  const certificate = candidates[0];
  if (normalizeThumbprint(certificate.Thumbprint) !== config.expectedThumbprint) throw new Error("The selected certificate thumbprint is unexpected.");
  if (String(certificate.CanonicalSubject ?? "").toUpperCase() !== expectedCanonicalSubject) throw new Error("The selected certificate subject is not an exact canonical match.");
  if (certificate.HasPrivateKey !== true) throw new Error("The selected certificate has no associated private key.");
  if (certificate.TrustValid !== true || !["self-signed", "publicly-trusted"].includes(certificate.TrustClassification)) {
    throw new Error("The selected certificate chain is invalid, private, or ambiguous.");
  }
  return certificate;
}

function pathComponents(root, target) {
  const resolvedRoot = resolve(root);
  const resolvedTarget = resolve(target);
  const rel = relative(resolvedRoot, resolvedTarget);
  if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error(`Refusing a path outside ${resolvedRoot}: ${resolvedTarget}`);
  const ancestors = [];
  let ancestor = resolvedRoot;
  while (true) {
    ancestors.unshift(ancestor);
    const parent = dirname(ancestor);
    if (parent === ancestor) break;
    ancestor = parent;
  }
  const components = [...ancestors];
  let current = resolvedRoot;
  for (const part of rel.split(/[\\/]+/)) { current = resolve(current, part); components.push(current); }
  return { resolvedRoot, resolvedTarget, components };
}

export function assertSafePath(root, target, options = {}) {
  const { resolvedRoot, resolvedTarget, components } = pathComponents(root, target);
  const existing = components.filter((path) => existsSync(path));
  for (const path of existing) if (lstatSync(path).isSymbolicLink()) throw new Error(`Refusing a symbolic link or junction in an output path: ${path}`);
  if (process.platform === "win32" && options.pathInspector !== false && existing.length) {
    const inspector = options.pathInspector ?? ((paths) => invokeWindowsHelper("path-info", { paths }, options.runner, options.env));
    const result = inspector(existing);
    for (const item of result.Items ?? []) if (item.ReparsePoint) throw new Error(`Refusing a reparse point in an output path: ${item.Path}`);
  }
  if (existsSync(resolvedRoot)) {
    const canonicalRoot = realpathSync.native(resolvedRoot);
    for (const path of existing.filter((candidate) => candidate.toLowerCase() === resolvedRoot.toLowerCase() || candidate.toLowerCase().startsWith(`${resolvedRoot.toLowerCase()}${sep}`))) {
      const canonical = realpathSync.native(path);
      const rel = relative(canonicalRoot, canonical);
      if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error(`Canonical output path escapes its root: ${path}`);
    }
  }
  return resolvedTarget;
}

function assertTreeHasNoLinks(root, options = {}) {
  if (!existsSync(root)) return;
  if (process.platform === "win32" && options.pathInspector !== false) {
    const inspector = options.treeInspector ?? ((path) => invokeWindowsHelper("tree-reparse-check", { root: path }, options.runner, options.env));
    const result = inspector(root);
    if (result.Safe !== true) throw new Error(`Refusing to recursively operate on an unsafe tree: ${root}`);
  }
  const stats = lstatSync(root);
  if (stats.isSymbolicLink()) throw new Error(`Refusing to traverse a symbolic link or junction: ${root}`);
  if (!stats.isDirectory()) return;
  for (const entry of readdirSync(root)) assertTreeHasNoLinks(resolve(root, entry), { ...options, pathInspector: false });
}

export function assertSafeTree(root, options = {}) {
  assertTreeHasNoLinks(resolve(root), options);
  return resolve(root);
}

export function removeSafeTree(root, target, options = {}) {
  const resolved = assertSafePath(root, target, options);
  if (!existsSync(resolved)) return;
  assertTreeHasNoLinks(resolved, options);
  rmSync(resolved, { recursive: true, force: true });
}

export function ensureSafeDirectory(root, target, options = {}) {
  const resolved = assertSafePath(root, target, options);
  mkdirSync(resolved, { recursive: true });
  assertSafePath(root, resolved, options);
  return resolved;
}

export function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex").toUpperCase();
}

export function buildStoreSignArgs(config, file) {
  return ["sign", "/fd", "SHA256", "/sha1", config.certificateThumbprint, "/d", "Glacial", "/tr", config.timestampUrl, "/td", "SHA256", resolve(file)];
}

export function buildCommandSignArgs(config, file) {
  const target = resolve(file);
  return config.commandArgs.map((argument) => argument.replaceAll("{file}", target));
}

export function createTauriSigningOverlay(nodePath = process.execPath, scriptPath = SIGNING_SCRIPT_PATH) {
  return { bundle: { windows: { digestAlgorithm: "sha256", signCommand: { cmd: resolve(nodePath), args: [resolve(scriptPath), "sign-one", "%1"] } } } };
}

export function isPortableExecutable(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 0x40 || buffer[0] !== 0x4d || buffer[1] !== 0x5a) return false;
  const peOffset = buffer.readUInt32LE(0x3c);
  return peOffset + 24 <= buffer.length && buffer.subarray(peOffset, peOffset + 4).equals(Buffer.from([0x50, 0x45, 0, 0]));
}

export function hasEmbeddedAuthenticode(buffer) {
  if (!isPortableExecutable(buffer)) return false;
  const peOffset = buffer.readUInt32LE(0x3c);
  const optionalHeader = peOffset + 24;
  if (optionalHeader + 2 > buffer.length) return false;
  const magic = buffer.readUInt16LE(optionalHeader);
  const dataDirectory = optionalHeader + (magic === 0x20b ? 112 : magic === 0x10b ? 96 : -1);
  const securityDirectory = dataDirectory + 32;
  return dataDirectory >= optionalHeader && securityDirectory + 8 <= buffer.length && buffer.readUInt32LE(securityDirectory) !== 0 && buffer.readUInt32LE(securityDirectory + 4) !== 0;
}

function walkFiles(current, output = []) {
  const rootStats = lstatSync(current);
  if (rootStats.isSymbolicLink()) throw new Error(`Release payloads must not contain symbolic links or junctions: ${current}`);
  for (const entry of readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const path = resolve(current, entry.name);
    const stats = lstatSync(path);
    if (stats.isSymbolicLink()) throw new Error(`Release payloads must not contain symbolic links or junctions: ${path}`);
    if (entry.isDirectory()) walkFiles(path, output); else if (entry.isFile()) output.push(path);
  }
  return output;
}

export function listPortableExecutables(root) {
  const resolvedRoot = assertSafeTree(root);
  return walkFiles(resolvedRoot).filter((path) => isPortableExecutable(readFileSync(path)));
}

export function inspectAuthenticode(file, runner = runCommand, env = process.env) {
  const value = invokeWindowsHelper("signature", { path: resolve(file) }, runner, env);
  return {
    status: value.Status,
    statusMessage: value.StatusMessage,
    signerThumbprint: value.SignerThumbprint ? normalizeThumbprint(value.SignerThumbprint, "signer thumbprint") : null,
    canonicalSubject: value.CanonicalSubject ?? null,
    timestampThumbprint: value.TimestampThumbprint ? normalizeThumbprint(value.TimestampThumbprint, "timestamp thumbprint") : null,
    trustValid: value.TrustValid === true,
    trustClassification: value.TrustClassification,
    chainStatuses: value.ChainStatuses ?? [],
  };
}

function verifyWithSignTool(file, config, runner = runCommand) {
  runner(config.signToolPath, ["verify", "/pa", "/all", "/tw", resolve(file)], { env: minimalEnvironment(process.env) });
}

export function verifySignature(file, config, options = {}) {
  const runner = options.runner ?? runCommand;
  const signature = options.signature ?? inspectAuthenticode(file, runner, options.env);
  if (signature.status !== "Valid") throw new Error(`Authenticode verification failed for ${basename(file)}.`);
  verifyWithSignTool(file, config, runner);
  if (options.expectFirstParty) {
    const expectedCanonical = options.expectedCanonicalSubject ?? canonicalizeDistinguishedName(config.expectedSubject, runner, options.env);
    if (signature.signerThumbprint !== config.expectedThumbprint) throw new Error(`The signer thumbprint for ${basename(file)} is unexpected.`);
    if (String(signature.canonicalSubject ?? "").toUpperCase() !== expectedCanonical) throw new Error(`The signer subject for ${basename(file)} is not an exact canonical match.`);
    if (!signature.timestampThumbprint) throw new Error(`The first-party signature for ${basename(file)} is not timestamped.`);
    if (!signature.trustValid || !["self-signed", "publicly-trusted"].includes(signature.trustClassification)) throw new Error(`The signer chain for ${basename(file)} is invalid, private, or ambiguous.`);
  }
  return signature;
}

function appendAuditRecord(config, record) {
  if (!config.auditLog) return;
  const audit = assertSafePath(DESKTOP_BUILD_ROOT, config.auditLog);
  ensureSafeDirectory(DESKTOP_BUILD_ROOT, dirname(audit));
  appendFileSync(audit, `${JSON.stringify(record)}\n`, { encoding: "utf8" });
}

export function signOne(file, config, options = {}) {
  const target = resolve(file);
  if (!isPortableExecutable(readFileSync(target))) throw new Error(`Refusing to Authenticode-sign a non-PE file: ${basename(target)}`);
  const runner = options.runner ?? runCommand;
  if (config.provider === "store") {
    runner(config.signToolPath, buildStoreSignArgs(config, target), { env: minimalEnvironment(process.env), timeoutMs: 120_000 });
  } else {
    runner(config.command, buildCommandSignArgs(config, target), { env: config.providerEnvironment, timeoutMs: 120_000 });
  }
  const signature = verifySignature(target, config, { expectFirstParty: true, runner, env: options.env });
  appendAuditRecord(config, { path: target, sha256: sha256(target), signerThumbprint: signature.signerThumbprint, canonicalSubject: signature.canonicalSubject, timestampThumbprint: signature.timestampThumbprint, trustClassification: signature.trustClassification, signedUtc: new Date().toISOString() });
  return signature;
}

export function preflightSigningProvider(config, options = {}) {
  const runner = options.runner ?? runCommand;
  const expectedCanonical = canonicalizeDistinguishedName(config.expectedSubject, runner, options.env);
  let storeCertificate = null;
  if (config.provider === "store") {
    const result = invokeWindowsHelper("certificate", { thumbprint: config.certificateThumbprint, expectedSubject: config.expectedSubject }, runner, options.env);
    storeCertificate = assertCertificateIdentity(result.Candidates, config, expectedCanonical);
  }
  const probeParent = options.probeParent ?? resolve(DESKTOP_BUILD_ROOT, "signing-preflight");
  ensureSafeDirectory(DESKTOP_BUILD_ROOT, probeParent, options);
  const probeRoot = resolve(probeParent, `probe-${process.pid}-${Date.now()}`);
  ensureSafeDirectory(DESKTOP_BUILD_ROOT, probeRoot, options);
  const probe = resolve(probeRoot, "Glacial-signing-probe.exe");
  try {
    const source = options.probeSource ?? systemExecutable("System32/where.exe", options.env ?? process.env);
    copyFileSync(source, probe);
    const signature = signOne(probe, { ...config, auditLog: null }, { runner, env: options.env });
    if (signature.canonicalSubject.toUpperCase() !== expectedCanonical) throw new Error("The private-key probe used an unexpected signer subject.");
    return { expectedCanonicalSubject: expectedCanonical, canonicalSubject: signature.canonicalSubject, trustClassification: signature.trustClassification, signerThumbprint: signature.signerThumbprint, storeCertificate };
  } finally {
    removeSafeTree(DESKTOP_BUILD_ROOT, probeRoot, options);
  }
}

export function planBackendSigning(entries) {
  return entries.map((entry) => {
    if (entry.signature.status === "Valid") return { ...entry, action: "preserve-vendor-signature" };
    if (entry.signature.status === "NotSigned" && !entry.embeddedSignature) return { ...entry, action: "sign-first-party" };
    throw new Error(`Refusing an invalid or ambiguous signature on ${entry.relativePath}.`);
  });
}

export function signBackendTree(root, config, options = {}) {
  const runner = options.runner ?? runCommand;
  const resolvedRoot = resolve(root);
  const entries = listPortableExecutables(resolvedRoot).map((path) => ({ path, relativePath: relative(resolvedRoot, path).replaceAll("\\", "/"), embeddedSignature: hasEmbeddedAuthenticode(readFileSync(path)), beforeSha256: sha256(path), signature: inspectAuthenticode(path, runner, options.env) }));
  const plan = planBackendSigning(entries);
  if (!plan.some((entry) => entry.relativePath.toLowerCase() === "glacial-backend.exe")) throw new Error("The PyInstaller payload does not contain glacial-backend.exe.");
  const records = [];
  for (const entry of plan) {
    if (entry.action === "sign-first-party") {
      const signature = signOne(entry.path, config, { runner, env: options.env });
      records.push({ ...entry, signature, afterSha256: sha256(entry.path), classification: "first-party" });
    } else {
      const signature = verifySignature(entry.path, config, { runner, env: options.env });
      const afterSha256 = sha256(entry.path);
      if (afterSha256 !== entry.beforeSha256) throw new Error(`Vendor-signed payload changed during verification: ${entry.relativePath}`);
      records.push({ ...entry, signature, afterSha256, classification: "third-party-vendor" });
    }
  }
  const backend = records.find((entry) => entry.relativePath.toLowerCase() === "glacial-backend.exe");
  if (backend.classification !== "first-party") throw new Error("glacial-backend.exe must be signed by the configured Glacial signer.");
  return records;
}

export function verifyPayloadTree(root, config, options = {}) {
  const runner = options.runner ?? runCommand;
  const resolvedRoot = resolve(root);
  const required = new Set((options.requiredFirstParty ?? []).map((path) => path.replaceAll("\\", "/").toLowerCase()));
  const records = [];
  for (const path of listPortableExecutables(resolvedRoot)) {
    const relativePath = relative(resolvedRoot, path).replaceAll("\\", "/");
    const signature = verifySignature(path, config, { runner, env: options.env });
    const classification = signature.signerThumbprint === config.expectedThumbprint ? "first-party" : "third-party-vendor";
    if (required.has(relativePath.toLowerCase()) && classification !== "first-party") throw new Error(`${relativePath} is not signed by the configured Glacial signer.`);
    if (classification === "first-party") verifySignature(path, config, { runner, env: options.env, expectFirstParty: true, signature, expectedCanonicalSubject: options.expectedCanonicalSubject });
    records.push({ relativePath, bytes: statSync(path).size, sha256: sha256(path), classification, ...signature });
  }
  if (!records.length) throw new Error(`No PE payloads were found under ${resolvedRoot}.`);
  for (const path of required) if (!records.some((record) => record.relativePath.toLowerCase() === path)) throw new Error(`Required first-party PE is missing: ${path}.`);
  return records;
}

export function signingEnvironment(source, releaseId) {
  const providerNames = parseEnvironmentNames(source.GLACIAL_WINDOWS_SIGN_COMMAND_ENV);
  return minimalEnvironment(source, { GLACIAL_WINDOWS_RELEASE_ID: releaseId }, [...INTERNAL_ENVIRONMENT_NAMES, ...providerNames]);
}

function printDryRun(config) {
  process.stdout.write(`${JSON.stringify({ provider: config.provider, expectedSubject: config.expectedSubject, expectedThumbprint: config.expectedThumbprint, signToolPath: config.signToolPath, timestampOrigin: new URL(config.timestampUrl).origin, timestampRequired: true, providerCommand: config.provider === "command" ? `${config.command} <reviewed argument array>` : null }, null, 2)}\n`);
}

async function main() {
  const [command, argument] = process.argv.slice(2);
  if (command === "dry-run") { printDryRun(loadSigningConfig(process.env, { dryRun: true })); return; }
  const config = loadSigningConfig();
  if (command === "sign-one" && argument) { signOne(argument, config); return; }
  if (command === "verify-one" && argument) { process.stdout.write(`${JSON.stringify(verifySignature(argument, config, { expectFirstParty: true }), null, 2)}\n`); return; }
  if (command === "verify-tree" && argument) { process.stdout.write(`${JSON.stringify(verifyPayloadTree(argument, config, { requiredFirstParty: process.argv.slice(4) }), null, 2)}\n`); return; }
  throw new Error("Usage: windows-signing.mjs dry-run | sign-one <PE> | verify-one <PE> | verify-tree <directory> [required first-party paths...]");
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(SIGNING_SCRIPT_PATH)) {
  main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
