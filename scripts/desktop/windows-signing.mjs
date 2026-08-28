import {
  constants,
  appendFileSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { request as httpRequest } from "node:http";
import { fileURLToPath } from "node:url";
import { assertAuthenticatedReleaseTool, assertCurrentReleaseAuthority } from "../release/release-authority.mjs";

export const DEFAULT_SIGNER_SUBJECT = "CN=Icefields Development";
export const SIGNING_SCRIPT_PATH = fileURLToPath(import.meta.url);
export const REPOSITORY_ROOT = resolve(dirname(SIGNING_SCRIPT_PATH), "..", "..");
export const DESKTOP_BUILD_ROOT = resolve(REPOSITORY_ROOT, ".desktop-build");
const AUTHENTIC_RELEASE_SIGNING_CONFIGS = new WeakSet();
const AUTHENTIC_SIGNING_AUTHORIZATIONS = new WeakSet();

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
  "GLACIAL_BUILD_IDENTITY_JSON",
  "GLACIAL_RELEASE_PROFILE",
  "GLACIAL_WINDOWS_ARTIFACT_SIGNER_CERTIFICATE_PATH",
  "GLACIAL_WINDOWS_CERTIFICATE_THUMBPRINT",
  "GLACIAL_WINDOWS_EXPECTED_SUBJECT",
  "GLACIAL_WINDOWS_EXPECTED_THUMBPRINT",
  "GLACIAL_WINDOWS_RELEASE_ID",
  "GLACIAL_WINDOWS_SIGN_AUDIT_KEY",
  "GLACIAL_WINDOWS_REQUIRE_TIMESTAMP",
  "GLACIAL_WINDOWS_SIGNING_PROVIDER",
  "GLACIAL_WINDOWS_SIGNTOOL_PATH",
  "GLACIAL_WINDOWS_SIGN_COMMAND",
  "GLACIAL_WINDOWS_SIGN_COMMAND_ARGS",
  "GLACIAL_WINDOWS_SIGN_COMMAND_ENV",
  "GLACIAL_WINDOWS_TIMESTAMP_URL",
  "GLACIAL_WINDOWS_RELEASE_AUTHORITY_PATH",
  "GLACIAL_WINDOWS_RELEASE_AUTHORITY_SIGNATURE_PATH",
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
  "Add-Type -TypeDefinition @'",
  "using System;",
  "using System.ComponentModel;",
  "using System.Runtime.InteropServices;",
  "using Microsoft.Win32.SafeHandles;",
  "public static class GlacialFileIdentity {",
  "  [StructLayout(LayoutKind.Sequential)] public struct Info { public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime; public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime; public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime; public uint VolumeSerialNumber; public uint FileSizeHigh; public uint FileSizeLow; public uint NumberOfLinks; public uint FileIndexHigh; public uint FileIndexLow; }",
  "  public sealed class Result { public string FinalPath { get; set; } public uint Attributes { get; set; } public uint VolumeSerialNumber { get; set; } public uint NumberOfLinks { get; set; } public uint FileIndexHigh { get; set; } public uint FileIndexLow { get; set; } public long FileSize { get; set; } }",
  "  [DllImport(\"kernel32.dll\", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);",
  "  [DllImport(\"kernel32.dll\", SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);",
  "  [DllImport(\"kernel32.dll\", CharSet=CharSet.Unicode, SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, System.Text.StringBuilder path, uint length, uint flags);",
  "  public static Result Inspect(string path) {",
  "    using (var handle = CreateFileW(path, 0x80, 7, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero)) {",
  "      if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());",
  "      Info info; if (!GetFileInformationByHandle(handle, out info)) throw new Win32Exception(Marshal.GetLastWin32Error());",
  "      var finalPath = new System.Text.StringBuilder(32768); uint length = GetFinalPathNameByHandleW(handle, finalPath, (uint)finalPath.Capacity, 0);",
  "      if (length == 0 || length >= finalPath.Capacity) throw new Win32Exception(Marshal.GetLastWin32Error());",
  "      return new Result { FinalPath=finalPath.ToString(), Attributes=info.Attributes, VolumeSerialNumber=info.VolumeSerialNumber, NumberOfLinks=info.NumberOfLinks, FileIndexHigh=info.FileIndexHigh, FileIndexLow=info.FileIndexLow, FileSize=((long)info.FileSizeHigh << 32) | info.FileSizeLow };",
  "    }",
  "  }",
  "}",
  "'@",
  "function Has-CodeSigningEku([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate) {",
  "  foreach ($extension in $Certificate.Extensions) {",
  "    if ($extension.Oid.Value -eq '2.5.29.37') {",
  "      $eku = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($extension.RawData, $false)",
  "      return @($eku.EnhancedKeyUsages | Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.3' }).Count -gt 0",
  "    }",
  "  }",
  "  return $false",
  "}",
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
  "      [pscustomobject]@{ Thumbprint = Thumb $_.Thumbprint; CanonicalSubject = Canonical-Dn $_.SubjectName; HasPrivateKey = $_.HasPrivateKey; NotBeforeUtc = $_.NotBefore.ToUniversalTime().ToString('o'); NotAfterUtc = $_.NotAfter.ToUniversalTime().ToString('o'); CodeSigningEku = Has-CodeSigningEku $_; TrustValid = $trust.Valid; TrustClassification = $trust.Classification; ChainStatuses = $trust.Statuses }",
  "    })",
  "    [pscustomobject]@{ Candidates = $candidates } | ConvertTo-Json -Compress -Depth 5",
  "  }",
  "  'signature' {",
  "    $signature = Get-AuthenticodeSignature -LiteralPath ([string]$payload.path)",
  "    $trust = if ($signature.SignerCertificate) { Trust-Info $signature.SignerCertificate } else { $null }",
  "    [pscustomobject]@{ Status = $signature.Status.ToString(); StatusMessage = $signature.StatusMessage; SignerThumbprint = if ($signature.SignerCertificate) { Thumb $signature.SignerCertificate.Thumbprint } else { $null }; CanonicalSubject = if ($signature.SignerCertificate) { Canonical-Dn $signature.SignerCertificate.SubjectName } else { $null }; SignerNotBeforeUtc = if ($signature.SignerCertificate) { $signature.SignerCertificate.NotBefore.ToUniversalTime().ToString('o') } else { $null }; SignerNotAfterUtc = if ($signature.SignerCertificate) { $signature.SignerCertificate.NotAfter.ToUniversalTime().ToString('o') } else { $null }; CodeSigningEku = if ($signature.SignerCertificate) { Has-CodeSigningEku $signature.SignerCertificate } else { $false }; TimestampThumbprint = if ($signature.TimeStamperCertificate) { Thumb $signature.TimeStamperCertificate.Thumbprint } else { $null }; TrustValid = if ($trust) { $trust.Valid } else { $false }; TrustClassification = if ($trust) { $trust.Classification } else { 'invalid' }; ChainStatuses = if ($trust) { $trust.Statuses } else { @() } } | ConvertTo-Json -Compress -Depth 5",
  "  }",
  "  'path-info' {",
  "    $items = @($payload.paths | ForEach-Object {",
  "      $path = [System.IO.Path]::GetFullPath([string]$_)",
  "      if (Test-Path -LiteralPath $path) { $item = Get-Item -LiteralPath $path -Force; [pscustomobject]@{ Path = $path; Exists = $true; ReparsePoint = (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0); Attributes = $item.Attributes.ToString() } }",
  "      else { [pscustomobject]@{ Path = $path; Exists = $false; ReparsePoint = $false; Attributes = '' } }",
  "    })",
  "    [pscustomobject]@{ Items = $items } | ConvertTo-Json -Compress -Depth 4",
  "  }",
  "  'file-identity' {",
  "    $path = [System.IO.Path]::GetFullPath([string]$payload.path)",
  "    [GlacialFileIdentity]::Inspect($path) | ConvertTo-Json -Compress",
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
  "  'process-info' {",
  "    $processId = [int]$payload.processId",
  "    if ($processId -le 0) { throw 'Process id is invalid.' }",
  "    $process = Get-CimInstance -ClassName Win32_Process -Filter (\"ProcessId = $processId\")",
  "    if (-not $process) { throw 'Process was not found.' }",
  "    [pscustomobject]@{ ProcessId = [int]$process.ProcessId; ExecutablePath = [string]$process.ExecutablePath; CommandLine = [string]$process.CommandLine } | ConvertTo-Json -Compress",
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

export function assertNoNodeRuntimeInjection(environment = process.env) {
  for (const name of ["NODE_OPTIONS", "NODE_PATH"]) {
    if (getEnvironmentValue(environment, name) != null) {
      throw new Error(`${name} is forbidden for the signed-release coordinator and its children.`);
    }
  }
  return true;
}

export function privacySafePath(value) {
  const target = resolve(String(value ?? ""));
  for (const [root, placeholder] of [
    [DESKTOP_BUILD_ROOT, "<DESKTOP_BUILD_ROOT>"],
    [REPOSITORY_ROOT, "<REPOSITORY_ROOT>"],
  ]) {
    const child = relative(root, target);
    if (!child || (!child.startsWith(`..${sep}`) && child !== ".." && !isAbsolute(child))) {
      return child ? `${placeholder}/${child.replaceAll("\\", "/")}` : placeholder;
    }
  }
  return `<HOST_PATH>/${basename(target)}`;
}

export function resolvePrivacySafePath(value) {
  const text = String(value ?? "");
  for (const [placeholder, root] of [
    ["<DESKTOP_BUILD_ROOT>", DESKTOP_BUILD_ROOT],
    ["<REPOSITORY_ROOT>", REPOSITORY_ROOT],
  ]) {
    if (text === placeholder) return root;
    if (text.startsWith(`${placeholder}/`)) {
      return resolve(root, text.slice(placeholder.length + 1));
    }
  }
  return resolve(text);
}

export function sanitizeDiagnosticText(value, redactions = []) {
  let text = String(value ?? "").replaceAll(/\r\n?/g, "\n");
  for (const secret of redactions.filter((item) => typeof item === "string" && item.length > 0)) {
    text = text.replaceAll(secret, "[REDACTED]");
  }
  text = text
    .replace(/-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----[\s\S]*?(?:-----END(?: [A-Z0-9]+)* PRIVATE KEY-----|$)/gi, "[REDACTED PRIVATE KEY]")
    .replace(/([A-Z][A-Z0-9+.-]*:\/\/)(?:[^/\s:@]+):(?:[^@\s/]+)@/gi, "$1[REDACTED]@")
    .replace(/(["']?\bauthorization\b["']?\s*[:=]\s*)[^\r\n]+/gi, "$1[REDACTED]")
    .replace(/\bbearer\s+[A-Z0-9._~+/=-]+/gi, "Bearer [REDACTED]")
    .replace(/(["']?\b(?:[A-Z0-9_.-]*(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|pwd|secret|private[_-]?key)[A-Z0-9_.-]*)\b["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}\])]+)/gim, "$1[REDACTED]")
    .replace(/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, "[REDACTED]")
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b/gi, "[REDACTED]")
    .replace(/(^|[^A-Za-z0-9])([0-9a-f]{40,128})(?=$|[^A-Za-z0-9])/gi, "$1[REDACTED]")
    .replace(/(^|[^A-Za-z0-9])([A-Za-z0-9._~+/=-]{32,})(?=$|[^A-Za-z0-9])/g, (match, prefix, token) => (
      shouldRedactLongToken(token) ? `${prefix}[REDACTED]` : match
    ))
    .replaceAll(REPOSITORY_ROOT, "<REPOSITORY_ROOT>")
    .replaceAll(DESKTOP_BUILD_ROOT, "<DESKTOP_BUILD_ROOT>")
    .replace(/(^|[^A-Za-z0-9])(?:[A-Za-z]:[\\/])Users[\\/][^\\/\s"'<>|]+/gi, "$1<USER_PROFILE>")
    .replace(/<USER_PROFILE>[\\/]AppData[\\/]Local[\\/]Temp(?:[\\/][^\r\n\t"'<>|]*)?/gi, "<TEMP_DIR>")
    .replace(/(^|[^A-Za-z0-9])\\\\[^\\/\s"'<>|]+\\[^\\/\s"'<>|]+(?:[\\/][^\r\n\t"'<>|]*)?/gi, "$1<HOST_PATH>")
    .replace(/(^|[^A-Za-z0-9])(?:[A-Za-z]:[\\/])[^\r\n\t"'<>|]*/gi, "$1<HOST_PATH>")
    .replace(/(^|[^A-Za-z0-9:])\/(?:Users|home|tmp|var\/tmp|private\/tmp|opt|srv|mnt|media)\/[^\r\n\t"'<>|]*/gi, "$1<HOST_PATH>")
    .replaceAll(/\u001B\[[0-?]*[ -/]*[@-~]/g, "")
    .replaceAll(/[^\t\n\x20-\x7E]/g, "");
  return text;
}

function shouldRedactLongToken(value) {
  const characters = new Set(value.toLowerCase());
  return characters.size >= 10 && /[A-Za-z]/.test(value) && /[0-9]/.test(value);
}

function sanitizedFailureOutput(result, redactions = []) {
  let output = [result.stdout, result.stderr].filter(Boolean).join("\n");
  output = sanitizeDiagnosticText(output, redactions).trim();
  if (output.length > 16_384) output = `${output.slice(0, 16_384)}\n[diagnostic output truncated]`;
  return output;
}

function commandFailure(command, result, options = {}) {
  const reason = result.signal ? `signal ${result.signal}` : `status ${result.status ?? "unknown"}`;
  const diagnostic = options.includeFailureOutput ? sanitizedFailureOutput(result, options.diagnosticRedactions) : "";
  return new Error(diagnostic ? `${basename(command)} failed with ${reason}.\n${diagnostic}` : `${basename(command)} failed with ${reason}; child output was suppressed.`);
}

export function runCommand(command, args, options = {}) {
  const executable = typeof command === "string" ? command : assertAuthenticatedReleaseTool(command);
  if (!isAbsolute(executable)) throw new Error(`Refusing to launch a non-absolute executable: ${executable}`);
  const result = spawnSync(executable, args, {
    cwd: options.cwd,
    env: options.env,
    encoding: "utf8",
    maxBuffer: options.maxBuffer ?? 64 * 1024 * 1024,
    timeout: options.timeoutMs ?? 120_000,
    windowsHide: false,
    shell: false,
  });
  if (result.error) throw new Error(`${basename(executable)} could not be started: ${result.error.code ?? "unknown error"}.`);
  if (result.status !== 0) throw commandFailure(executable, result, options);
  return result;
}

export function normalizeThumbprint(value, name = "certificate thumbprint") {
  const normalized = String(value ?? "").replaceAll(/\s/g, "").toUpperCase();
  if (!/^[0-9A-F]{40}$/.test(normalized)) throw new Error(`${name} must be a 40-character SHA-1 certificate thumbprint.`);
  return normalized;
}

export function validateStructuredDigest(value, contract) {
  if (typeof value !== "string") throw new Error(`${contract} must be a string.`);
  const patterns = {
    "git-commit": /^[0-9a-f]{40}$/i,
    sha256: /^[0-9a-f]{64}$/i,
  };
  const pattern = patterns[contract];
  if (!pattern) throw new Error("Unknown structured digest contract.");
  if (!pattern.test(value)) throw new Error(`${contract} is invalid.`);
  return value;
}

function parseTimestampUrl(value) {
  if (!value) throw new Error("GLACIAL_WINDOWS_TIMESTAMP_URL is required for signed releases.");
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error("GLACIAL_WINDOWS_TIMESTAMP_URL is invalid."); }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("GLACIAL_WINDOWS_TIMESTAMP_URL must not contain credentials, a query string, or a fragment.");
  }
  const exactDigiCertHttpEndpoint = parsed.protocol === "http:" && parsed.hostname.toLowerCase() === "timestamp.digicert.com" && !parsed.port && parsed.pathname === "/";
  if (parsed.protocol !== "https:" && !exactDigiCertHttpEndpoint) {
    throw new Error("GLACIAL_WINDOWS_TIMESTAMP_URL must use HTTPS or the exact DigiCert HTTP RFC 3161 endpoint.");
  }
  return exactDigiCertHttpEndpoint ? "http://timestamp.digicert.com" : parsed.toString();
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
  if (!/^Glacial-0\.9\.12-[0-9a-f]{12}-[0-9]{8}T[0-9]{6}Z$/i.test(value)) throw new Error("Invalid internal release id.");
  return value;
}

function validateSigningAuditKey(value) {
  const key = String(value ?? "");
  if (!/^[0-9a-f]{64}$/i.test(key)) throw new Error("GLACIAL_WINDOWS_SIGN_AUDIT_KEY must be a 64-character release-scoped key.");
  return key.toLowerCase();
}

export function loadSigningConfig(env = process.env, options = {}) {
  const dryRun = options.dryRun === true;
  if (!dryRun && !new Set(["signed-preview", "public-rc"]).has(options.profile)) {
    throw new Error("An authorized signed-release profile is required.");
  }
  const authority = dryRun ? null : assertCurrentReleaseAuthority(options.authority, { profile: options.profile });
  const authorizedSigning = authority?.signing ?? null;
  const tools = options.tools ?? null;
  if (!dryRun && (!tools?.powerShell || !tools?.signTool || !tools?.signingProvider)) {
    throw new Error("Authenticated PowerShell, SignTool, and signing-provider tools are required.");
  }
  if (!dryRun) {
    for (const role of ["powerShell", "signTool", "signingProvider"]) {
      const expected = authority.tools[role];
      const supplied = tools[role];
      if (supplied.role !== role || resolve(supplied.path).toLowerCase() !== resolve(expected.path).toLowerCase()
          || supplied.sha256 !== expected.sha256) throw new Error(`Authenticated ${role} does not match the release authority.`);
    }
  }
  const provider = authorizedSigning?.provider ?? String(env.GLACIAL_WINDOWS_SIGNING_PROVIDER ?? "").toLowerCase();
  if (provider !== "store" && provider !== "command") throw new Error("GLACIAL_WINDOWS_SIGNING_PROVIDER must be store or command.");
  if (dryRun && !/^(1|true)$/i.test(String(env.GLACIAL_WINDOWS_REQUIRE_TIMESTAMP ?? ""))) {
    throw new Error("GLACIAL_WINDOWS_REQUIRE_TIMESTAMP must be 1 for signed releases.");
  }
  const expectedSubject = String(authorizedSigning?.expectedSubject ?? env.GLACIAL_WINDOWS_EXPECTED_SUBJECT ?? DEFAULT_SIGNER_SUBJECT).trim();
  if (!expectedSubject) throw new Error("GLACIAL_WINDOWS_EXPECTED_SUBJECT must not be empty.");
  const signToolPath = dryRun
    ? requireAbsoluteFile(env.GLACIAL_WINDOWS_SIGNTOOL_PATH, "GLACIAL_WINDOWS_SIGNTOOL_PATH", true)
    : assertAuthenticatedReleaseTool(tools.signTool);
  const powerShellPath = dryRun ? null : assertAuthenticatedReleaseTool(tools.powerShell);
  const timestampUrl = authorizedSigning?.timestampUrl ?? parseTimestampUrl(env.GLACIAL_WINDOWS_TIMESTAMP_URL);
  const releaseId = validateReleaseId(env.GLACIAL_WINDOWS_RELEASE_ID);
  const auditLog = releaseId ? resolve(DESKTOP_BUILD_ROOT, "signing", releaseId, "signing-events.jsonl") : null;
  const auditKey = releaseId ? validateSigningAuditKey(env.GLACIAL_WINDOWS_SIGN_AUDIT_KEY) : null;
  const applicationTarget = releaseId ? resolve(REPOSITORY_ROOT, "frontend", "src-tauri", "target", "release", "glacial.exe") : null;
  const applicationCapture = releaseId ? resolve(DESKTOP_BUILD_ROOT, "signing", releaseId, "application", "Glacial.exe") : null;
  const releaseState = {
    releaseId, auditLog, auditKey, applicationTarget, applicationCapture,
    releaseAuthority: authority,
    authorityDigest: authority?.digest ?? null,
    releaseProfile: dryRun ? null : options.profile,
    nodeTool: tools?.node ?? null,
    powerShellTool: tools?.powerShell ?? null,
    powerShellPath,
    signToolTool: tools?.signTool ?? null,
    signingProviderTool: tools?.signingProvider ?? null,
  };

  if (provider === "store") {
    const thumbprint = authorizedSigning?.expectedThumbprint ?? normalizeThumbprint(env.GLACIAL_WINDOWS_CERTIFICATE_THUMBPRINT);
    return finalizeSigningConfig({ provider, expectedSubject, expectedThumbprint: thumbprint, certificateThumbprint: thumbprint, signToolPath, timestampUrl, requireTimestamp: true, ...releaseState }, dryRun);
  }
  const command = dryRun
    ? requireAbsoluteFile(env.GLACIAL_WINDOWS_SIGN_COMMAND, "GLACIAL_WINDOWS_SIGN_COMMAND", true)
    : assertAuthenticatedReleaseTool(tools.signingProvider);
  const providerEnvironmentNames = authorizedSigning?.providerEnvironmentNames ?? parseEnvironmentNames(env.GLACIAL_WINDOWS_SIGN_COMMAND_ENV);
  const providerEnvironment = minimalEnvironment(env, {}, providerEnvironmentNames);
  return finalizeSigningConfig({
    provider,
    expectedSubject,
    expectedThumbprint: authorizedSigning?.expectedThumbprint ?? normalizeThumbprint(env.GLACIAL_WINDOWS_EXPECTED_THUMBPRINT, "GLACIAL_WINDOWS_EXPECTED_THUMBPRINT"),
    signToolPath,
    timestampUrl,
    requireTimestamp: true,
    command,
    commandArgs: authorizedSigning?.commandArgs ?? parseCommandArguments(env.GLACIAL_WINDOWS_SIGN_COMMAND_ARGS),
    providerEnvironmentNames,
    providerEnvironment: Object.freeze(providerEnvironment),
    ...releaseState,
  }, dryRun);
}

function finalizeSigningConfig(config, dryRun) {
  const result = Object.freeze(config);
  if (!dryRun) AUTHENTIC_RELEASE_SIGNING_CONFIGS.add(result);
  return result;
}

function assertReleaseSigningConfig(config) {
  if (!config || !AUTHENTIC_RELEASE_SIGNING_CONFIGS.has(config)) {
    throw new Error("An authentic authority-derived signing configuration is required.");
  }
  const authority = assertCurrentReleaseAuthority(config.releaseAuthority, { profile: config.releaseProfile });
  for (const role of ["node", "powerShell", "signTool", "signingProvider"]) {
    const tool = config[`${role}Tool`];
    if (assertAuthenticatedReleaseTool(tool).toLowerCase() !== resolve(authority.tools[role].path).toLowerCase()
        || tool.sha256 !== authority.tools[role].sha256) {
      throw new Error(`Signing configuration ${role} no longer matches its release authority.`);
    }
  }
  const signing = authority.signing;
  if (config.provider !== signing.provider || config.expectedSubject !== signing.expectedSubject
      || config.expectedThumbprint !== signing.expectedThumbprint || config.timestampUrl !== signing.timestampUrl
      || (config.provider === "command" && (config.command !== config.signingProviderTool.path
        || JSON.stringify(config.commandArgs) !== JSON.stringify(signing.commandArgs)
        || JSON.stringify(config.providerEnvironmentNames) !== JSON.stringify(signing.providerEnvironmentNames)))) {
    throw new Error("Signing configuration no longer matches its release authority.");
  }
  return authority;
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

export function resolvePnpmInvocation(env = process.env, options = {}) {
  const command = resolveToolExecutable("node.exe", env, options);
  const pnpmLauncher = resolveToolExecutable("pnpm.cmd", env, options);
  const launcher = readFileSync(pnpmLauncher, "utf8");
  const candidates = [...launcher.matchAll(/"%~dp0([^"\r\n]+\.(?:cjs|mjs|js))"/gi)]
    .map((match) => resolve(dirname(pnpmLauncher), match[1]))
    .filter((path) => /(?:^|[\\/])pnpm(?:[\\/]|\.(?:cjs|mjs|js)$)/i.test(path))
    .filter((path, index, paths) => paths.findIndex((candidate) => candidate.toLowerCase() === path.toLowerCase()) === index)
    .filter((path) => existsSync(path) && lstatSync(path).isFile() && !lstatSync(path).isSymbolicLink());
  if (candidates.length !== 1) throw new Error("Could not resolve pnpm to one direct JavaScript CLI entrypoint.");
  const [pnpmCli] = candidates;
  const forbiddenRoot = options.forbiddenRoot ? resolve(options.forbiddenRoot) : null;
  if (forbiddenRoot) {
    const rel = relative(forbiddenRoot, pnpmCli);
    if (!rel || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel))) {
      throw new Error("Refusing a repository-local pnpm CLI entrypoint.");
    }
  }
  return { command, prefixArgs: [pnpmCli] };
}

export function createPowerShellInvocation(operation, payload, env = process.env, powerShellTool = null) {
  return {
    command: powerShellTool
      ? assertAuthenticatedReleaseTool(powerShellTool)
      : systemExecutable("System32/WindowsPowerShell/v1.0/powershell.exe", env),
    args: ["-NoProfile", "-NonInteractive", "-Command", WINDOWS_SIGNING_POWERSHELL_HELPER_COMMAND],
    env: minimalEnvironment(env, {
      GLACIAL_WINDOWS_HELPER_OPERATION: operation,
      GLACIAL_WINDOWS_HELPER_PAYLOAD: JSON.stringify(payload),
    }),
  };
}

function invokeWindowsHelper(operation, payload, runner = runCommand, env = process.env, powerShellTool = null) {
  const invocation = createPowerShellInvocation(operation, payload, env, powerShellTool);
  const result = runner(invocation.command, invocation.args, { env: invocation.env, timeoutMs: 30_000 });
  const output = String(result.stdout ?? "").trim();
  if (!output) throw new Error(`Windows signing helper returned no ${operation} result.`);
  try { return JSON.parse(output); } catch { throw new Error(`Windows signing helper returned malformed ${operation} data.`); }
}

export function canonicalizeDistinguishedName(subject, runner = runCommand, env = process.env, powerShellTool = null) {
  const result = invokeWindowsHelper("canonical-subject", { subject }, runner, env, powerShellTool);
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
  const now = Date.now();
  const notBefore = Date.parse(certificate.NotBeforeUtc);
  const notAfter = Date.parse(certificate.NotAfterUtc);
  if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter) || now < notBefore || now > notAfter) {
    throw new Error("The selected certificate is expired, not yet valid, or has malformed validity dates.");
  }
  if (certificate.CodeSigningEku !== true) throw new Error("The selected certificate lacks the Code Signing EKU.");
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
  return ["sign", "/debug", "/v", "/s", "My", "/sha1", config.certificateThumbprint, "/fd", "SHA256", "/d", "Glacial", resolve(file)];
}

export function buildTimestampArgs(config, file) {
  return ["timestamp", "/debug", "/v", "/tr", config.timestampUrl, "/td", "SHA256", resolve(file)];
}

export function buildCommandSignArgs(config, file) {
  const target = resolve(file);
  return config.commandArgs.map((argument) => argument.replaceAll("{file}", target));
}

export function createTauriSigningOverlay(nodePath = process.execPath, scriptPath = SIGNING_SCRIPT_PATH) {
  return { bundle: { active: true, targets: ["nsis"], windows: { digestAlgorithm: "sha256", signCommand: { cmd: resolve(nodePath), args: [resolve(scriptPath), "sign-request", "%1"] } } } };
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

export function createUnsignedProbeCopy(source, destination) {
  copyFileSync(source, destination);
  const original = readFileSync(destination);
  if (!isPortableExecutable(original)) throw new Error("The signing probe source is not a PE file.");
  const peOffset = original.readUInt32LE(0x3c);
  let unsigned = Buffer.from(original);
  if (hasEmbeddedAuthenticode(original)) {
    const optionalHeader = peOffset + 24;
    const magic = original.readUInt16LE(optionalHeader);
    const dataDirectory = optionalHeader + (magic === 0x20b ? 112 : magic === 0x10b ? 96 : -1);
    const securityDirectory = dataDirectory + 32;
    const certificateOffset = original.readUInt32LE(securityDirectory);
    const certificateSize = original.readUInt32LE(securityDirectory + 4);
    if (dataDirectory < optionalHeader || certificateOffset <= 0 || certificateSize <= 0 || certificateOffset + certificateSize !== original.length) {
      throw new Error("The signing probe source has an unsupported Authenticode certificate layout.");
    }
    unsigned = Buffer.from(original.subarray(0, certificateOffset));
    unsigned.writeUInt32LE(0, securityDirectory);
    unsigned.writeUInt32LE(0, securityDirectory + 4);
  }
  const coffTimestampOffset = peOffset + 8;
  unsigned.writeUInt32LE((unsigned.readUInt32LE(coffTimestampOffset) ^ 1) >>> 0, coffTimestampOffset);
  if (!isPortableExecutable(unsigned) || hasEmbeddedAuthenticode(unsigned)) throw new Error("Could not create an unsigned signing probe copy.");
  writeFileSync(destination, unsigned);
  return destination;
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

export function inspectAuthenticode(file, runner = runCommand, env = process.env, powerShellTool = null) {
  const value = invokeWindowsHelper("signature", { path: resolve(file) }, runner, env, powerShellTool);
  return {
    status: value.Status,
    statusMessage: value.StatusMessage,
    signerThumbprint: value.SignerThumbprint ? normalizeThumbprint(value.SignerThumbprint, "signer thumbprint") : null,
    canonicalSubject: value.CanonicalSubject ?? null,
    signerNotBeforeUtc: value.SignerNotBeforeUtc ?? null,
    signerNotAfterUtc: value.SignerNotAfterUtc ?? null,
    codeSigningEku: value.CodeSigningEku === true,
    timestampThumbprint: value.TimestampThumbprint ? normalizeThumbprint(value.TimestampThumbprint, "timestamp thumbprint") : null,
    trustValid: value.TrustValid === true,
    trustClassification: value.TrustClassification,
    chainStatuses: value.ChainStatuses ?? [],
  };
}

function verifyWithSignTool(file, config, runner = runCommand) {
  const signToolPath = config.signToolTool ? assertAuthenticatedReleaseTool(config.signToolTool) : config.signToolPath;
  runner(signToolPath, ["verify", "/pa", "/all", "/tw", resolve(file)], { env: minimalEnvironment(process.env), includeFailureOutput: true });
}

export function verifySignature(file, config, options = {}) {
  const runner = options.runner ?? runCommand;
  assertReleaseSigningConfig(config);
  const signature = options.signature ?? inspectAuthenticode(file, runner, options.env, config.powerShellTool);
  if (signature.status !== "Valid") throw new Error(`Authenticode verification failed for ${basename(file)}.`);
  verifyWithSignTool(file, config, runner);
  if (options.expectFirstParty) {
    const expectedCanonical = options.expectedCanonicalSubject ?? canonicalizeDistinguishedName(config.expectedSubject, runner, options.env, config.powerShellTool);
    if (signature.signerThumbprint !== config.expectedThumbprint) throw new Error(`The signer thumbprint for ${basename(file)} is unexpected.`);
    if (String(signature.canonicalSubject ?? "").toUpperCase() !== expectedCanonical) throw new Error(`The signer subject for ${basename(file)} is not an exact canonical match.`);
    if (!signature.timestampThumbprint) throw new Error(`The first-party signature for ${basename(file)} is not timestamped.`);
    const now = Date.now();
    const notBefore = Date.parse(signature.signerNotBeforeUtc);
    const notAfter = Date.parse(signature.signerNotAfterUtc);
    if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter) || now < notBefore || now > notAfter) {
      throw new Error(`The signer certificate for ${basename(file)} is expired, not yet valid, or malformed.`);
    }
    if (signature.codeSigningEku !== true) throw new Error(`The signer certificate for ${basename(file)} lacks the Code Signing EKU.`);
    if (!signature.trustValid || !["self-signed", "publicly-trusted"].includes(signature.trustClassification)) throw new Error(`The signer chain for ${basename(file)} is invalid, private, or ambiguous.`);
  }
  return signature;
}

function escapedRegularExpression(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function assertReleaseCoordinatorParent(config, expectedScript, runner = runCommand) {
  assertReleaseSigningConfig(config);
  const processInfo = invokeWindowsHelper("process-info", { processId: process.ppid }, runner, process.env, config.powerShellTool);
  const expectedNode = assertAuthenticatedReleaseTool(config.nodeTool);
  const actualExecutable = resolve(String(processInfo.ExecutablePath ?? ""));
  if (actualExecutable.toLowerCase() !== resolve(expectedNode).toLowerCase()) {
    throw new Error("The signed-release child process was not launched by the authenticated Node runtime.");
  }
  const nodePattern = escapedRegularExpression(resolve(expectedNode));
  const scriptPattern = escapedRegularExpression(resolve(expectedScript));
  const commandLine = String(processInfo.CommandLine ?? "");
  const canonicalPrefix = new RegExp(`^(?:\"${nodePattern}\"|${nodePattern})\\s+(?:\"${scriptPattern}\"|${scriptPattern})(?:\\s|$)`, "i");
  if (!canonicalPrefix.test(commandLine)) {
    throw new Error("The signed-release child process was not launched by the canonical release coordinator.");
  }
  return Object.freeze({ processId: Number(processInfo.ProcessId), executablePath: actualExecutable, commandLine });
}

export function signingAuditRecord(record) {
  const trustClassification = String(record.trustClassification ?? "");
  if (!["self-signed", "publicly-trusted"].includes(trustClassification)) {
    throw new Error("Signing audit trust classification is invalid.");
  }
  const signedUtc = String(record.signedUtc ?? "");
  if (!signedUtc || Number.isNaN(Date.parse(signedUtc))) {
    throw new Error("Signing audit timestamp is invalid.");
  }
  const artifactRole = String(record.artifactRole ?? "");
  if (!/^(?:application|installer|nsis-uninstaller|nsis-plugin:[a-z0-9_.-]+|backend:[A-Za-z0-9_./-]+|preflight-probe)$/.test(artifactRole)) {
    throw new Error("Signing audit artifact role is invalid.");
  }
  const objectIdentity = String(record.objectIdentity ?? "").toUpperCase();
  if (!/^[0-9A-F]+:[0-9A-F]+$/.test(objectIdentity)) throw new Error("Signing audit object identity is invalid.");
  const releaseId = record.releaseId == null ? null : validateReleaseId(record.releaseId);
  const evidenceObjectIdentity = record.evidenceObjectIdentity == null ? null : String(record.evidenceObjectIdentity).toUpperCase();
  if (evidenceObjectIdentity !== null && !/^[0-9A-F]+:[0-9A-F]+$/.test(evidenceObjectIdentity)) throw new Error("Signing audit evidence object identity is invalid.");
  return {
    path: privacySafePath(record.path),
    artifactRole,
    releaseId,
    objectIdentity,
    evidenceObjectIdentity,
    beforeSha256: validateStructuredDigest(record.beforeSha256, "sha256"),
    sha256: validateStructuredDigest(record.sha256, "sha256"),
    applicationCapturePath: record.applicationCapturePath
      ? privacySafePath(record.applicationCapturePath)
      : null,
    signerThumbprint: normalizeThumbprint(record.signerThumbprint, "signer thumbprint"),
    canonicalSubject: sanitizeDiagnosticText(record.canonicalSubject),
    timestampThumbprint: normalizeThumbprint(record.timestampThumbprint, "timestamp thumbprint"),
    trustClassification,
    signedUtc,
  };
}

export function serializeSigningAuditRecord(record, auditKey) {
  const persisted = signingAuditRecord(record);
  const payload = JSON.stringify(persisted);
  const auditMac = createHmac("sha256", validateSigningAuditKey(auditKey)).update(payload, "utf8").digest("hex").toUpperCase();
  return JSON.stringify({ ...persisted, auditMac });
}

export function parseSigningAuditRecord(line, auditKey) {
  let parsed;
  try { parsed = JSON.parse(line); } catch { throw new Error("Signing audit JSONL is malformed."); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Signing audit JSONL record is malformed.");
  const { auditMac, ...unsigned } = parsed;
  if (!/^[0-9A-F]{64}$/.test(String(auditMac ?? ""))) throw new Error("Signing audit record authentication is missing or malformed.");
  const persisted = signingAuditRecord({
    ...unsigned,
    path: resolvePrivacySafePath(unsigned.path),
    applicationCapturePath: unsigned.applicationCapturePath ? resolvePrivacySafePath(unsigned.applicationCapturePath) : null,
  });
  if (JSON.stringify(persisted) !== JSON.stringify(unsigned)) throw new Error("Signing audit record is not canonical.");
  const expected = createHmac("sha256", validateSigningAuditKey(auditKey)).update(JSON.stringify(unsigned), "utf8").digest();
  const actual = Buffer.from(auditMac, "hex");
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw new Error("Signing audit record authentication failed.");
  return parsed;
}

function appendAuditRecord(config, record) {
  if (!config.auditLog) return;
  const audit = assertSafePath(DESKTOP_BUILD_ROOT, config.auditLog);
  ensureSafeDirectory(DESKTOP_BUILD_ROOT, dirname(audit));
  appendFileSync(audit, `${serializeSigningAuditRecord(record, config.auditKey)}\n`, { encoding: "utf8" });
}

function samePath(left, right) {
  return Boolean(left && right) && resolve(left).toLowerCase() === resolve(right).toLowerCase();
}

function normalizeObjectIdentity(value) {
  if (!value || typeof value !== "object") throw new Error("Signing object identity inspection failed.");
  const objectId = String(value.objectId ?? "").toUpperCase();
  const linkCount = Number(value.linkCount);
  const size = Number(value.size);
  if (!/^[0-9A-F]+:[0-9A-F]+$/.test(objectId) || !Number.isSafeInteger(linkCount) || linkCount < 1 || !Number.isSafeInteger(size) || size < 0) {
    throw new Error("Signing object identity inspection returned malformed data.");
  }
  if (value.reparsePoint === true) throw new Error("Refusing to sign a reparse-point artifact.");
  if (linkCount !== 1) throw new Error("Refusing to sign an artifact with multiple hardlinks.");
  return { objectId, linkCount, size, reparsePoint: false };
}

export function inspectSigningObject(file, options = {}) {
  const target = realpathSync.native(resolve(file));
  if (options.objectInspector) return normalizeObjectIdentity(options.objectInspector(target));
  if (process.platform === "win32" && options.pathInspector !== false) {
    const value = invokeWindowsHelper("file-identity", { path: target }, options.runner, options.env, options.powerShellTool);
    const objectId = `${Number(value.VolumeSerialNumber).toString(16)}:${Number(value.FileIndexHigh).toString(16).padStart(8, "0")}${Number(value.FileIndexLow).toString(16).padStart(8, "0")}`;
    return normalizeObjectIdentity({
      objectId,
      linkCount: value.NumberOfLinks,
      size: value.FileSize,
      reparsePoint: (Number(value.Attributes) & 0x400) !== 0,
    });
  }
  const metadata = statSync(target);
  return normalizeObjectIdentity({
    objectId: `${BigInt(metadata.dev).toString(16)}:${BigInt(metadata.ino).toString(16)}`,
    linkCount: metadata.nlink,
    size: metadata.size,
    reparsePoint: false,
  });
}

function assertSameSigningObject(file, authorization, options = {}, expectedSha256 = null) {
  const identity = inspectSigningObject(file, options);
  if (identity.objectId !== authorization.objectIdentity) throw new Error("The authorized filesystem object identity changed before signing completed.");
  if (expectedSha256 && sha256(file) !== expectedSha256) throw new Error("The signed bytes changed before signing evidence was committed.");
  return identity;
}

export function captureSignedApplication(file, config, options = {}) {
  const target = resolve(file);
  if (!samePath(target, config.applicationTarget)) return null;
  if (!config.applicationCapture) throw new Error("The application capture path is unavailable.");
  const capture = assertSafePath(DESKTOP_BUILD_ROOT, config.applicationCapture, options);
  const captureRoot = ensureSafeDirectory(DESKTOP_BUILD_ROOT, dirname(capture), options);
  assertSafeTree(captureRoot, options);
  if (existsSync(capture)) throw new Error("Refusing a duplicate Glacial application capture.");

  const temporary = assertSafePath(captureRoot, resolve(captureRoot, `Glacial.exe.capture-${process.pid}-${Date.now()}.tmp`), options);
  try {
    copyFileSync(target, temporary, constants.COPYFILE_EXCL);
    const targetHash = sha256(target);
    if (sha256(temporary) !== targetHash) throw new Error("The temporary Glacial application capture is not byte-identical.");
    const signature = verifySignature(temporary, config, { expectFirstParty: true, runner: options.runner, env: options.env });
    renameSync(temporary, capture);
    if (sha256(capture) !== targetHash) throw new Error("The atomic Glacial application capture hash changed.");
    const capturedSignature = verifySignature(capture, config, { expectFirstParty: true, runner: options.runner, env: options.env });
    return { path: capture, sha256: targetHash, signature: capturedSignature, objectIdentity: inspectSigningObject(capture, options).objectId };
  } finally {
    if (existsSync(temporary)) unlinkSync(temporary);
  }
}

const consumedSigningPlans = new WeakSet();

export function exactSigningAuthorization(file, role, options = {}) {
  const authority = options.config?.releaseAuthority ?? null;
  if (authority) assertReleaseSigningConfig(options.config);
  const target = realpathSync.native(resolve(file));
  const identity = inspectSigningObject(target, { ...options, powerShellTool: options.config?.powerShellTool ?? options.powerShellTool });
  const authorization = Object.freeze({
    schemaVersion: 1,
    role: String(role),
    path: target,
    beforeSha256: sha256(target),
    objectIdentity: identity.objectId,
    releaseId: options.releaseId ?? null,
    authorityId: authority?.authorityId ?? null,
    authorityDigest: authority?.digest ?? null,
    authorityExpiresAtUtc: authority?.authorization.expiresAtUtc ?? null,
  });
  if (authority) AUTHENTIC_SIGNING_AUTHORIZATIONS.add(authorization);
  return authorization;
}

export function defaultTauriNsisPluginRoot() {
  return resolve(REPOSITORY_ROOT, "frontend", "src-tauri", "target", "release", "nsis", "x64", "Plugins", "x86-unicode");
}

function consumeSigningAuthorization(file, authorization, options = {}) {
  if (!authorization || !AUTHENTIC_SIGNING_AUTHORIZATIONS.has(authorization) || consumedSigningPlans.has(authorization)) {
    throw new Error("Signing requires one unused authentic artifact authorization.");
  }
  const target = realpathSync.native(resolve(file));
  if (target.toLowerCase() !== resolve(authorization.path).toLowerCase()) throw new Error("Signing target is not the authorized artifact path.");
  if (sha256(target) !== authorization.beforeSha256) throw new Error("Signing target does not match its authorized pre-signing digest.");
  if ((authorization.releaseId ?? null) !== (options.releaseId ?? authorization.releaseId ?? null)) throw new Error("Signing authorization release context changed.");
  assertSameSigningObject(target, authorization, options);
  consumedSigningPlans.add(authorization);
  return target;
}

export function authorizeTauriSigningRequest(file, config, env = process.env, options = {}) {
  const target = realpathSync.native(resolve(file));
  const lower = target.toLowerCase();
  const application = resolve(config.applicationTarget).toLowerCase();
  const installer = resolve(config.installerTarget ?? resolve(REPOSITORY_ROOT, "frontend", "src-tauri", "target", "release", "bundle", "nsis", "Glacial_0.9.12_x64-setup.exe")).toLowerCase();
  const pluginRoot = resolve(config.nsisPluginRoot ?? defaultTauriNsisPluginRoot());
  const pluginNames = new Set(["nsisdl.dll", "startmenu.dll", "system.dll", "nsdialogs.dll"]);
  const additionalPluginRoot = resolve(pluginRoot, "additional");
  const temporaryRoot = resolve(config.temporaryRoot ?? getEnvironmentValue(env, "TEMP") ?? getEnvironmentValue(env, "TMP") ?? "");
  let role = null;
  if (lower === application) role = "application";
  else if (lower === installer) role = "installer";
  else if (resolve(dirname(target)).toLowerCase() === pluginRoot.toLowerCase() && pluginNames.has(basename(target).toLowerCase())) role = `nsis-plugin:${basename(target).toLowerCase()}`;
  else if (resolve(dirname(target)).toLowerCase() === additionalPluginRoot.toLowerCase() && basename(target).toLowerCase() === "nsis_tauri_utils.dll") role = "nsis-plugin:nsis_tauri_utils.dll";
  else if (resolve(dirname(target)).toLowerCase() === temporaryRoot.toLowerCase() && /^nst[0-9a-f]+\.tmp$/i.test(basename(target))) role = "nsis-uninstaller";
  if (!role) throw new Error("Signing target is not a member of the authorized Tauri release artifact set.");
  return exactSigningAuthorization(target, role, { ...options, config, releaseId: config.releaseId ?? null });
}

export function signOne(file, config, options = {}) {
  const authority = assertReleaseSigningConfig(config);
  const trustedOptions = { ...options, powerShellTool: config.powerShellTool, releaseId: config.releaseId ?? options.authorization?.releaseId ?? null };
  const target = consumeSigningAuthorization(file, options.authorization, trustedOptions);
  if (options.authorization?.authorityId !== authority.authorityId
      || options.authorization?.authorityDigest !== authority.digest
      || options.authorization?.authorityExpiresAtUtc !== authority.authorization.expiresAtUtc) {
    throw new Error("Signing authorization is not derived from the current release authority.");
  }
  if (!isPortableExecutable(readFileSync(target))) throw new Error(`Refusing to Authenticode-sign a non-PE file: ${basename(target)}`);
  if (samePath(target, config.applicationTarget) && config.applicationCapture && existsSync(config.applicationCapture)) throw new Error("Refusing a duplicate Glacial application capture.");
  const beforeSha256 = sha256(target);
  const runner = options.runner ?? runCommand;
  if (config.provider === "store") {
    const commandOptions = { env: minimalEnvironment(process.env), timeoutMs: 120_000, includeFailureOutput: true };
    runner(assertAuthenticatedReleaseTool(config.signToolTool), buildStoreSignArgs(config, target), commandOptions);
    runner(assertAuthenticatedReleaseTool(config.signToolTool), buildTimestampArgs(config, target), commandOptions);
  } else {
    runner(assertAuthenticatedReleaseTool(config.signingProviderTool), buildCommandSignArgs(config, target), { env: config.providerEnvironment, timeoutMs: 120_000 });
  }
  const signature = verifySignature(target, config, { expectFirstParty: true, runner, env: options.env });
  const signedSha256 = sha256(target);
  assertSameSigningObject(target, options.authorization, trustedOptions, signedSha256);
  const applicationCapture = captureSignedApplication(target, config, { ...trustedOptions, runner });
  if (applicationCapture && applicationCapture.sha256 !== signedSha256) throw new Error("The Glacial application capture does not match the signed bytes.");
  assertSameSigningObject(target, options.authorization, trustedOptions, signedSha256);
  if (!options.skipAudit) appendAuditRecord(config, { path: target, artifactRole: options.authorization.role, releaseId: options.authorization.releaseId, objectIdentity: options.authorization.objectIdentity, evidenceObjectIdentity: applicationCapture?.objectIdentity ?? null, beforeSha256, sha256: signedSha256, applicationCapturePath: applicationCapture?.path ?? null, signerThumbprint: signature.signerThumbprint, canonicalSubject: signature.canonicalSubject, timestampThumbprint: signature.timestampThumbprint, trustClassification: signature.trustClassification, signedUtc: new Date().toISOString() });
  return signature;
}

export function preflightSigningProvider(config, options = {}) {
  assertReleaseSigningConfig(config);
  const runner = options.runner ?? runCommand;
  const expectedCanonical = canonicalizeDistinguishedName(config.expectedSubject, runner, options.env, config.powerShellTool);
  let storeCertificate = null;
  if (config.provider === "store") {
    const result = invokeWindowsHelper("certificate", { thumbprint: config.certificateThumbprint, expectedSubject: config.expectedSubject }, runner, options.env, config.powerShellTool);
    storeCertificate = assertCertificateIdentity(result.Candidates, config, expectedCanonical);
  }
  const probeParent = options.probeParent ?? resolve(DESKTOP_BUILD_ROOT, "signing-preflight");
  ensureSafeDirectory(DESKTOP_BUILD_ROOT, probeParent, options);
  const probeRoot = resolve(probeParent, `probe-${process.pid}-${Date.now()}`);
  ensureSafeDirectory(DESKTOP_BUILD_ROOT, probeRoot, options);
  const probe = resolve(probeRoot, "Glacial-signing-probe.exe");
  try {
    const source = options.probeSource ?? systemExecutable("System32/where.exe", options.env ?? process.env);
    createUnsignedProbeCopy(source, probe);
    const initialSignature = inspectAuthenticode(probe, runner, options.env, config.powerShellTool);
    if (initialSignature.status !== "NotSigned") throw new Error("The disposable signing probe is not unsigned.");
    const signature = signOne(probe, config, { ...options, skipAudit: true, runner, env: options.env, authorization: exactSigningAuthorization(probe, "preflight-probe", { ...options, config, releaseId: config.releaseId ?? null }) });
    if (signature.canonicalSubject.toUpperCase() !== expectedCanonical) throw new Error("The private-key probe used an unexpected signer subject.");
    return {
      expectedCanonicalSubject: expectedCanonical,
      canonicalSubject: signature.canonicalSubject,
      trustClassification: signature.trustClassification,
      signerThumbprint: signature.signerThumbprint,
      signerNotBeforeUtc: signature.signerNotBeforeUtc,
      signerNotAfterUtc: signature.signerNotAfterUtc,
      codeSigningEku: signature.codeSigningEku,
      timestampThumbprint: signature.timestampThumbprint,
      storeCertificate,
    };
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
  const entries = listPortableExecutables(resolvedRoot).map((path) => ({ path, relativePath: relative(resolvedRoot, path).replaceAll("\\", "/"), embeddedSignature: hasEmbeddedAuthenticode(readFileSync(path)), beforeSha256: sha256(path), signature: inspectAuthenticode(path, runner, options.env, config.powerShellTool) }));
  const plan = planBackendSigning(entries);
  if (!plan.some((entry) => entry.relativePath.toLowerCase() === "glacial-backend.exe")) throw new Error("The PyInstaller payload does not contain glacial-backend.exe.");
  const records = [];
  for (const entry of plan) {
    if (entry.action === "sign-first-party") {
      const signature = signOne(entry.path, config, { ...options, runner, env: options.env, authorization: exactSigningAuthorization(entry.path, `backend:${entry.relativePath}`, { ...options, config, releaseId: config.releaseId ?? null }) });
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

export function signingEnvironment(source, releaseId, auditKey, providerNames = []) {
  if (!Array.isArray(providerNames) || providerNames.some((name) => typeof name !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name))) {
    throw new Error("Authorized signing-provider environment names are invalid.");
  }
  return minimalEnvironment(source, { GLACIAL_WINDOWS_RELEASE_ID: releaseId, GLACIAL_WINDOWS_SIGN_AUDIT_KEY: validateSigningAuditKey(auditKey) }, [...INTERNAL_ENVIRONMENT_NAMES, ...providerNames]);
}

export function signingBrokerEnvironment(source, releaseId, port, token, buildIdentity, backendStageAuthority, cargoHome) {
  return minimalEnvironment(source, {
    GLACIAL_WINDOWS_RELEASE_ID: releaseId,
    GLACIAL_WINDOWS_SIGN_BROKER_PORT: port,
    GLACIAL_WINDOWS_SIGN_BROKER_TOKEN: token,
    GLACIAL_BUILD_IDENTITY_JSON: buildIdentity,
    GLACIAL_BACKEND_STAGE_AUTHORITY_JSON: backendStageAuthority,
    CARGO_HOME: cargoHome,
    CARGO_NET_OFFLINE: "true",
  }, ["GLACIAL_WINDOWS_RELEASE_ID", "GLACIAL_RELEASE_PROFILE", "GLACIAL_WINDOWS_ARTIFACT_SIGNER_CERTIFICATE_PATH",
    "GLACIAL_WINDOWS_RELEASE_AUTHORITY_PATH", "GLACIAL_WINDOWS_RELEASE_AUTHORITY_SIGNATURE_PATH"]);
}

export function requestBrokerSignature(file, env = process.env) {
  const port = Number(getEnvironmentValue(env, "GLACIAL_WINDOWS_SIGN_BROKER_PORT"));
  const token = String(getEnvironmentValue(env, "GLACIAL_WINDOWS_SIGN_BROKER_TOKEN") ?? "");
  if (!Number.isInteger(port) || port < 1 || port > 65535 || !/^[0-9a-f]{64}$/.test(token)) throw new Error("The constrained signing broker is unavailable.");
  return new Promise((resolveRequest, rejectRequest) => {
    const request = httpRequest({ hostname: "127.0.0.1", port, method: "POST", path: "/sign", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" } }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { body += chunk; if (body.length > 16_384) request.destroy(new Error("Signing broker response is too large.")); });
      response.on("end", () => response.statusCode === 200 ? resolveRequest() : rejectRequest(new Error(sanitizeDiagnosticText(body) || "Signing broker rejected the artifact.")));
    });
    request.on("error", rejectRequest);
    request.end(JSON.stringify({ path: resolve(file) }));
  });
}

function printDryRun(config) {
  process.stdout.write(`${JSON.stringify({ provider: config.provider, expectedSubject: config.expectedSubject, expectedThumbprint: config.expectedThumbprint, signToolPath: privacySafePath(config.signToolPath), timestampOrigin: new URL(config.timestampUrl).origin, timestampRequired: true, providerCommand: config.provider === "command" ? `${privacySafePath(config.command)} <reviewed argument array>` : null }, null, 2)}\n`);
}

async function main() {
  const [command, argument] = process.argv.slice(2);
  if (command === "dry-run") { printDryRun(loadSigningConfig(process.env, { dryRun: true })); return; }
  if (command === "sign-request" && argument) { await requestBrokerSignature(argument); return; }
  if (command === "sign-one" && argument) throw new Error("Direct release-role signing is disabled; use the authenticated release coordinator.");
  const { authenticateReleaseTools, loadReleaseAuthority, verifyAuthorizedReleaseCheckout } = await import("../release/release-authority.mjs");
  const authority = loadReleaseAuthority(process.env, { repository: REPOSITORY_ROOT });
  const tools = authenticateReleaseTools(authority, { node: process.execPath });
  verifyAuthorizedReleaseCheckout(authority, tools.git, REPOSITORY_ROOT);
  const profile = String(process.env.GLACIAL_RELEASE_PROFILE ?? "");
  const config = loadSigningConfig(process.env, { authority, tools, profile });
  if (command === "verify-one" && argument) { process.stdout.write(`${JSON.stringify(verifySignature(argument, config, { expectFirstParty: true }), null, 2)}\n`); return; }
  if (command === "verify-tree" && argument) { process.stdout.write(`${JSON.stringify(verifyPayloadTree(argument, config, { requiredFirstParty: process.argv.slice(4) }), null, 2)}\n`); return; }
  throw new Error("Usage: windows-signing.mjs dry-run | sign-one <PE> | verify-one <PE> | verify-tree <directory> [required first-party paths...]");
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(SIGNING_SCRIPT_PATH)) {
  main().catch((error) => { process.stderr.write(`${sanitizeDiagnosticText(error.message)}\n`); process.exitCode = 1; });
}
