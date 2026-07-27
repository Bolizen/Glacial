const PRIVATE_KEY = /-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----[\s\S]*?(?:-----END(?: [A-Z0-9]+)* PRIVATE KEY-----|$)/gi;
const AUTHORIZATION = /(["']?\bauthorization\b["']?\s*[:=]\s*)[^\r\n]+/gi;
const BEARER = /\bbearer\s+[A-Z0-9._~+/=-]+/gi;
const CREDENTIAL_URL = /([A-Z][A-Z0-9+.-]*:\/\/)(?:[^/\s:@]+):(?:[^@\s/]+)@/gi;
const CREDENTIAL_ASSIGNMENT = /(["']?\b(?:[A-Z0-9_.-]*(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|pwd|secret|private[_-]?key)[A-Z0-9_.-]*)\b["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}\])]+)/gim;
const CONNECTION_SECRET = /(\b(?:password|passwd|pwd|user\s*id|uid)\s*=\s*)[^;\s]+/gi;
const AWS_ACCESS_KEY = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g;
const GITHUB_TOKEN = /\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b/gi;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
const LONG_TOKEN = /(^|[^A-Za-z0-9])([A-Za-z0-9._~+/=-]{32,})(?=$|[^A-Za-z0-9])/g;

const EXTENDED_WINDOWS_PATH = /(^|[^A-Za-z0-9])\\\\\?\\(?:UNC\\[^\\/\s"'<>|]+\\[^\\/\s"'<>|]+|[A-Za-z]:\\)[^\r\n\t"'<>|]*/gi;
const UNC_PATH = /(^|[^A-Za-z0-9])\\\\[^\\/\s"'<>|]+\\[^\\/\s"'<>|]+(?:[\\/][^\r\n\t"'<>|]*)?/gi;
const WINDOWS_PATH = /(^|[^A-Za-z0-9])(?:[A-Za-z]:[\\/])[^\r\n\t"'<>|]*/gi;
const POSIX_PATH = /(^|[^A-Za-z0-9:])\/(?:Users|home|tmp|var\/tmp|private\/tmp|opt|srv|mnt|media)\/[^\r\n\t"'<>|]*/gi;


export function redactSecretValues(value) {
  let text = normalizeControls(value);
  text = text
    .replace(PRIVATE_KEY, "[REDACTED PRIVATE KEY]")
    .replace(CREDENTIAL_URL, "$1[REDACTED]@")
    .replace(AUTHORIZATION, "$1[REDACTED]")
    .replace(BEARER, "Bearer [REDACTED]")
    .replace(CREDENTIAL_ASSIGNMENT, "$1[REDACTED]")
    .replace(CONNECTION_SECRET, "$1[REDACTED]")
    .replace(AWS_ACCESS_KEY, "[REDACTED]")
    .replace(GITHUB_TOKEN, "[REDACTED]")
    .replace(JWT, "[REDACTED]");
  return text.replace(LONG_TOKEN, (match, prefix, token) => (
    shouldRedactLongToken(token) ? `${prefix}[REDACTED]` : match
  ));
}


export function replaceAbsolutePaths(value) {
  return normalizeControls(value)
    .replace(/(^|[^A-Za-z0-9])(?:[A-Za-z]:[\\/])Users[\\/][^\\/\s"'<>|]+/gi, "$1<USER_PROFILE>")
    .replace(/<USER_PROFILE>[\\/]AppData[\\/]Local[\\/]Temp(?:[\\/][^\r\n\t"'<>|]*)?/gi, "<TEMP_DIR>")
    .replace(EXTENDED_WINDOWS_PATH, "$1<HOST_PATH>")
    .replace(UNC_PATH, "$1<HOST_PATH>")
    .replace(WINDOWS_PATH, "$1<HOST_PATH>")
    .replace(POSIX_PATH, "$1<HOST_PATH>");
}


export function sanitizeDisclosureText(value, limit = 4000, { preserveLines = false } = {}) {
  let text = replaceAbsolutePaths(redactSecretValues(value));
  text = preserveLines
    ? text.split("\n").map((line) => line.replace(/\s+/g, " ").trim()).join("\n")
    : text.replace(/\s+/g, " ").trim();
  return text.slice(0, Math.max(0, limit));
}


export function safeErrorMessage(value, fallback = "Request failed.") {
  return sanitizeDisclosureText(value, 300) || fallback;
}


function normalizeControls(value) {
  return String(value ?? "")
    .replace(/\r\n?/g, "\n")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "\uFFFD");
}


function shouldRedactLongToken(value) {
  if (/^[0-9a-f]{40,128}$/i.test(value)) return false;
  if (/^(?:sha(?:256|384|512)[:_-]|cf[a-z0-9]*_)/i.test(value)) return false;
  const characters = new Set(value.toLowerCase());
  const hasLetter = /[A-Za-z]/.test(value);
  const hasDigit = /[0-9]/.test(value);
  return characters.size >= 10 && hasLetter && hasDigit;
}
