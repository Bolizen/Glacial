import { createHash } from "node:crypto";

function scalar(value) {
  const trimmed = value.trim();
  if (trimmed.startsWith("'") && trimmed.endsWith("'")) {
    return trimmed.slice(1, -1).replaceAll("''", "'");
  }
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) return JSON.parse(trimmed);
  return trimmed;
}

function importerGroup(lines, group) {
  const importerStart = lines.indexOf("  .:");
  if (importerStart < 0) throw new Error("pnpm lockfile root importer is unavailable.");
  const groupStart = lines.indexOf(`    ${group}:`, importerStart + 1);
  if (groupStart < 0) return {};
  const result = {};
  for (let index = groupStart + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (/^    \S/.test(line) || /^  \S/.test(line) || /^\S/.test(line)) break;
    const packageMatch = line.match(/^      (\S.*):$/);
    if (!packageMatch) continue;
    const name = scalar(packageMatch[1]);
    const entry = {};
    for (index += 1; index < lines.length; index += 1) {
      const detail = lines[index].match(/^        (specifier|version): (.+)$/);
      if (!detail) {
        index -= 1;
        break;
      }
      entry[detail[1]] = scalar(detail[2]);
    }
    result[name] = entry;
  }
  return result;
}

export function readRootImporter(lockText) {
  if (typeof lockText !== "string") throw new Error("pnpm lockfile text is required.");
  const lines = lockText.replaceAll("\r\n", "\n").split("\n");
  return {
    dependencies: importerGroup(lines, "dependencies"),
    devDependencies: importerGroup(lines, "devDependencies"),
  };
}

export function packageVersionKeys(lockText) {
  if (typeof lockText !== "string") throw new Error("pnpm lockfile text is required.");
  const normalized = lockText.replaceAll("\r\n", "\n");
  const start = normalized.indexOf("\npackages:\n");
  const end = normalized.indexOf("\nsnapshots:\n", start + 1);
  if (start < 0 || end < 0) throw new Error("pnpm lockfile package graph is unavailable.");
  const result = new Set();
  for (const line of normalized.slice(start + 11, end).split("\n")) {
    const match = line.match(/^  (\S.*):$/);
    if (!match) continue;
    const key = scalar(match[1]);
    const separator = key.lastIndexOf("@");
    if (separator > 0) result.add(key.slice(0, separator + 1) + key.slice(separator + 1).split("(", 1)[0]);
  }
  return result;
}

export function readTopLevelMap(yamlText, name) {
  if (typeof yamlText !== "string") throw new Error("pnpm workspace settings text is required.");
  const lines = yamlText.replaceAll("\r\n", "\n").split("\n");
  const start = lines.indexOf(`${name}:`);
  if (start < 0) return {};
  const result = {};
  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;
    if (/^\S/.test(line)) break;
    const match = line.match(/^  (\S.*?): (.+)$/);
    if (!match) throw new Error(`Unsupported ${name} setting in pnpm-workspace.yaml.`);
    result[scalar(match[1])] = scalar(match[2]);
  }
  return result;
}

export function resolvedGraphFingerprint(lockText) {
  if (typeof lockText !== "string") throw new Error("pnpm lockfile text is required.");
  const normalized = lockText.replaceAll("\r\n", "\n");
  const start = normalized.indexOf("\npackages:\n");
  if (start < 0) throw new Error("pnpm lockfile package graph is unavailable.");
  return createHash("sha256").update(normalized.slice(start)).digest("hex").toUpperCase();
}
