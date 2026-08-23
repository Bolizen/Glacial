import { realpathSync, statSync } from "node:fs";

export function canonicalPathsEqual(left, right, options = {}) {
  const canonicalize = options.canonicalize ?? realpathSync.native;
  const platform = options.platform ?? process.platform;
  const leftPath = canonicalize(left);
  const rightPath = canonicalize(right);
  return platform === "win32"
    ? leftPath.toLowerCase() === rightPath.toLowerCase()
    : leftPath === rightPath;
}

export function sameFilesystemObject(left, right, options = {}) {
  const inspect = options.inspect ?? ((path) => statSync(path, { bigint: true }));
  const leftObject = inspect(left);
  const rightObject = inspect(right);
  return leftObject.dev === rightObject.dev && leftObject.ino === rightObject.ino;
}
