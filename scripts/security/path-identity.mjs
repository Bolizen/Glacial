import { lstatSync, readlinkSync, realpathSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

function objectIdentity(metadata) {
  return Object.freeze({ dev: metadata.dev, ino: metadata.ino });
}

function identitiesEqual(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

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

export function captureTrustedCargoExecutable(cargoHome, options = {}) {
  const platform = options.platform ?? process.platform;
  const inspectLink = options.inspectLink ?? ((path) => lstatSync(path, { bigint: true }));
  const inspectTarget = options.inspectTarget ?? ((path) => statSync(path, { bigint: true }));
  const readLink = options.readLink ?? readlinkSync;
  const home = resolve(cargoHome);
  const bin = join(home, "bin");
  const cargo = join(bin, platform === "win32" ? "cargo.exe" : "cargo");
  const rustup = join(bin, platform === "win32" ? "rustup.exe" : "rustup");

  for (const path of [home, bin]) {
    let metadata;
    try { metadata = inspectLink(path); } catch { throw new Error("the trusted Cargo executable was not found in the trusted Cargo home"); }
    if (metadata.isSymbolicLink()) throw new Error("the trusted Cargo executable parent path must not contain symbolic links");
    if (!metadata.isDirectory()) throw new Error("the trusted Cargo executable parent path has an unexpected type");
  }

  let cargoPathObject;
  try { cargoPathObject = inspectLink(cargo); } catch { throw new Error("the trusted Cargo executable was not found in the trusted Cargo home"); }
  let kind = "direct";
  if (cargoPathObject.isSymbolicLink()) {
    kind = "rustup-symlink-proxy";
    let rustupPathObject;
    try { rustupPathObject = inspectLink(rustup); } catch { throw new Error("the trusted Cargo symlink proxy requires the sibling rustup executable"); }
    if (rustupPathObject.isSymbolicLink() || !rustupPathObject.isFile()) {
      throw new Error("the trusted Cargo symlink proxy requires a real sibling rustup executable");
    }
    let linkTarget;
    try { linkTarget = readLink(cargo); } catch { throw new Error("the trusted Cargo symlink proxy target could not be inspected"); }
    if (resolve(bin, linkTarget) !== rustup) {
      throw new Error("the trusted Cargo symlink proxy must point directly to the sibling rustup executable");
    }
    let cargoTarget;
    let rustupTarget;
    try {
      cargoTarget = inspectTarget(cargo);
      rustupTarget = inspectTarget(rustup);
    } catch {
      throw new Error("the trusted Cargo symlink proxy target could not be inspected");
    }
    if (!cargoTarget.isFile() || !rustupTarget.isFile() || !identitiesEqual(objectIdentity(cargoTarget), objectIdentity(rustupTarget))) {
      throw new Error("the trusted Cargo symlink proxy must resolve to the sibling rustup executable object");
    }
  } else if (!cargoPathObject.isFile()) {
    throw new Error("the trusted Cargo executable path has an unexpected type");
  }

  let effectiveObject;
  try { effectiveObject = inspectTarget(cargo); } catch { throw new Error("the trusted Cargo executable target could not be inspected"); }
  if (!effectiveObject.isFile()) throw new Error("the trusted Cargo executable target has an unexpected type");
  return Object.freeze({
    path: cargo,
    kind,
    pathObject: objectIdentity(cargoPathObject),
    effectiveObject: objectIdentity(effectiveObject),
  });
}

export function revalidateTrustedCargoExecutable(record, cargoHome, options = {}) {
  const current = captureTrustedCargoExecutable(cargoHome, options);
  if (
    !record ||
    record.path !== current.path ||
    record.kind !== current.kind ||
    !identitiesEqual(record.pathObject ?? {}, current.pathObject) ||
    !identitiesEqual(record.effectiveObject ?? {}, current.effectiveObject)
  ) {
    throw new Error("the trusted Cargo executable identity changed after selection");
  }
  return current.path;
}
