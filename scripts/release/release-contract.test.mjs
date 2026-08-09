import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  WINDOWS_RELEASE_PYTHON,
  assertWindowsReleasePythonIdentity,
  currentProductVersion,
} from "./release-contract.mjs";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const validIdentity = {
  implementation: "cpython",
  version: "3.13.13",
  platform: "win32",
  bits: 64,
  machine: "AMD64",
};

test("Windows release contract accepts exactly CPython 3.13.13 x64", () => {
  assert.deepEqual(WINDOWS_RELEASE_PYTHON, {
    name: "CPython",
    implementation: "cpython",
    version: "3.13.13",
    platform: "win32",
    bits: 64,
    machine: "AMD64",
  });
  assert.equal(assertWindowsReleasePythonIdentity(validIdentity), true);
});

for (const [label, override, observed] of [
  ["CPython 3.12.13", { version: "3.12.13" }, "3.12.13"],
  ["a different 3.13 patch", { version: "3.13.12" }, "3.13.12"],
  ["a 32-bit interpreter", { bits: 32, machine: "x86" }, "32-bit x86"],
]) {
  test(`Windows release contract rejects ${label} with actionable diagnostics`, () => {
    assert.throws(
      () => assertWindowsReleasePythonIdentity({ ...validIdentity, ...override }),
      (error) => {
        assert.match(error.message, new RegExp(observed.replaceAll(".", "\\.")));
        assert.match(error.message, /requires CPython 3\.13\.13, architecture 64-bit AMD64/);
        assert.match(error.message, /--python <path-to-python\.exe>/);
        return true;
      },
    );
  });
}

test("current release version derives from package.json while historical evidence stays historical", () => {
  assert.equal(currentProductVersion(repository), "0.9.12");
  assert.match(readFileSync(join(repository, "docs", "release", "g051-documentation-closure.md"), "utf8"), /Audited version: `0\.9\.8`/);
  assert.match(readFileSync(join(repository, "docs", "installed-windows-lifecycle.md"), "utf8"), /Glacial 0\.9\.11/);
});
