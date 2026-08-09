import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  parseInventoryArguments,
  pythonRuntime,
} from "./generate-third-party-inventory.mjs";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

function fixture(t) {
  const root = mkdtempSync(join(repository, ".g078-inventory-test-"));
  const sitePackages = join(root, "Lib", "site-packages");
  mkdirSync(sitePackages, { recursive: true });
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return { root, sitePackages };
}

function metadata(sitePackages, name, version, license = "MIT") {
  const directory = join(sitePackages, `${name.replaceAll(/[-.]/g, "_")}-${version}.dist-info`);
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, "METADATA"), `Metadata-Version: 2.4\nName: ${name}\nVersion: ${version}\nLicense-Expression: ${license}\n`, "utf8");
}

const requirements = "demo-package==1.2.3\n";

test("inventory validation targets explicitly supplied Python site-packages", (t) => {
  const { sitePackages } = fixture(t);
  metadata(sitePackages, "demo-package", "1.2.3");
  metadata(sitePackages, "pip", "25.0.1");
  const options = parseInventoryArguments(["--check", "--python-site-packages", sitePackages]);
  assert.equal(options.check, true);
  assert.equal(options.pythonSitePackages, sitePackages);
  assert.deepEqual(pythonRuntime(options.pythonSitePackages, requirements), [
    { name: "demo-package", version: "1.2.3", license: "MIT" },
  ]);
});

test("missing explicitly supplied site-packages fails clearly", (t) => {
  const { root } = fixture(t);
  assert.throws(
    () => parseInventoryArguments(["--python-site-packages", join(root, "missing")]),
    /Python site-packages is unavailable/,
  );
});

test("installed Python package version mismatch fails", (t) => {
  const { sitePackages } = fixture(t);
  metadata(sitePackages, "demo-package", "1.2.2");
  assert.throws(() => pythonRuntime(sitePackages, requirements), /metadata is 1\.2\.2; expected 1\.2\.3/);
});

test("missing expected Python metadata fails", (t) => {
  const { sitePackages } = fixture(t);
  metadata(sitePackages, "pip", "25.0.1");
  assert.throws(() => pythonRuntime(sitePackages, requirements), /No Python metadata found for demo-package/);
});

test("valid installed Python metadata passes", (t) => {
  const { sitePackages } = fixture(t);
  metadata(sitePackages, "demo-package", "1.2.3", "Apache-2.0");
  assert.deepEqual(pythonRuntime(sitePackages, requirements), [
    { name: "demo-package", version: "1.2.3", license: "Apache-2.0" },
  ]);
});

test("explicit clean-validation metadata never falls back to unrelated developer state", (t) => {
  const { root, sitePackages } = fixture(t);
  const developerSitePackages = join(root, "developer", "Lib", "site-packages");
  mkdirSync(developerSitePackages, { recursive: true });
  metadata(developerSitePackages, "demo-package", "1.2.3");
  assert.throws(() => pythonRuntime(sitePackages, requirements), /No Python metadata found for demo-package/);
});

test("unexpected installed Python metadata fails closed", (t) => {
  const { sitePackages } = fixture(t);
  metadata(sitePackages, "demo-package", "1.2.3");
  metadata(sitePackages, "unlocked-package", "9.9.9");
  assert.throws(() => pythonRuntime(sitePackages, requirements), /Unexpected Python metadata found: unlocked_package/);
});
