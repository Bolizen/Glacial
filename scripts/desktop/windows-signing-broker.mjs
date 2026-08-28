import { timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseInjectedBuildIdentity } from "../release/build-identity.mjs";
import {
  authenticateReleaseTools,
  loadReleaseAuthority,
  verifyAuthorizedReleaseCheckout,
} from "../release/release-authority.mjs";
import { assertNoNodeRuntimeInjection, assertReleaseCoordinatorParent, authorizeTauriSigningRequest, loadSigningConfig, sanitizeDiagnosticText, signOne } from "./windows-signing.mjs";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
assertNoNodeRuntimeInjection(process.env);
const token = String(process.env.GLACIAL_WINDOWS_SIGN_BROKER_TOKEN ?? "");
if (!/^[0-9a-f]{64}$/.test(token)) throw new Error("Signing broker token is invalid.");
const authority = loadReleaseAuthority(process.env, { repository });
const tools = authenticateReleaseTools(authority, { node: process.execPath });
verifyAuthorizedReleaseCheckout(authority, tools.git, repository);
const identity = parseInjectedBuildIdentity(process.env);
if (!identity || identity.sourceCommit !== authority.source.commit) throw new Error("Signing broker build identity is not authorized.");
const profile = String(process.env.GLACIAL_RELEASE_PROFILE ?? "");
if (identity.buildProfile !== profile) throw new Error("Signing broker release profile is inconsistent.");
const config = loadSigningConfig(process.env, { authority, tools, profile });
assertReleaseCoordinatorParent(config, resolve(repository, "..", "scripts", "release", "validate-clean-environment.mjs"));
if (!String(config.releaseId ?? "").includes(`-${authority.source.commit.slice(0, 12)}-`)) throw new Error("Signing broker release id is not source-bound.");
const usedRoles = new Set();
let complete = false;

function authorized(header) {
  const supplied = Buffer.from(String(header ?? "").replace(/^Bearer /, ""), "utf8");
  const expected = Buffer.from(token, "utf8");
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

function consumeRole(role) {
  if (complete || usedRoles.has(role)) throw new Error("Signing request has unexpected role cardinality.");
  if (role === "installer") {
    const required = ["application", "nsis-uninstaller", "nsis-plugin:nsisdl.dll", "nsis-plugin:startmenu.dll", "nsis-plugin:system.dll", "nsis-plugin:nsdialogs.dll", "nsis-plugin:nsis_tauri_utils.dll"];
    if (required.some((item) => !usedRoles.has(item))) throw new Error("Installer signing request arrived before the authorized artifact set was complete.");
    complete = true;
  }
  usedRoles.add(role);
}

const server = createServer((request, response) => {
  if (request.method !== "POST" || request.url !== "/sign" || !authorized(request.headers.authorization)) { response.writeHead(403); response.end("Signing request is unauthorized."); return; }
  let body = "";
  request.setEncoding("utf8");
  request.on("data", (chunk) => { body += chunk; if (body.length > 4096) request.destroy(); });
  request.on("end", () => {
    try {
      const payload = JSON.parse(body);
      const authorization = authorizeTauriSigningRequest(resolve(String(payload.path ?? "")), config, process.env);
      consumeRole(authorization.role);
      signOne(authorization.path, config, { authorization });
      response.writeHead(200); response.end("signed");
    } catch (error) { response.writeHead(400); response.end(sanitizeDiagnosticText(error.message)); }
  });
});

server.listen(0, "127.0.0.1", () => {
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Signing broker failed to bind loopback.");
  process.send?.({ type: "ready", port: address.port });
});
process.on("message", (message) => { if (message?.type === "close") server.close(() => process.exit(complete ? 0 : 1)); });
