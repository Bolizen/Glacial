import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { sanitizeDiagnosticText } from "./windows-signing.mjs";

const SCRIPT_PATH = fileURLToPath(import.meta.url);

export function rejectDetachedSigningBroker() {
  throw new Error("Detached signing brokers are disabled; private-key operations remain inside the authenticated canonical release coordinator.");
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(SCRIPT_PATH)) {
  try { rejectDetachedSigningBroker(); } catch (error) {
    process.stderr.write(`${sanitizeDiagnosticText(error.message)}\n`);
    process.exitCode = 1;
  }
}
