import assert from "node:assert/strict";
import test from "node:test";

import { saveExportBlob } from "./downloads.js";

test("native exports send only the generated filename and exact bytes to the Tauri host", async () => {
  const calls = [];
  const result = await saveExportBlob(
    new Blob(["bounded report"], { type: "text/markdown" }),
    "scan-report.md",
    {
      isTauriImpl: () => true,
      invokeImpl: async (command, argumentsValue) => {
        calls.push({ command, argumentsValue });
        return "scan-report (1).md";
      },
    },
  );

  assert.deepEqual(calls, [{
    command: "save_export",
    argumentsValue: {
      fileName: "scan-report.md",
      bytes: [...Buffer.from("bounded report")],
    },
  }]);
  assert.deepEqual(result, { status: "saved", fileName: "scan-report (1).md" });
});

test("native export rejects a malformed host response", async () => {
  await assert.rejects(
    saveExportBlob(new Blob(["report"]), "scan-report.md", {
      isTauriImpl: () => true,
      invokeImpl: async () => null,
    }),
    /native export result is invalid/,
  );
});
