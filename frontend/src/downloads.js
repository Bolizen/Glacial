import { invoke, isTauri } from "@tauri-apps/api/core";

export async function saveExportBlob(blob, fileName, dependencies = {}) {
  const native = dependencies.isTauriImpl ? dependencies.isTauriImpl() : isTauri();
  if (native) {
    const bytes = Array.from(new Uint8Array(await blob.arrayBuffer()));
    const invokeImpl = dependencies.invokeImpl || invoke;
    const savedName = await invokeImpl("save_export", { fileName, bytes });
    if (typeof savedName !== "string" || !savedName) {
      throw new Error("The native export result is invalid.");
    }
    return { status: "saved", fileName: savedName };
  }

  const documentImpl = dependencies.documentImpl || document;
  const urlImpl = dependencies.urlImpl || URL;
  const url = urlImpl.createObjectURL(blob);
  const link = documentImpl.createElement("a");
  link.href = url;
  link.download = fileName;
  documentImpl.body.appendChild(link);
  link.click();
  link.remove();
  urlImpl.revokeObjectURL(url);
  return { status: "started", fileName };
}
