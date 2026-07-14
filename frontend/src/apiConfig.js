export const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";

export function resolveApiBaseUrl(value) {
  const configured = typeof value === "string" ? value.trim().replace(/\/+$/, "") : "";
  return configured || DEFAULT_API_BASE_URL;
}

const viteEnvironment = typeof import.meta.env === "object" && import.meta.env ? import.meta.env : {};

export const API_BASE_URL = resolveApiBaseUrl(viteEnvironment.VITE_API_BASE_URL);
