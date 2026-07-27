import { invoke, isTauri } from "@tauri-apps/api/core";

import { API_BASE_URL } from "./apiConfig.js";
import { safeErrorMessage } from "./privacy.js";


const API_BRIDGE_COMMAND = "api_request";


export function createApiRequester(dependencies = {}) {
  return async function requestApi(path, options = {}) {
    const method = String(options.method || "GET").toUpperCase();
    const useTauri = dependencies.isTauriImpl ? dependencies.isTauriImpl() : isTauri();
    let status;
    let data;

    if (useTauri) {
      const invokeImpl = dependencies.invokeImpl || invoke;
      let response;
      try {
        response = await withAbort(
          invokeImpl(API_BRIDGE_COMMAND, {
            path,
            method,
            body: options.body ?? null,
          }),
          options.signal,
        );
      } catch (error) {
        if (error?.name === "AbortError") {
          throw error;
        }
        throw error instanceof Error
          ? new Error(safeErrorMessage(error.message))
          : new Error(safeErrorMessage(error));
      }
      status = response?.status;
      data = response && Object.hasOwn(response, "body") ? response.body : {};
    } else {
      const fetchImpl = dependencies.fetchImpl || globalThis.fetch;
      const baseUrl = dependencies.baseUrl || API_BASE_URL;
      let response;
      try {
        response = await fetchImpl(`${baseUrl}${path}`, {
          method,
          signal: options.signal,
          headers: options.body ? { "Content-Type": "application/json" } : undefined,
          body: options.body ? JSON.stringify(options.body) : undefined,
        });
      } catch (error) {
        if (error?.name === "AbortError") throw error;
        throw new Error(safeErrorMessage(error?.message));
      }
      status = response.status;
      data = await response.json().catch(() => ({}));
    }

    if (!Number.isInteger(status) || status < 200 || status > 299) {
      throw new Error(safeErrorMessage(data?.detail));
    }
    return data;
  };
}


function withAbort(promise, signal) {
  if (!signal) {
    return promise;
  }
  if (signal.aborted) {
    return Promise.reject(abortError());
  }
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(abortError());
    signal.addEventListener("abort", onAbort, { once: true });
    Promise.resolve(promise).then(resolve, reject).finally(() => {
      signal.removeEventListener("abort", onAbort);
    });
  });
}


function abortError() {
  const error = new Error("The request was aborted.");
  error.name = "AbortError";
  return error;
}


export const requestApi = createApiRequester();
