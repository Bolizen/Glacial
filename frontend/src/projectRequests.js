export function requestIsCurrent(currentPath, currentGeneration, requestPath, requestGeneration) {
  return currentPath === requestPath && currentGeneration === requestGeneration;
}

export function isAbortError(error) {
  return error?.name === "AbortError";
}
