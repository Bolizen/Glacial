export function requestIsCurrent(currentPath, currentGeneration, requestPath, requestGeneration) {
  return currentPath === requestPath && currentGeneration === requestGeneration;
}

export function scopedRequestIsCurrent(
  latestRequestId,
  requestId,
  currentPath,
  currentGeneration,
  requestPath,
  requestGeneration,
) {
  return latestRequestId === requestId && requestIsCurrent(
    currentPath,
    currentGeneration,
    requestPath,
    requestGeneration,
  );
}

export function shouldReloadSelectedProjectAfterMutation(
  currentPath,
  currentGeneration,
  requestPath,
  requestGeneration,
) {
  return currentPath === requestPath && currentGeneration !== requestGeneration;
}

export function projectListResponsePolicy(
  latestRequestId,
  requestId,
  currentPath,
  currentGeneration,
  requestPath,
  requestGeneration,
) {
  const applyData = latestRequestId === requestId;
  const applySelection = applyData && (
    requestPath === null
    || requestIsCurrent(
      currentPath,
      currentGeneration,
      requestPath,
      requestGeneration,
    )
  );
  return { applyData, applySelection };
}

export function isAbortError(error) {
  return error?.name === "AbortError";
}
