from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any


# The native bridge reads at most 16 MiB for the complete HTTP response and
# independently permits at most 64 KiB of headers. Keeping JSON below the
# remainder guarantees that a valid backend response can traverse the bridge.
MAX_NATIVE_BRIDGE_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_NATIVE_BRIDGE_HEADER_BYTES = 64 * 1024 + 4
MAX_NATIVE_BRIDGE_JSON_BYTES = (
    MAX_NATIVE_BRIDGE_RESPONSE_BYTES - MAX_NATIVE_BRIDGE_HEADER_BYTES
)


class BridgeResponseTooLarge(ValueError):
    pass


def serialized_json_bytes(value: object) -> int:
    return len(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def fit_scan_reviewed_files(
    scan: dict[str, Any],
    response_factory: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    response = response_factory()
    if serialized_json_bytes(response) <= MAX_NATIVE_BRIDGE_JSON_BYTES:
        return response

    reviewed_files = list(scan.get("reviewedFiles", []))
    scan["reviewedFilesTruncated"] = True
    scan["reviewedFiles"] = []
    response = response_factory()
    if serialized_json_bytes(response) > MAX_NATIVE_BRIDGE_JSON_BYTES:
        raise BridgeResponseTooLarge(
            "Scan findings and conclusions exceed the supported native bridge response limit."
        )

    low = 0
    high = len(reviewed_files)
    while low <= high:
        retained = (low + high) // 2
        scan["reviewedFiles"] = reviewed_files[:retained]
        candidate = response_factory()
        if serialized_json_bytes(candidate) <= MAX_NATIVE_BRIDGE_JSON_BYTES:
            low = retained + 1
        else:
            high = retained - 1
    scan["reviewedFiles"] = reviewed_files[:high]
    return response_factory()


def fit_history_response(
    scans: list[dict[str, Any]],
    *,
    available_scan_count: int,
) -> dict[str, Any]:
    response: dict[str, Any] = {"scans": scans}
    if serialized_json_bytes(response) <= MAX_NATIVE_BRIDGE_JSON_BYTES:
        return response

    response.update({
        "historyMetadataReduced": True,
        "historyTruncated": False,
        "availableScanCount": available_scan_count,
        "returnedScanCount": len(scans),
    })
    for scan in reversed(scans):
        reviewed_files = list(scan.get("reviewedFiles", []))
        if not reviewed_files:
            continue
        scan["reviewedFilesTruncated"] = True
        scan["scanMetadataReliable"] = False
        scan["reviewedFiles"] = []
        if serialized_json_bytes(response) <= MAX_NATIVE_BRIDGE_JSON_BYTES:
            low = 0
            high = len(reviewed_files)
            while low <= high:
                retained = (low + high) // 2
                scan["reviewedFiles"] = reviewed_files[:retained]
                if serialized_json_bytes(response) <= MAX_NATIVE_BRIDGE_JSON_BYTES:
                    low = retained + 1
                else:
                    high = retained - 1
            scan["reviewedFiles"] = reviewed_files[:high]
            return response

    while len(scans) > 1 and serialized_json_bytes(response) > MAX_NATIVE_BRIDGE_JSON_BYTES:
        scans.pop()
        response["historyTruncated"] = True
        response["returnedScanCount"] = len(scans)

    if serialized_json_bytes(response) > MAX_NATIVE_BRIDGE_JSON_BYTES:
        raise BridgeResponseTooLarge(
            "The newest scan exceeds the supported native bridge response limit without reviewed-file metadata."
        )
    return response
