"""Small, defensive client for the SecureIoT Sentinel backend."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import requests

DEFAULT_BACKEND_URL = "http://127.0.0.1:8000"
TIMEOUT = (3.05, 8.0)


@dataclass
class APIResult:
    """Result of one API request; errors are safe, user-facing summaries."""

    data: Any = None
    error: str | None = None
    status_code: int | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def backend_url() -> str:
    return os.getenv("BACKEND_URL", DEFAULT_BACKEND_URL).rstrip("/")


def _request(path: str, session: requests.Session | None = None) -> APIResult:
    client = session or requests
    url = f"{backend_url()}{path}"
    try:
        response = client.get(url, timeout=TIMEOUT)
    except requests.Timeout:
        return APIResult(error="Backend request timed out.")
    except requests.ConnectionError:
        return APIResult(error="Backend is unreachable.")
    except requests.RequestException:
        return APIResult(error="Backend request failed.")

    if not 200 <= response.status_code < 300:
        return APIResult(error=f"Backend returned HTTP {response.status_code}.", status_code=response.status_code)
    try:
        payload = response.json()
    except (ValueError, requests.exceptions.JSONDecodeError):
        return APIResult(error="Backend returned invalid JSON.", status_code=response.status_code)
    return APIResult(data=payload, status_code=response.status_code)



def validate_health(payload: Any) -> bool:
    """Accept a JSON object as a health document; no undocumented status key is assumed."""
    return isinstance(payload, dict)


def validate_records(payload: Any, collection_keys: tuple[str, ...]) -> list[dict[str, Any]] | None:
    """Extract records from a bare list or a known collection envelope.

    Unknown envelopes and non-object list entries are rejected instead of silently
    coercing backend data. The original record dictionaries are returned unchanged.
    """
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = next((payload[k] for k in collection_keys if isinstance(payload.get(k), list)), None)
        if rows is None:
            return None
    else:
        return None
    if not all(isinstance(row, dict) for row in rows):
        return None
    return rows


def get_health(session: requests.Session | None = None) -> APIResult:
    result = _request("/api/v1/health", session)
    if result.ok and not validate_health(result.data):
        return APIResult(error="Backend health response has an unsupported shape.", status_code=result.status_code)
    return result


def get_devices(session: requests.Session | None = None) -> APIResult:
    result = _request("/api/v1/devices", session)
    if result.ok:
        rows = validate_records(result.data, ("devices", "items", "results"))
        if rows is None:
            return APIResult(error="Backend device response has an unsupported shape.", status_code=result.status_code)
        result.data = rows
    return result


def get_alerts(session: requests.Session | None = None) -> APIResult:
    result = _request("/api/v1/alerts", session)
    if result.ok:
        rows = validate_records(result.data, ("alerts", "items", "results"))
        if rows is None:
            return APIResult(error="Backend alert response has an unsupported shape.", status_code=result.status_code)
        result.data = rows
    return result


def load_snapshot(session: requests.Session | None = None) -> dict[str, APIResult]:
    """Fetch the three documented endpoints once, returning independent outcomes."""
    return {"health": get_health(session), "devices": get_devices(session), "alerts": get_alerts(session)}
