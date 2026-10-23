# SecureIoT Sentinel — Security Detection Engine

This module is a small FastAPI backend for observing device messages and raising
deterministic policy or behavior alerts. It does not use an AI classifier and
does not require physical ESP32 hardware.

## Architecture

- `app/registry.py` stores which device IDs are authorized. Registration is
  distinct from observed activity.
- `app/detector.py` tracks server-side rolling observations and applies the
  three independent detection rules.
- `app/alert_store.py` assigns increasing alert IDs and keeps a bounded,
  in-memory history.
- `app/main.py` exposes the API. Its ASGI middleware measures the raw message
  request-body bytes and enforces the maximum before FastAPI parses JSON.
- `app/config.py` validates settings, and `app/schemas.py` defines request and
  response models.

An unregistered device is a policy violation, not conclusive proof of malicious
intent. Alert severity and summaries are demonstration choices, not a universal
severity standard.

## Windows PowerShell setup

From the project root:

```powershell
Set-Location .\security_engine
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

If PowerShell blocks virtual-environment activation, use
`.\.venv\Scripts\python.exe -m pip install -r requirements.txt`,
`.\.venv\Scripts\python.exe -m pytest`, and
`.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000`
instead.

For same-laptop testing, use `http://127.0.0.1:8000`. To allow an ESP32 or other
device on the same network to connect, start the server with:

```powershell
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Find the laptop's LAN IPv4 address by running `ipconfig` and reading the IPv4
Address under the active Wi-Fi adapter. The other device should use that LAN
address, for example `http://192.168.x.x:8000`, not `127.0.0.1` (which always
refers to the device making the request). Allow inbound TCP port 8000 in Windows
Firewall for the appropriate private network profile. The Wi-Fi access point or
router must also allow clients to communicate; guest Wi-Fi and client/AP
isolation can block device-to-laptop traffic.

## Sending a sample request from PowerShell

With the server running locally:

```powershell
$body = @{
    device_id = "CCTV-ESP32-01"
    device_type = "cctv_simulator"
    message_id = "msg-0001"
    timestamp_ms = 1790000000000
    data = @{
        status = "online"
        activity = "heartbeat"
    }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post `
    -Uri "http://127.0.0.1:8000/api/v1/messages" `
    -ContentType "application/json" `
    -Body $body
```

## Configuration and defaults

`Settings` in `app/config.py` can be passed to `create_app()` in tests or other
Python code. The standalone server reads these optional environment variables:

| Environment variable | Default | Meaning |
| --- | ---: | --- |
| `SECURITY_ENGINE_MESSAGE_WINDOW_SECONDS` | `10` | Rolling message-count window |
| `SECURITY_ENGINE_MESSAGE_THRESHOLD` | `20` | Alert when count is greater than this |
| `SECURITY_ENGINE_VOLUME_WINDOW_SECONDS` | `10` | Rolling received-body-byte window |
| `SECURITY_ENGINE_VOLUME_THRESHOLD_BYTES` | `10240` | Alert when total is greater than this |
| `SECURITY_ENGINE_UNREGISTERED_COOLDOWN_SECONDS` | `60` | Repeat interval for unregistered-device alerts |
| `SECURITY_ENGINE_BEHAVIORAL_COOLDOWN_SECONDS` | `60` | Repeat interval while a behavioral rule stays active |
| `SECURITY_ENGINE_ALERT_HISTORY_LIMIT` | `1000` | Maximum alerts retained in memory |
| `SECURITY_ENGINE_MAX_REQUEST_BODY_BYTES` | `65536` | Maximum raw body size accepted by the message endpoint |

The 10 KiB volume threshold and 10-second window are demonstration settings, not
universal security limits. Request size means the HTTP request-body bytes
received by the application; it does not include headers, transport framing, or
all network traffic.

The initial registry contains `CCTV-ESP32-01` with type `cctv_simulator`.
Change authorized devices without changing detection rules by creating a
`DeviceRegistry` and passing it to `create_app`, or by calling
`register(device_id, device_type)` on the engine's registry. For example:

```python
from app.main import create_app
from app.registry import DeviceRegistry

registry = DeviceRegistry({"CCTV-ESP32-01": "cctv_simulator"})
registry.register("door-sensor-01", "door_sensor")
app = create_app(registry=registry)
```

Every registry instance, observation, cooldown, alert ID counter, and alert
history is in memory. It is lost when the process restarts; this prototype
does not use SQLite or other persistent storage. Each `create_app()` call
creates fresh isolated engine state. Every HTTP message request counts as a
message, even if its `message_id` repeats; message IDs do not authenticate a
device.

## API schemas

### `GET /api/v1/health`

Response:

```json
{"status": "ok"}
```

### `POST /api/v1/messages`

All fields are required. `timestamp_ms` must be a non-negative integer, and
`data` must be a JSON object. String fields have maximum lengths; unexpected
fields are rejected. Invalid JSON or field values return HTTP 422. A body
larger than the configured raw-body limit returns HTTP 413.

Request:

```json
{
  "device_id": "CCTV-ESP32-01",
  "device_type": "cctv_simulator",
  "message_id": "msg-0001",
  "timestamp_ms": 1790000000000,
  "data": {"status": "online", "activity": "heartbeat"}
}
```

Response (the `alerts` array contains only alerts newly generated by this
request):

```json
{
  "device_id": "CCTV-ESP32-01",
  "registered": true,
  "message_id": "msg-0001",
  "received_at_ms": 1790000001000,
  "request_size_bytes": 178,
  "observations": {
    "messages_in_window": 1,
    "message_window_seconds": 10.0,
    "bytes_in_window": 178,
    "byte_window_seconds": 10.0
  },
  "alerts": []
}
```

`received_at_ms` and behavioral windows use server receipt time. The
device-provided `timestamp_ms` is validated but never used for rate or volume
calculations.

### Alert object

Both message responses and the alerts endpoint use this shape. `evidence`
contains the server-observed count/byte total, window, and configured threshold
for the applicable rule.

```json
{
  "alert_id": "ALT-0001",
  "device_id": "CCTV-ESP32-01",
  "category": "HIGH_MESSAGE_RATE",
  "severity": "HIGH",
  "evidence": {
    "messages_in_window": 21,
    "window_seconds": 10,
    "threshold": 20
  },
  "summary": "Message frequency exceeded the configured threshold.",
  "timestamp_ms": 1790000001000
}
```

Categories are `UNREGISTERED_DEVICE`, `HIGH_MESSAGE_RATE`, and
`HIGH_DATA_VOLUME`. Unregistered-device alerts use `MEDIUM`; behavioral
threshold alerts use `HIGH`. These are chosen for this demonstration.

### `GET /api/v1/devices`

Returns the union of registered and observed IDs. `registered` and `authorized`
are equivalent authorization indicators; `device_type` is null for an unknown
ID. An authorized but not-yet-observed device has `last_seen_ms: null`.

```json
{
  "devices": [
    {
      "device_id": "CCTV-ESP32-01",
      "device_type": "cctv_simulator",
      "registered": true,
      "authorized": true,
      "last_seen_ms": null,
      "messages_in_window": 0,
      "bytes_in_window": 0
    }
  ],
  "count": 1
}
```

### `GET /api/v1/alerts`

Alerts are newest first. The optional `limit` is an integer from 1 through
1000, defaulting to 100. `count` is the number returned (not the lifetime
number of alerts).

```json
{"alerts": [], "count": 0}
```

## Limitations

This is a learning prototype, not a production security system. It has no
cryptographic device authentication, no TLS configuration, and only
process-local observations and alert history. A device ID and message ID are
untrusted values, and an unregistered alert does not establish malicious
intent. The in-memory alert list is bounded and resets with the process.
