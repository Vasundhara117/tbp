# SecureIoT Sentinel — Security Detection Engine

This module is a small FastAPI backend for observing device messages and raising
deterministic policy or behavior alerts. It does not use an AI classifier and
does not require physical ESP32 hardware.

## Architecture

- `app/registry.py` stores which device IDs are authorized. Registration is
  distinct from observed activity.
- `app/detector.py` tracks server-side rolling observations and applies
  deterministic authorization, rate, volume, and configured destination rules.
- `app/observers.py` provides repeatable simulated events and an optional,
  explicitly controlled Scapy passive-capture provider.
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
| `SECURITY_ENGINE_MAX_REQUEST_BODY_BYTES` | `65536` | Maximum raw body size accepted by message and observation endpoints |
| `SECURITY_ENGINE_PASSIVE_CAPTURE_ENABLED` | `false` | Opt in to the loopback-only passive-capture controls |
| `SECURITY_ENGINE_PASSIVE_CAPTURE_INTERFACE` | unset | Scapy interface name selected for explicit capture |

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

## Independent network observations

`POST /api/v1/observations` accepts metadata independently of
`POST /api/v1/messages`. The validated observation can include an application
device ID, MAC/IP addresses, a source and timestamp, device-type hint,
message/packet and byte counts, destination IP, protocol, and a `simulated`
flag. Payload contents are not part of the observation model. The endpoint
updates the same in-memory inventory and alert pipeline used by messages.

The matching order is explicit:

1. A supplied `device_id` matches that registry ID. It is a caller-supplied
   label, not proof of physical identity.
2. Without a `device_id`, a MAC address matches a registered device only when
   that address was explicitly mapped in the trusted registry.
3. An unregistered MAC gets a MAC-keyed record. An observation with neither a
   device ID nor MAC gets its own record; IP-only observations are never merged
   based on the IP address.

MACs may be spoofed or randomized, and an IP address may be reassigned. Even a
trusted MAC mapping is an allowlist hint, not cryptographic authentication or
conclusive spoofing detection. Registry ID authorization remains compatible
with the original message API. The ingestion endpoint accepts caller-supplied
`source` and `simulated` values, so these are provenance labels rather than
cryptographic attestations. The synthetic demonstration route itself generates
and marks its own records.

Configure a MAC allowlist through the existing `DeviceRegistry`:

```python
from app.main import create_app
from app.registry import DeviceRegistry

registry = DeviceRegistry(
    {"CCTV-ESP32-01": "cctv_simulator"},
    mac_addresses={"02:00:00:00:00:01": "CCTV-ESP32-01"},
    expected_destinations={
        "CCTV-ESP32-01": {"192.0.2.5", "198.51.100.10"}
    },
)
app = create_app(registry=registry)
```

An `UNEXPECTED_DESTINATION` alert is generated only for devices with a
configured destination allowlist and observations that actually contain a
destination IP. With no allowlist, destination metadata is recorded but is not
classified as unexpected.

For a safe, deterministic demonstration, start the backend and submit:

```powershell
Invoke-RestMethod -Method Post `
    -Uri "http://127.0.0.1:8000/api/v1/monitoring/synthetic/next"
```

Repeated calls alternate between a trusted demonstration device and an
untrusted one. Every such record has `simulated: true` and the source
`synthetic_demo`; its observation `timestamp_ms` is generated from the current
provider clock at event creation, not a fixed historical demo date. This is
generated demonstration data, not network discovery.
Check `/api/v1/monitoring/status` for provider capability and state, and inspect
`/api/v1/devices` and `/api/v1/alerts` for the resulting inventory and alerts.
An untrusted observed device is alerted even if it never submits an HTTP
heartbeat.

When supplied, an observation's `timestamp_ms` is its event time and is
returned with the ingestion response. It is also retained as
`observation_timestamp_ms` evidence. Alert `timestamp_ms` and inventory
`first_seen_ms`/`last_seen_ms` represent backend receipt time; receipt time and
the monotonic clock drive activity windows and cooldowns. Synthetic event time
is set at creation, so it should be close to receipt time. This distinction
also applies to delayed observations, for which event and alert times may
differ. No router/AP client-list provider is included because no authorized
router interface is configured for this project.

Unauthorized-device alerts are deduplicated per device and alert category for
`SECURITY_ENGINE_UNREGISTERED_COOLDOWN_SECONDS` (60 seconds by default).
Different device records have independent cooldowns, and behavioral alert
categories use their own rule state and cooldowns. After the unauthorized
cooldown expires, another observation can generate a new unauthorized alert.
This is a notification-rate policy, not suppression of the underlying
observations or inventory updates.

Evidence is limited to fields present in the observation. For example,
destination IP and protocol are included when observed and omitted when
unavailable. `UNREGISTERED_DEVICE` is an authorization-policy alert, not a
threshold rule, so it does not claim a measurement threshold or fabricate one.

## Optional passive monitoring

Passive capture is not installed as a dependency and never starts when the API
launches. To try it, install Scapy in the backend environment, choose an
interface supported by the local platform, then opt in before starting the
backend:

```powershell
python -m pip install scapy
$env:SECURITY_ENGINE_PASSIVE_CAPTURE_ENABLED = "true"
$env:SECURITY_ENGINE_PASSIVE_CAPTURE_INTERFACE = "Wi-Fi"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

On Windows, packet capture generally requires Npcap and appropriate
permissions; interface names and support depend on the local Scapy/Npcap
installation. On other platforms, capture permissions and interface selection
also depend on the OS. The loopback-only controls explicitly start and stop
capture:

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/monitoring/passive/start"
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/monitoring/passive/stop"
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/monitoring/status"
```

Capture-control requests are rejected unless the opt-in setting is enabled and
the caller is connected over loopback. Missing Scapy, interface errors, or
permission/platform failures are reported in the API response and monitoring
status instead of being started automatically. Captured records contain only
packet metadata (addresses, protocol, packet count, and observed byte length),
not payload contents. The passive provider is optional and has not been
validated on this host; do not treat its availability status as proof that the
selected interface can capture.

Observation packet counts use the configured message-rate threshold and
window; observed byte totals share the existing configured rolling volume
threshold with application request-body bytes. Alerts retain source,
simulation state, measured values, thresholds, and observed network metadata.
Repeated alerts use the existing cooldown/deduplication behavior.

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
