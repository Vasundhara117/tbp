import time

from fastapi.testclient import TestClient

from app.config import Settings
from app.device_control import DeviceCommandController
from app.main import create_app


TOKEN = "test-device-control-token"


def _client(token: str | None = TOKEN, client: tuple[str, int] = ("127.0.0.1", 12345)) -> TestClient:
    return TestClient(
        create_app(Settings(device_control_token=token)),
        client=client,
    )


def _heartbeat(client: TestClient) -> None:
    response = client.post(
        "/api/v1/messages",
        json={
            "device_id": "ESP32-01",
            "device_type": "esp32_device",
            "message_id": "heartbeat-1",
            "timestamp_ms": int(time.time() * 1000),
            "data": {"status": "online"},
        },
    )
    assert response.status_code == 200


def test_control_status_requires_loopback_and_reports_recent_hardware():
    client = _client()
    _heartbeat(client)
    status = client.get("/api/v1/device-control/status")
    assert status.status_code == 200
    assert status.json()["connected"] is True
    assert status.json()["control_configured"] is True

    external_client = _client(client=("192.168.1.40", 12345))
    assert external_client.get("/api/v1/device-control/status").status_code == 403
    cross_origin = client.get(
        "/api/v1/device-control/status",
        headers={"Origin": "http://192.168.1.50:5173"},
    )
    assert cross_origin.status_code == 403


def test_device_command_requires_recent_esp_and_configured_token():
    client = _client()
    assert client.post(
        "/api/v1/device-control/commands",
        json={"mode": "burst", "duration_seconds": 10},
    ).status_code == 409

    _heartbeat(client)
    unconfigured = _client(token=None)
    _heartbeat(unconfigured)
    response = unconfigured.post(
        "/api/v1/device-control/commands",
        json={"mode": "burst", "duration_seconds": 10},
    )
    assert response.status_code == 503


def test_burst_command_is_bounded_authenticated_and_acknowledged():
    client = _client()
    _heartbeat(client)
    invalid_duration = client.post(
        "/api/v1/device-control/commands",
        json={"mode": "burst", "duration_seconds": 11},
    )
    assert invalid_duration.status_code == 422

    issued = client.post(
        "/api/v1/device-control/commands",
        json={"mode": "burst", "duration_seconds": 5},
    )
    assert issued.status_code == 200
    command_id = issued.json()["command_id"]
    duplicate = client.post(
        "/api/v1/device-control/commands",
        json={"mode": "normal"},
    )
    assert duplicate.status_code == 409

    command_url = "/api/v1/device-control/commands/next?device_id=ESP32-01"
    assert client.get(command_url).status_code == 401
    headers = {"X-Device-Token": TOKEN}
    command = client.get(command_url, headers=headers)
    assert command.status_code == 200
    assert command.text == f"{command_id}|BURST|5"
    assert client.get(command_url, headers=headers).status_code == 204

    started = client.post(
        "/api/v1/device-control/commands/ack",
        params={"command_id": command_id, "status": "started"},
        headers=headers,
    )
    assert started.status_code == 204
    active_burst = client.post(
        "/api/v1/device-control/commands",
        json={"mode": "burst", "duration_seconds": 10},
    )
    assert active_burst.status_code == 409

    stop = client.post(
        "/api/v1/device-control/commands",
        json={"mode": "normal"},
    )
    assert stop.status_code == 200
    stop_id = stop.json()["command_id"]
    stop_command = client.get(command_url, headers=headers)
    assert stop_command.status_code == 200
    assert stop_command.text == f"{stop_id}|NORMAL|0"
    completed = client.post(
        "/api/v1/device-control/commands/ack",
        params={"command_id": stop_id, "status": "completed"},
        headers=headers,
    )
    assert completed.status_code == 204
    assert client.get("/api/v1/device-control/status").json()["status"] == "completed"


def test_only_loopback_can_queue_a_command():
    client = _client(client=("192.168.1.40", 12345))
    _heartbeat(client)
    response = client.post(
        "/api/v1/device-control/commands",
        json={"mode": "normal"},
    )
    assert response.status_code == 403


def test_unclaimed_device_commands_expire(monkeypatch):
    controller = DeviceCommandController()
    issued = controller.issue("burst", 10)
    issued_at = time.time()
    monkeypatch.setattr("app.device_control.time.time", lambda: issued_at + 21)

    assert controller.take_pending() is None
    assert controller.status()["status"] == "expired"
    assert controller.status()["command_id"] == issued["command_id"]
