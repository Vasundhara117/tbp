import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.registry import DeviceRegistry


def make_client(
    *,
    settings: Settings | None = None,
    registry: DeviceRegistry | None = None,
) -> TestClient:
    return TestClient(create_app(settings, registry))


def message(
    *,
    device_id: str = "ESP32-01",
    message_id: str = "msg-0001",
    timestamp_ms: int = 1_790_000_000_000,
    data: dict | None = None,
) -> dict:
    return {
        "device_id": device_id,
        "device_type": "esp32_device",
        "message_id": message_id,
        "timestamp_ms": timestamp_ms,
        "data": data if data is not None else {"status": "online"},
    }


def test_authorized_normal_message_has_no_alert() -> None:
    with make_client() as client:
        response = client.post("/api/v1/messages", json=message())

    assert response.status_code == 200
    result = response.json()
    assert result["registered"] is True
    assert result["message_id"] == "msg-0001"
    assert result["request_size_bytes"] > 0
    assert result["observations"]["messages_in_window"] == 1
    assert result["observations"]["bytes_in_window"] == result["request_size_bytes"]
    assert result["alerts"] == []


def test_unregistered_device_generates_medium_alert() -> None:
    with make_client() as client:
        response = client.post(
            "/api/v1/messages", json=message(device_id="unknown-device")
        )

    alert = response.json()["alerts"][0]
    assert alert["category"] == "UNREGISTERED_DEVICE"
    assert alert["severity"] == "MEDIUM"
    assert alert["device_id"] == "unknown-device"


def test_more_than_twenty_messages_triggers_rate_alert() -> None:
    with make_client() as client:
        responses = [
            client.post(
                "/api/v1/messages",
                json=message(message_id=f"msg-{index}", timestamp_ms=index),
            )
            for index in range(21)
        ]

    alerts = responses[-1].json()["alerts"]
    rate_alert = next(a for a in alerts if a["category"] == "HIGH_MESSAGE_RATE")
    assert rate_alert["severity"] == "HIGH"
    assert rate_alert["evidence"]["messages_in_window"] == 21
    assert rate_alert["evidence"]["threshold"] == 20


def test_esp32_demo_workflow_classifies_devices_and_lists_alerts() -> None:
    with make_client() as client:
        normal = client.post(
            "/api/v1/messages",
            json=message(message_id="esp32-normal"),
        ).json()
        unknown = client.post(
            "/api/v1/messages",
            json=message(device_id="ESP32-UNKNOWN-01", message_id="unknown"),
        ).json()
        burst_responses = [
            client.post(
                "/api/v1/messages",
                json=message(message_id=f"esp32-burst-{index}"),
            ).json()
            for index in range(21)
        ]
        devices = client.get("/api/v1/devices").json()["devices"]
        alerts = client.get("/api/v1/alerts").json()["alerts"]

    assert normal["registered"] is True
    assert unknown["registered"] is False
    assert any(
        alert["category"] == "UNREGISTERED_DEVICE"
        for alert in unknown["alerts"]
    )
    assert any(
        alert["category"] == "HIGH_MESSAGE_RATE"
        for result in burst_responses
        for alert in result["alerts"]
    )
    assert {device["device_id"] for device in devices} >= {
        "ESP32-01",
        "ESP32-UNKNOWN-01",
    }
    assert {alert["category"] for alert in alerts} >= {
        "UNREGISTERED_DEVICE",
        "HIGH_MESSAGE_RATE",
    }


def test_request_body_bytes_trigger_volume_alert() -> None:
    settings = Settings(volume_threshold_bytes=250)
    with make_client(settings=settings) as client:
        responses = [
            client.post(
                "/api/v1/messages",
                json=message(
                    message_id=f"volume-{index}",
                    data={"padding": "x" * 90},
                ),
            )
            for index in range(3)
        ]

    volume_alert = next(
        alert
        for response in responses
        for alert in response.json()["alerts"]
        if alert["category"] == "HIGH_DATA_VOLUME"
    )
    assert volume_alert["evidence"]["bytes_in_window"] > 250
    assert volume_alert["evidence"]["threshold"] == 250


def test_unregistered_alerts_respect_cooldown() -> None:
    settings = Settings(unregistered_alert_cooldown_seconds=3_600)
    with make_client(settings=settings) as client:
        responses = [
            client.post(
                "/api/v1/messages",
                json=message(device_id="unknown-device", message_id=f"unknown-{i}"),
            )
            for i in range(10)
        ]

    generated = [
        alert
        for response in responses
        for alert in response.json()["alerts"]
        if alert["category"] == "UNREGISTERED_DEVICE"
    ]
    assert len(generated) == 1


@pytest.mark.parametrize(
    "payload",
    [
        {"device_id": "ESP32-01"},
        {
            **message(),
            "timestamp_ms": "not-an-integer",
        },
        {
            **message(),
            "data": ["not", "an", "object"],
        },
    ],
)
def test_invalid_or_missing_fields_return_422(payload: dict) -> None:
    with make_client() as client:
        response = client.post("/api/v1/messages", json=payload)
    assert response.status_code == 422
    assert response.json()["detail"]


def test_oversized_request_is_rejected_before_json_parsing() -> None:
    settings = Settings(max_request_body_bytes=20)
    with make_client(settings=settings) as client:
        response = client.post("/api/v1/messages", content=b"x" * 21)
    assert response.status_code == 413
    assert "configured limit" in response.json()["detail"]


def test_health_devices_and_alerts_schemas() -> None:
    with make_client() as client:
        health = client.get("/api/v1/health")
        client.post(
            "/api/v1/messages",
            json=message(device_id="unregistered-device"),
        )
        devices = client.get("/api/v1/devices")
        alerts = client.get("/api/v1/alerts", params={"limit": 1})

    assert health.json() == {"status": "ok"}
    device_body = devices.json()
    assert device_body["count"] == len(device_body["devices"])
    authorized = next(d for d in device_body["devices"] if d["device_id"] == "ESP32-01")
    observed = next(
        d for d in device_body["devices"] if d["device_id"] == "unregistered-device"
    )
    assert authorized["registered"] and authorized["authorized"]
    assert authorized["last_seen_ms"] is None
    assert not observed["registered"] and not observed["authorized"]
    assert observed["last_seen_ms"] is not None
    alert_body = alerts.json()
    assert alert_body["count"] == 1
    assert alert_body["alerts"][0]["alert_id"] == "ALT-0001"
    assert list(alert_body["alerts"][0]) == [
        "alert_id",
        "device_id",
        "category",
        "severity",
        "evidence",
        "summary",
        "timestamp_ms",
    ]


def test_fresh_app_instances_do_not_share_state() -> None:
    first = make_client()
    second = make_client()
    with first, second:
        first.post(
            "/api/v1/messages", json=message(device_id="not-in-second")
        )
        first_alerts = first.get("/api/v1/alerts").json()
        second_alerts = second.get("/api/v1/alerts").json()

    assert first_alerts["count"] == 1
    assert second_alerts["count"] == 0


def test_invalid_json_returns_422() -> None:
    with make_client() as client:
        response = client.post(
            "/api/v1/messages",
            content=b'{"device_id":',
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 422
