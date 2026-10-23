from fastapi.testclient import TestClient

from app.config import Settings
from app.detector import SecurityEngine
from app.main import create_app
from app.registry import DeviceRegistry
from app.schemas import MessageRequest


def payload(device_id: str, message_id: str, timestamp_ms: int) -> dict:
    return {
        "device_id": device_id,
        "device_type": "simulator",
        "message_id": message_id,
        "timestamp_ms": timestamp_ms,
        "data": {"status": "online"},
    }


def test_repeated_traffic_is_deduplicated_while_rule_stays_active() -> None:
    settings = Settings(
        message_threshold=1,
        behavioral_alert_cooldown_seconds=3_600,
    )
    client = TestClient(create_app(settings, DeviceRegistry({"device-a": "simulator"})))
    with client:
        alerts = []
        for index in range(30):
            response = client.post(
                "/api/v1/messages",
                json=payload("device-a", f"message-{index}", index),
            )
            alerts.extend(response.json()["alerts"])

    rate_alerts = [a for a in alerts if a["category"] == "HIGH_MESSAGE_RATE"]
    assert len(rate_alerts) == 1
    assert rate_alerts[0]["evidence"]["messages_in_window"] == 2


def test_device_observations_are_independent() -> None:
    settings = Settings(message_threshold=1)
    registry = DeviceRegistry({"device-a": "simulator", "device-b": "simulator"})
    client = TestClient(create_app(settings, registry))
    with client:
        client.post("/api/v1/messages", json=payload("device-a", "a-1", 0))
        client.post("/api/v1/messages", json=payload("device-b", "b-1", 0))
        second_a = client.post("/api/v1/messages", json=payload("device-a", "a-2", 0))
        device_b = client.get("/api/v1/devices").json()

    assert [a["category"] for a in second_a.json()["alerts"]] == [
        "HIGH_MESSAGE_RATE"
    ]
    b = next(d for d in device_b["devices"] if d["device_id"] == "device-b")
    assert b["messages_in_window"] == 1


def test_client_timestamp_does_not_control_rate_detection() -> None:
    settings = Settings(message_threshold=2)
    client = TestClient(create_app(settings, DeviceRegistry({"device-a": "simulator"})))
    with client:
        first = client.post(
            "/api/v1/messages",
            json=payload("device-a", "first", 9_999_999_999_999),
        )
        second = client.post(
            "/api/v1/messages",
            json=payload("device-a", "second", 1),
        )
        third = client.post(
            "/api/v1/messages",
            json=payload("device-a", "third", 0),
        )

    assert first.json()["alerts"] == []
    assert second.json()["alerts"] == []
    assert third.json()["observations"]["messages_in_window"] == 3
    assert any(a["category"] == "HIGH_MESSAGE_RATE" for a in third.json()["alerts"])
    assert third.json()["received_at_ms"] != 0


def test_cooldown_realerts_with_current_evidence_and_window_expires() -> None:
    current_time = [0.0]
    engine = SecurityEngine(
        Settings(message_threshold=1, behavioral_alert_cooldown_seconds=5),
        DeviceRegistry({"device-a": "simulator"}),
        monotonic_clock=lambda: current_time[0],
        wall_clock=lambda: 1_790_000_000,
    )

    def send(message_id: str):
        request = MessageRequest.model_validate(payload("device-a", message_id, 0))
        return engine.process_message(request, request_size_bytes=100)

    assert send("one").alerts == []
    current_time[0] = 1
    initial_alert = send("two").alerts[0]
    assert initial_alert.evidence["messages_in_window"] == 2

    current_time[0] = 2
    suppressed = send("three")
    assert suppressed.alerts == []
    assert suppressed.observations.messages_in_window == 3

    current_time[0] = 6
    repeated_alert = send("four").alerts[0]
    assert repeated_alert.evidence["messages_in_window"] == 4

    current_time[0] = 16.1
    expired = send("five")
    assert expired.observations.messages_in_window == 1
    assert expired.alerts == []
