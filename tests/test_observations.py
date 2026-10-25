import time

from fastapi.testclient import TestClient

from app.config import Settings
from app.detector import SecurityEngine
from app.main import create_app
from app.observers import ObservationProviderError, SyntheticObservationProvider
from app.registry import DeviceRegistry
from app.schemas import NetworkObservation


def observation(**overrides) -> dict:
    return {
        "observation_id": "capture-1",
        "device_id": "authorized-sensor",
        "mac_address": "02:00:00:00:00:01",
        "ip_address": "192.0.2.10",
        "timestamp_ms": 1_790_000_000_000,
        "source": "test_capture",
        "device_type": "temperature_sensor",
        "message_count": 0,
        "packet_count": 1,
        "byte_count": 256,
        "destination_ip": "198.51.100.5",
        "protocol": "TCP",
        "simulated": False,
        **overrides,
    }


def test_trusted_mac_observation_is_authorized_without_alert() -> None:
    registry = DeviceRegistry(
        {"authorized-sensor": "temperature_sensor"},
        mac_addresses={"02:00:00:00:00:01": "authorized-sensor"},
    )
    client = TestClient(create_app(registry=registry))
    with client:
        response = client.post(
            "/api/v1/observations",
            json=observation(device_id=None),
        )

    assert response.status_code == 200
    assert response.json()["authorized"] is True
    assert response.json()["alerts"] == []


def test_unknown_network_observation_alerts_without_heartbeat() -> None:
    client = TestClient(create_app(registry=DeviceRegistry({})))
    with client:
        response = client.post(
            "/api/v1/observations",
            json=observation(device_id=None),
        )
        inventory = client.get("/api/v1/devices").json()
        alerts = client.get("/api/v1/alerts").json()

    body = response.json()
    assert body["authorized"] is False
    assert body["device_id"].startswith("MAC-")
    assert body["alerts"][0]["category"] == "UNREGISTERED_DEVICE"
    assert body["alerts"][0]["evidence"]["destination_ip"] == "198.51.100.5"
    assert body["alerts"][0]["evidence"]["protocol"] == "TCP"
    assert inventory["count"] == 1
    assert inventory["devices"][0]["device_type"] == "temperature_sensor"
    assert inventory["devices"][0]["authorized"] is False
    assert alerts["count"] == 1


def test_unregistered_alert_includes_only_observed_evidence() -> None:
    client = TestClient(create_app(registry=DeviceRegistry({})))
    with client:
        response = client.post(
            "/api/v1/observations",
            json=observation(device_id=None, destination_ip=None, protocol=None),
        )

    alert = response.json()["alerts"][0]
    assert alert["category"] == "UNREGISTERED_DEVICE"
    assert alert["alert_id"]
    assert alert["timestamp_ms"] > 0
    assert alert["summary"]
    assert alert["severity"] == "MEDIUM"
    assert alert["evidence"]["device_record_id"] == response.json()["device_record_id"]
    assert alert["evidence"]["observation_id"] == "capture-1"
    assert alert["evidence"]["observation_source"] == "test_capture"
    assert alert["evidence"]["observation_timestamp_ms"] == 1_790_000_000_000
    assert alert["evidence"]["simulated"] is False
    assert alert["evidence"]["mac_address"] == "02:00:00:00:00:01"
    assert alert["evidence"]["ip_address"] == "192.0.2.10"
    assert "destination_ip" not in alert["evidence"]
    assert "protocol" not in alert["evidence"]
    assert "threshold" not in alert["evidence"]
    assert "observed_measurement" not in alert["evidence"]


def test_repeated_unregistered_observations_deduplicate_per_device_and_category() -> None:
    settings = Settings(
        message_threshold=1,
        unregistered_alert_cooldown_seconds=60,
        behavioral_alert_cooldown_seconds=60,
    )
    client = TestClient(create_app(settings, DeviceRegistry({})))
    with client:
        first = client.post(
            "/api/v1/observations",
            json=observation(device_id="unknown-a", packet_count=2),
        ).json()
        repeated = client.post(
            "/api/v1/observations",
            json=observation(
                observation_id="capture-2",
                device_id="unknown-a",
                packet_count=2,
            ),
        ).json()
        distinct_device = client.post(
            "/api/v1/observations",
            json=observation(
                observation_id="capture-3",
                device_id="unknown-b",
                mac_address="02:00:00:00:00:02",
                packet_count=2,
            ),
        ).json()

    assert {item["category"] for item in first["alerts"]} == {
        "UNREGISTERED_DEVICE",
        "HIGH_PACKET_RATE",
    }
    assert repeated["alerts"] == []
    assert {item["category"] for item in distinct_device["alerts"]} == {
        "UNREGISTERED_DEVICE",
        "HIGH_PACKET_RATE",
    }


def test_unregistered_alert_repeats_after_configured_cooldown() -> None:
    monotonic_now = [100.0]
    engine = SecurityEngine(
        Settings(
            unregistered_alert_cooldown_seconds=5,
            message_threshold=100,
        ),
        DeviceRegistry({}),
        monotonic_clock=lambda: monotonic_now[0],
        wall_clock=lambda: 1_800_000_000,
    )
    event = NetworkObservation.model_validate(
        observation(device_id="unknown-a", message_count=0, packet_count=0, byte_count=0)
    )

    first = engine.process_observation(event)
    monotonic_now[0] += 4
    suppressed = engine.process_observation(event)
    monotonic_now[0] += 1
    after_cooldown = engine.process_observation(event)

    assert [alert.category for alert in first.alerts] == ["UNREGISTERED_DEVICE"]
    assert suppressed.alerts == []
    assert [alert.category for alert in after_cooldown.alerts] == [
        "UNREGISTERED_DEVICE"
    ]


def test_synthetic_timestamp_uses_provider_clock() -> None:
    provider = SyntheticObservationProvider(wall_clock=lambda: 1_800_000_123.456)

    synthetic = provider.next_observation()

    assert synthetic.timestamp_ms == 1_800_000_123_456
    assert synthetic.simulated is True


def test_observation_event_timestamp_is_distinct_from_receipt_timeline() -> None:
    event_timestamp_ms = 1_700_000_000_000
    receipt_timestamp_ms = 1_800_000_000_000
    engine = SecurityEngine(
        Settings(message_threshold=100),
        DeviceRegistry({}),
        wall_clock=lambda: receipt_timestamp_ms / 1_000,
    )
    event = NetworkObservation.model_validate(
        observation(
            device_id="unknown-a",
            timestamp_ms=event_timestamp_ms,
            message_count=0,
            packet_count=0,
            byte_count=0,
            destination_ip=None,
            protocol=None,
        )
    )

    result = engine.process_observation(event)
    device = engine.devices()[0]

    assert result.timestamp_ms == event_timestamp_ms
    assert result.alerts[0].timestamp_ms == receipt_timestamp_ms
    assert result.alerts[0].evidence["observation_timestamp_ms"] == event_timestamp_ms
    assert device.first_seen_ms == device.last_seen_ms == receipt_timestamp_ms


def test_known_device_packet_threshold_creates_evidence_alert() -> None:
    settings = Settings(message_threshold=2)
    client = TestClient(
        create_app(settings, DeviceRegistry({"authorized-sensor": "sensor"}))
    )
    with client:
        response = client.post(
            "/api/v1/observations",
            json=observation(packet_count=3, byte_count=10),
        )

    alert = next(
        item
        for item in response.json()["alerts"]
        if item["category"] == "HIGH_PACKET_RATE"
    )
    assert alert["severity"] == "HIGH"
    assert alert["evidence"]["packets_in_window"] == 3
    assert alert["evidence"]["threshold"] == 2
    assert alert["evidence"]["observation_source"] == "test_capture"
    assert alert["evidence"]["simulated"] is False
    assert alert["evidence"]["destination_ip"] == "198.51.100.5"


def test_configured_destination_allowlist_detects_unexpected_destination() -> None:
    registry = DeviceRegistry(
        {"authorized-sensor": "temperature_sensor"},
        expected_destinations={"authorized-sensor": {"198.51.100.4"}},
    )
    client = TestClient(create_app(registry=registry))
    with client:
        response = client.post(
            "/api/v1/observations",
            json=observation(packet_count=1, byte_count=20),
        )

    alert = next(
        item
        for item in response.json()["alerts"]
        if item["category"] == "UNEXPECTED_DESTINATION"
    )
    assert alert["evidence"]["observed_destination"] == "198.51.100.5"
    assert alert["evidence"]["expected_destinations"] == "198.51.100.4"


def test_distinct_unexpected_destinations_are_not_deduplicated_together() -> None:
    registry = DeviceRegistry(
        {"authorized-sensor": "temperature_sensor"},
        expected_destinations={"authorized-sensor": {"198.51.100.4"}},
    )
    client = TestClient(create_app(registry=registry))
    with client:
        first = client.post(
            "/api/v1/observations",
            json=observation(destination_ip="198.51.100.5"),
        )
        second = client.post(
            "/api/v1/observations",
            json=observation(
                observation_id="capture-2",
                destination_ip="198.51.100.6",
            ),
        )

    assert first.json()["alerts"][0]["evidence"]["observed_destination"] == "198.51.100.5"
    assert second.json()["alerts"][0]["evidence"]["observed_destination"] == "198.51.100.6"


def test_normal_observation_does_not_trigger_behavioral_alert() -> None:
    client = TestClient(create_app())
    with client:
        response = client.post("/api/v1/observations", json=observation())

    assert not any(
        alert["category"] in {"HIGH_PACKET_RATE", "HIGH_DATA_VOLUME"}
        for alert in response.json()["alerts"]
    )


def test_repeated_observation_updates_inventory_statistics() -> None:
    client = TestClient(create_app())
    with client:
        client.post("/api/v1/observations", json=observation(packet_count=2))
        client.post(
            "/api/v1/observations",
            json=observation(
                observation_id="capture-2",
                mac_address="02-00-00-00-00-01",
                ip_address="192.0.2.11",
                packet_count=3,
                byte_count=512,
            ),
        )
        devices = client.get("/api/v1/devices").json()["devices"]

    device = next(row for row in devices if row["device_id"] == "authorized-sensor")
    assert device["mac_address"] == "02:00:00:00:00:01"
    assert device["ip_address"] == "192.0.2.11"
    assert device["first_seen_ms"] <= device["last_seen_ms"]
    assert device["packet_count_in_window"] == 5
    assert device["bytes_in_window"] == 768


def test_missing_identity_fields_create_distinct_safe_records() -> None:
    client = TestClient(create_app(registry=DeviceRegistry({})))
    with client:
        first = client.post(
            "/api/v1/observations",
            json=observation(
                observation_id="ip-only-1",
                device_id=None,
                mac_address=None,
            ),
        )
        second = client.post(
            "/api/v1/observations",
            json=observation(
                observation_id="ip-only-2",
                device_id=None,
                mac_address=None,
            ),
        )
        invalid_mac = client.post(
            "/api/v1/observations",
            json=observation(mac_address="not-a-mac"),
        )
        invalid_ip = client.post(
            "/api/v1/observations",
            json=observation(ip_address="not-an-ip"),
        )

    assert first.status_code == second.status_code == 200
    assert first.json()["device_record_id"] != second.json()["device_record_id"]
    assert invalid_mac.status_code == invalid_ip.status_code == 422


def test_synthetic_observations_are_marked_and_cycle_trusted_and_unknown() -> None:
    before_request_ms = int(time.time() * 1_000)
    client = TestClient(create_app())
    with client:
        trusted = client.post("/api/v1/monitoring/synthetic/next").json()
        unknown = client.post("/api/v1/monitoring/synthetic/next").json()
    after_request_ms = int(time.time() * 1_000)

    assert trusted["simulated"] is True
    assert trusted["observation_source"] == "synthetic_demo"
    assert before_request_ms <= trusted["timestamp_ms"] <= after_request_ms
    assert trusted["authorized"] is True
    assert unknown["simulated"] is True
    assert unknown["authorized"] is False
    assert before_request_ms <= unknown["timestamp_ms"] <= after_request_ms
    assert abs(unknown["timestamp_ms"] - unknown["alerts"][0]["timestamp_ms"]) < 5_000
    assert unknown["alerts"][0]["evidence"]["observation_source"] == "synthetic_demo"


def test_passive_provider_failure_is_reported_without_api_crash() -> None:
    class BrokenProvider:
        running = False
        error = None

        @staticmethod
        def scapy_available() -> bool:
            return False

        @staticmethod
        def platform_name() -> str:
            return "Test"

        def start(self) -> None:
            self.error = "capture interface is unavailable"
            raise ObservationProviderError(self.error)

        def stop(self) -> None:
            return None

    provider = BrokenProvider()
    app = create_app(
        Settings(passive_capture_enabled=True, passive_capture_interface="test0"),
        passive_provider=provider,
    )
    client = TestClient(app, client=("127.0.0.1", 12345))
    with client:
        failed = client.post("/api/v1/monitoring/passive/start")
        status = client.get("/api/v1/monitoring/status")

    assert failed.status_code == 503
    assert "capture interface" in failed.json()["detail"]
    assert status.status_code == 200
    assert status.json()["error"] == "capture interface is unavailable"


def test_passive_capture_controls_reject_non_loopback_clients() -> None:
    client = TestClient(
        create_app(
            Settings(
                passive_capture_enabled=True,
                passive_capture_interface="test0",
            )
        ),
        client=("192.0.2.40", 12345),
    )
    with client:
        response = client.post("/api/v1/monitoring/passive/start")

    assert response.status_code == 403
    assert "loopback" in response.json()["detail"]


def test_existing_routes_keep_their_response_envelopes() -> None:
    client = TestClient(create_app())
    with client:
        health = client.get("/api/v1/health")
        message = client.post(
            "/api/v1/messages",
            json={
                "device_id": "CCTV-ESP32-01",
                "device_type": "cctv_simulator",
                "message_id": "preserved",
                "timestamp_ms": 1,
                "data": {"status": "online"},
            },
        )
        devices = client.get("/api/v1/devices")
        alerts = client.get("/api/v1/alerts")

    assert health.json() == {"status": "ok"}
    assert "observations" in message.json()
    assert set(devices.json()) == {"devices", "count"}
    assert set(alerts.json()) == {"alerts", "count"}
