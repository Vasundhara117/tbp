from app.registry import DeviceRegistry


def test_default_registry_contains_demonstration_device() -> None:
    registry = DeviceRegistry()
    assert registry.is_registered("CCTV-ESP32-01")
    assert registry.device_type_for("CCTV-ESP32-01") == "cctv_simulator"
    assert not registry.is_registered("unknown")


def test_registry_can_be_configured_without_changing_detection_rules() -> None:
    registry = DeviceRegistry({})
    registry.register("door-sensor", "door_sensor")
    assert registry.snapshot() == {"door-sensor": "door_sensor"}
    assert registry.unregister("door-sensor")
    assert not registry.unregister("door-sensor")


def test_unregistering_device_removes_its_mac_and_destination_trust() -> None:
    registry = DeviceRegistry(
        {"door-sensor": "door_sensor"},
        mac_addresses={"02:00:00:00:00:01": "door-sensor"},
        expected_destinations={"door-sensor": {"192.0.2.10"}},
    )

    assert registry.unregister("door-sensor")
    assert registry.device_id_for_mac("02:00:00:00:00:01") is None
    assert registry.destination_policy("door-sensor", "192.0.2.10") == (
        False,
        False,
        (),
    )
