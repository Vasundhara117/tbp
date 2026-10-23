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
