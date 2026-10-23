"""In-memory authorized-device registry."""

from threading import RLock


DEFAULT_DEVICES = {"CCTV-ESP32-01": "cctv_simulator"}


class DeviceRegistry:
    """Stores authorization separately from a device's observed activity."""

    def __init__(self, devices: dict[str, str] | None = None) -> None:
        # None selects the demonstration device; an explicit empty mapping stays empty.
        self._devices = dict(DEFAULT_DEVICES if devices is None else devices)
        self._lock = RLock()

    def register(self, device_id: str, device_type: str) -> None:
        if not device_id or not device_type:
            raise ValueError("device_id and device_type must not be empty")
        with self._lock:
            self._devices[device_id] = device_type

    def unregister(self, device_id: str) -> bool:
        with self._lock:
            return self._devices.pop(device_id, None) is not None

    def is_registered(self, device_id: str) -> bool:
        with self._lock:
            return device_id in self._devices

    def device_type_for(self, device_id: str) -> str | None:
        with self._lock:
            return self._devices.get(device_id)

    def snapshot(self) -> dict[str, str]:
        with self._lock:
            return dict(self._devices)
