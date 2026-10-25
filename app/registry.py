"""In-memory authorized-device registry."""

from threading import RLock

from .schemas import NetworkObservation


DEFAULT_DEVICES = {"CCTV-ESP32-01": "cctv_simulator"}


class DeviceRegistry:
    """Stores authorization separately from a device's observed activity."""

    def __init__(
        self,
        devices: dict[str, str] | None = None,
        *,
        mac_addresses: dict[str, str] | None = None,
        expected_destinations: dict[str, set[str] | list[str]] | None = None,
    ) -> None:
        # None selects the demonstration device; an explicit empty mapping stays empty.
        self._devices = dict(DEFAULT_DEVICES if devices is None else devices)
        self._mac_addresses: dict[str, str] = {}
        self._expected_destinations: dict[str, frozenset[str]] = {}
        self._lock = RLock()
        for mac_address, device_id in (mac_addresses or {}).items():
            self.register_mac(mac_address, device_id)
        for device_id, destinations in (expected_destinations or {}).items():
            self.set_expected_destinations(device_id, destinations)

    def register(self, device_id: str, device_type: str) -> None:
        if not device_id or not device_type:
            raise ValueError("device_id and device_type must not be empty")
        with self._lock:
            self._devices[device_id] = device_type

    def unregister(self, device_id: str) -> bool:
        with self._lock:
            removed = self._devices.pop(device_id, None) is not None
            if removed:
                self._mac_addresses = {
                    mac: registered_id
                    for mac, registered_id in self._mac_addresses.items()
                    if registered_id != device_id
                }
                self._expected_destinations.pop(device_id, None)
            return removed

    def is_registered(self, device_id: str) -> bool:
        with self._lock:
            return device_id in self._devices

    def device_type_for(self, device_id: str) -> str | None:
        with self._lock:
            return self._devices.get(device_id)

    def snapshot(self) -> dict[str, str]:
        with self._lock:
            return dict(self._devices)

    def register_mac(self, mac_address: str, device_id: str) -> None:
        if not device_id:
            raise ValueError("device_id must not be empty")
        normalized = NetworkObservation(mac_address=mac_address).mac_address
        if normalized is None:
            raise ValueError("mac_address must not be empty")
        with self._lock:
            if device_id not in self._devices:
                raise ValueError("device_id must be registered before its MAC address")
            self._mac_addresses[normalized] = device_id

    def device_id_for_mac(self, mac_address: str) -> str | None:
        normalized = NetworkObservation(mac_address=mac_address).mac_address
        if normalized is None:
            return None
        with self._lock:
            return self._mac_addresses.get(normalized)

    def set_expected_destinations(
        self, device_id: str, destinations: set[str] | list[str]
    ) -> None:
        if not device_id:
            raise ValueError("device_id must not be empty")
        normalized = {
            NetworkObservation(destination_ip=destination).destination_ip
            for destination in destinations
        }
        if None in normalized:
            raise ValueError("expected destinations must not contain empty values")
        with self._lock:
            if device_id not in self._devices:
                raise ValueError("device_id must be registered before destinations")
            self._expected_destinations[device_id] = frozenset(normalized)

    def destination_policy(
        self, device_id: str, destination_ip: str
    ) -> tuple[bool, bool, tuple[str, ...]]:
        normalized = NetworkObservation(destination_ip=destination_ip).destination_ip
        if normalized is None:
            return False, False, ()
        with self._lock:
            allowed = self._expected_destinations.get(device_id)
            if allowed is None:
                return False, False, ()
            ordered_allowed = tuple(sorted(allowed))
            return True, normalized in allowed, ordered_allowed
