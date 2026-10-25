"""Optional metadata-only network observation providers."""

import importlib.util
import platform
from threading import Lock
import time
from typing import Any, Callable

from .schemas import NetworkObservation


class ObservationProviderError(RuntimeError):
    """A provider could not be started or stopped."""


class SyntheticObservationProvider:
    """Produces a repeatable sequence of explicitly simulated observations."""

    _events = (
        {
            "device_id": "CCTV-ESP32-01",
            "device_type": "cctv_simulator",
            "mac_address": "02:00:00:00:00:01",
            "ip_address": "192.0.2.10",
        },
        {
            "device_id": "SYNTH-UNKNOWN-01",
            "device_type": "unknown_sensor",
            "mac_address": "02:00:00:00:00:02",
            "ip_address": "192.0.2.20",
        },
    )

    def __init__(self, *, wall_clock: Callable[[], float] = time.time) -> None:
        self._next_event = 0
        self._wall_clock = wall_clock
        self._lock = Lock()

    def next_observation(self) -> NetworkObservation:
        with self._lock:
            sequence = self._next_event
            self._next_event += 1
        event = self._events[sequence % len(self._events)]
        return NetworkObservation(
            observation_id=f"synthetic-{sequence + 1:04d}",
            timestamp_ms=int(self._wall_clock() * 1_000),
            source="synthetic_demo",
            message_count=1,
            packet_count=1,
            byte_count=256,
            simulated=True,
            **event,
        )


class ScapyPassiveObservationProvider:
    """Starts Scapy only on explicit request and forwards packet metadata."""

    def __init__(
        self,
        interface: str | None,
        on_observation: Callable[[NetworkObservation], object],
    ) -> None:
        self.interface = interface
        self._on_observation = on_observation
        self._sniffer = None
        self._error: str | None = None
        self._lock = Lock()

    @property
    def running(self) -> bool:
        with self._lock:
            return bool(self._sniffer is not None and self._sniffer.running)

    @property
    def error(self) -> str | None:
        with self._lock:
            return self._error

    @staticmethod
    def scapy_available() -> bool:
        return importlib.util.find_spec("scapy") is not None

    @staticmethod
    def platform_name() -> str:
        return platform.system()

    def start(self) -> None:
        with self._lock:
            if self._sniffer is not None and self._sniffer.running:
                return
        if not self.interface:
            raise ObservationProviderError(
                "Set SECURITY_ENGINE_PASSIVE_CAPTURE_INTERFACE before starting capture."
            )
        try:
            from scapy.all import AsyncSniffer, ARP, Ether, IP, IPv6
            from scapy.error import Scapy_Exception
        except ImportError as error:
            message = "Scapy is not installed; install the optional passive-monitor dependency."
            self._set_error(message)
            raise ObservationProviderError(message) from error

        def observe_packet(packet: Any) -> None:
            mac_address = None
            ip_address = None
            destination_ip = None
            protocol = None
            if packet.haslayer(Ether):
                mac_address = packet[Ether].src
            if packet.haslayer(IP):
                ip_address = packet[IP].src
                destination_ip = packet[IP].dst
                protocol = packet[IP].proto
            elif packet.haslayer(IPv6):
                ip_address = packet[IPv6].src
                destination_ip = packet[IPv6].dst
                protocol = packet[IPv6].nh
            elif packet.haslayer(ARP):
                ip_address = packet[ARP].psrc
                destination_ip = packet[ARP].pdst
                protocol = "ARP"
            observation = NetworkObservation(
                mac_address=mac_address,
                ip_address=ip_address,
                destination_ip=destination_ip,
                protocol=str(protocol) if protocol is not None else None,
                timestamp_ms=int(time.time() * 1_000),
                source=f"scapy:{self.interface}",
                packet_count=1,
                byte_count=len(packet),
                simulated=False,
            )
            self._on_observation(observation)

        sniffer = AsyncSniffer(
            iface=self.interface,
            store=False,
            prn=observe_packet,
        )
        try:
            sniffer.start()
        except (OSError, RuntimeError, Scapy_Exception) as error:
            message = f"Could not start Scapy capture: {error}"
            self._set_error(message)
            raise ObservationProviderError(message) from error
        with self._lock:
            self._sniffer = sniffer
            self._error = None

    def stop(self) -> None:
        with self._lock:
            sniffer = self._sniffer
        if sniffer is None or not sniffer.running:
            return
        try:
            from scapy.error import Scapy_Exception

            sniffer.stop()
        except (OSError, RuntimeError, Scapy_Exception) as error:
            message = f"Could not stop Scapy capture: {error}"
            self._set_error(message)
            raise ObservationProviderError(message) from error
        with self._lock:
            self._sniffer = None
            self._error = None

    def _set_error(self, message: str) -> None:
        with self._lock:
            self._error = message
