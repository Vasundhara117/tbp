"""Deterministic, server-observation-based detection rules."""

from collections import deque
from dataclasses import dataclass, field
import time
from threading import RLock
from typing import Callable

from .alert_store import AlertStore
from .config import Settings
from .registry import DeviceRegistry
from .schemas import (
    AlertResponse,
    DeviceObservation,
    DeviceResponse,
    MessageRequest,
    MessageResponse,
    NetworkObservation,
    ObservationIngestResponse,
)

UNREGISTERED_SUMMARY = "Message came from a device not present in the authorized registry."
MESSAGE_RATE_SUMMARY = "Message frequency exceeded the configured threshold."
DATA_VOLUME_SUMMARY = "Received request-body bytes exceeded the configured threshold."
OBSERVED_UNREGISTERED_SUMMARY = (
    "Network observation came from a device not present in the authorized registry."
)
PACKET_RATE_SUMMARY = "Observed packet frequency exceeded the configured threshold."
OBSERVED_DATA_VOLUME_SUMMARY = (
    "Observed network bytes exceeded the configured threshold."
)
UNEXPECTED_DESTINATION_SUMMARY = (
    "Observed destination was not in the device's configured destination allowlist."
)
Evidence = dict[str, int | float | str | bool | None]


@dataclass
class _DeviceActivity:
    messages: deque[tuple[float, int]] = field(default_factory=deque)
    packets: deque[tuple[float, int]] = field(default_factory=deque)
    body_bytes: deque[tuple[float, int]] = field(default_factory=deque)
    last_seen_ms: int | None = None


@dataclass
class _DeviceRecord:
    device_record_id: str
    device_id: str
    device_type: str | None
    mac_address: str | None
    ip_address: str | None
    first_seen_ms: int
    last_seen_ms: int
    observation_source: str


class SecurityEngine:
    """Coordinates registry checks, rolling observations, and alert generation."""

    def __init__(
        self,
        settings: Settings,
        registry: DeviceRegistry,
        alert_store: AlertStore | None = None,
        *,
        monotonic_clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings
        self.registry = registry
        self.alert_store = alert_store or AlertStore(settings.alert_history_limit)
        self._monotonic_clock = monotonic_clock
        self._wall_clock = wall_clock
        self._activity: dict[str, _DeviceActivity] = {}
        self._records_by_identity: dict[str, _DeviceRecord] = {}
        self._records_by_device_id: dict[str, _DeviceRecord] = {}
        self._next_record_id = 1
        self._last_alert_at: dict[tuple[str, str], float] = {}
        self._active_rules: set[tuple[str, str]] = set()
        self._lock = RLock()

    def process_message(
        self, message: MessageRequest, request_size_bytes: int
    ) -> MessageResponse:
        with self._lock:
            now = self._monotonic_clock()
            received_at_ms = int(self._wall_clock() * 1_000)
            activity = self._activity.setdefault(message.device_id, _DeviceActivity())
            activity.messages.append((now, 1))
            activity.body_bytes.append((now, request_size_bytes))
            activity.last_seen_ms = received_at_ms

            self._prune(activity, now)
            message_count = sum(count for _, count in activity.messages)
            byte_count = sum(size for _, size in activity.body_bytes)
            registered = self.registry.is_registered(message.device_id)
            record = self._get_or_create_record(
                f"id:{message.device_id}",
                message.device_id,
                received_at_ms,
                source="application_message",
                device_type=(
                    self.registry.device_type_for(message.device_id)
                    if registered
                    else None
                ),
            )
            record.last_seen_ms = received_at_ms
            record.observation_source = "application_message"
            new_alerts: list[AlertResponse] = []

            if not registered:
                alert = self._maybe_alert(
                    device_id=message.device_id,
                    category="UNREGISTERED_DEVICE",
                    severity="MEDIUM",
                    evidence={"messages_in_window": message_count},
                    summary=UNREGISTERED_SUMMARY,
                    timestamp_ms=received_at_ms,
                    now=now,
                    cooldown=self.settings.unregistered_alert_cooldown_seconds,
                )
                if alert:
                    new_alerts.append(alert)

            alert = self._behavioral_alert(
                device_id=message.device_id,
                category="HIGH_MESSAGE_RATE",
                active=message_count > self.settings.message_threshold,
                evidence={
                    "messages_in_window": message_count,
                    "window_seconds": self.settings.message_window_seconds,
                    "threshold": self.settings.message_threshold,
                },
                summary=MESSAGE_RATE_SUMMARY,
                timestamp_ms=received_at_ms,
                now=now,
            )
            if alert:
                new_alerts.append(alert)

            alert = self._behavioral_alert(
                device_id=message.device_id,
                category="HIGH_DATA_VOLUME",
                active=byte_count > self.settings.volume_threshold_bytes,
                evidence={
                    "bytes_in_window": byte_count,
                    "window_seconds": self.settings.volume_window_seconds,
                    "threshold": self.settings.volume_threshold_bytes,
                },
                summary=DATA_VOLUME_SUMMARY,
                timestamp_ms=received_at_ms,
                now=now,
            )
            if alert:
                new_alerts.append(alert)

            return MessageResponse(
                device_id=message.device_id,
                registered=registered,
                message_id=message.message_id,
                received_at_ms=received_at_ms,
                request_size_bytes=request_size_bytes,
                observations=DeviceObservation(
                    messages_in_window=message_count,
                    message_window_seconds=self.settings.message_window_seconds,
                    bytes_in_window=byte_count,
                    byte_window_seconds=self.settings.volume_window_seconds,
                ),
                alerts=new_alerts,
            )

    def process_observation(
        self, observation: NetworkObservation
    ) -> ObservationIngestResponse:
        with self._lock:
            now = self._monotonic_clock()
            observed_at_ms = int(self._wall_clock() * 1_000)
            record = self._record_for_observation(observation, observed_at_ms)
            activity = self._activity.setdefault(record.device_id, _DeviceActivity())
            activity.last_seen_ms = observed_at_ms
            if observation.message_count:
                activity.messages.append((now, observation.message_count))
            if observation.packet_count:
                activity.packets.append((now, observation.packet_count))
            if observation.byte_count:
                activity.body_bytes.append((now, observation.byte_count))
            self._prune(activity, now)

            registered = self.registry.is_registered(record.device_id)
            device_type = self.registry.device_type_for(record.device_id)
            if device_type is not None:
                record.device_type = device_type
            message_count = sum(count for _, count in activity.messages)
            packet_count = sum(count for _, count in activity.packets)
            byte_count = sum(size for _, size in activity.body_bytes)
            evidence = {
                "observation_source": observation.source,
                "observation_timestamp_ms": observation.timestamp_ms,
                "simulated": observation.simulated,
                "observation_id": observation.observation_id,
                "mac_address": observation.mac_address,
                "ip_address": observation.ip_address,
                "destination_ip": observation.destination_ip,
                "protocol": observation.protocol,
                "device_record_id": record.device_record_id,
            }
            evidence = {
                key: value for key, value in evidence.items() if value is not None
            }
            new_alerts: list[AlertResponse] = []

            if not registered:
                alert = self._maybe_alert(
                    device_id=record.device_id,
                    category="UNREGISTERED_DEVICE",
                    severity="MEDIUM",
                    evidence=evidence,
                    summary=OBSERVED_UNREGISTERED_SUMMARY,
                    timestamp_ms=observed_at_ms,
                    now=now,
                    cooldown=self.settings.unregistered_alert_cooldown_seconds,
                )
                if alert:
                    new_alerts.append(alert)

            if observation.message_count:
                alert = self._behavioral_alert(
                    device_id=record.device_id,
                    category="HIGH_MESSAGE_RATE",
                    active=message_count > self.settings.message_threshold,
                    evidence={
                        **evidence,
                        "messages_in_window": message_count,
                        "window_seconds": self.settings.message_window_seconds,
                        "observed_measurement": message_count,
                        "threshold": self.settings.message_threshold,
                    },
                    summary=MESSAGE_RATE_SUMMARY,
                    timestamp_ms=observed_at_ms,
                    now=now,
                )
                if alert:
                    new_alerts.append(alert)

            if observation.packet_count:
                alert = self._behavioral_alert(
                    device_id=record.device_id,
                    category="HIGH_PACKET_RATE",
                    active=packet_count > self.settings.message_threshold,
                    evidence={
                        **evidence,
                        "packets_in_window": packet_count,
                        "window_seconds": self.settings.message_window_seconds,
                        "observed_measurement": packet_count,
                        "threshold": self.settings.message_threshold,
                    },
                    summary=PACKET_RATE_SUMMARY,
                    timestamp_ms=observed_at_ms,
                    now=now,
                )
                if alert:
                    new_alerts.append(alert)

            if observation.byte_count:
                alert = self._behavioral_alert(
                    device_id=record.device_id,
                    category="HIGH_DATA_VOLUME",
                    active=byte_count > self.settings.volume_threshold_bytes,
                    evidence={
                        **evidence,
                        "bytes_in_window": byte_count,
                        "window_seconds": self.settings.volume_window_seconds,
                        "observed_measurement": byte_count,
                        "threshold": self.settings.volume_threshold_bytes,
                    },
                    summary=OBSERVED_DATA_VOLUME_SUMMARY,
                    timestamp_ms=observed_at_ms,
                    now=now,
                )
                if alert:
                    new_alerts.append(alert)

            if observation.destination_ip is not None:
                has_policy, is_expected, expected = self.registry.destination_policy(
                    record.device_id, observation.destination_ip
                )
                if has_policy:
                    alert = self._behavioral_alert(
                        device_id=record.device_id,
                        category="UNEXPECTED_DESTINATION",
                        active=not is_expected,
                        evidence={
                            **evidence,
                            "observed_destination": observation.destination_ip,
                            "expected_destinations": ",".join(expected),
                            "threshold": "configured destination allowlist",
                        },
                        summary=UNEXPECTED_DESTINATION_SUMMARY,
                        timestamp_ms=observed_at_ms,
                        now=now,
                        deduplication_key=(
                            f"UNEXPECTED_DESTINATION:{observation.destination_ip}"
                        ),
                    )
                    if alert:
                        new_alerts.append(alert)

            return ObservationIngestResponse(
                observation_id=observation.observation_id,
                timestamp_ms=observation.timestamp_ms,
                observation_source=observation.source,
                simulated=observation.simulated,
                device_record_id=record.device_record_id,
                device_id=record.device_id,
                authorized=registered,
                alerts=new_alerts,
            )

    def devices(self) -> list[DeviceResponse]:
        with self._lock:
            registered = self.registry.snapshot()
            device_ids = (
                set(registered)
                | set(self._activity)
                | set(self._records_by_device_id)
            )
            now = self._monotonic_clock()
            result: list[DeviceResponse] = []
            for device_id in sorted(device_ids):
                activity = self._activity.get(device_id)
                message_count = 0
                packet_count = 0
                byte_count = 0
                last_seen_ms = None
                if activity is not None:
                    self._prune(activity, now)
                    message_count = sum(count for _, count in activity.messages)
                    packet_count = sum(count for _, count in activity.packets)
                    byte_count = sum(size for _, size in activity.body_bytes)
                    last_seen_ms = activity.last_seen_ms
                record = self._records_by_device_id.get(device_id)
                is_registered = device_id in registered
                device_type = registered.get(device_id) or (
                    record.device_type if record is not None else None
                )
                result.append(
                    DeviceResponse(
                        device_id=device_id,
                        device_type=device_type,
                        registered=is_registered,
                        authorized=is_registered,
                        last_seen_ms=last_seen_ms,
                        messages_in_window=message_count,
                        bytes_in_window=byte_count,
                        device_record_id=(
                            record.device_record_id if record is not None else None
                        ),
                        mac_address=record.mac_address if record is not None else None,
                        ip_address=record.ip_address if record is not None else None,
                        first_seen_ms=record.first_seen_ms if record is not None else None,
                        observation_source=(
                            record.observation_source if record is not None else None
                        ),
                        packet_count_in_window=packet_count,
                    )
                )
            return result

    def _prune(self, activity: _DeviceActivity, now: float) -> None:
        message_cutoff = now - self.settings.message_window_seconds
        while activity.messages and activity.messages[0][0] < message_cutoff:
            activity.messages.popleft()
        while activity.packets and activity.packets[0][0] < message_cutoff:
            activity.packets.popleft()

        byte_cutoff = now - self.settings.volume_window_seconds
        while activity.body_bytes and activity.body_bytes[0][0] < byte_cutoff:
            activity.body_bytes.popleft()

    def _record_for_observation(
        self, observation: NetworkObservation, observed_at_ms: int
    ) -> _DeviceRecord:
        if observation.device_id is not None:
            device_id = observation.device_id
            identity = f"id:{device_id}"
        elif observation.mac_address is not None:
            trusted_device_id = self.registry.device_id_for_mac(
                observation.mac_address
            )
            device_id = trusted_device_id or (
                f"MAC-{observation.mac_address.replace(':', '').upper()}"
            )
            identity = (
                f"id:{device_id}"
                if trusted_device_id
                else f"mac:{observation.mac_address}"
            )
        else:
            device_id = f"OBS-{self._next_record_id:06d}"
            identity = f"observation:{self._next_record_id}"

        record = self._get_or_create_record(
            identity,
            device_id,
            observed_at_ms,
            source=observation.source,
            device_type=observation.device_type,
            mac_address=observation.mac_address,
            ip_address=observation.ip_address,
        )
        if observation.mac_address is not None:
            record.mac_address = observation.mac_address
        if observation.ip_address is not None:
            record.ip_address = observation.ip_address
        if observation.device_type is not None:
            record.device_type = observation.device_type
        record.last_seen_ms = observed_at_ms
        record.observation_source = observation.source
        return record

    def _get_or_create_record(
        self,
        identity: str,
        device_id: str,
        observed_at_ms: int,
        *,
        source: str,
        device_type: str | None = None,
        mac_address: str | None = None,
        ip_address: str | None = None,
    ) -> _DeviceRecord:
        record = self._records_by_identity.get(identity)
        if record is None:
            record = _DeviceRecord(
                device_record_id=f"DEV-{self._next_record_id:06d}",
                device_id=device_id,
                device_type=device_type,
                mac_address=mac_address,
                ip_address=ip_address,
                first_seen_ms=observed_at_ms,
                last_seen_ms=observed_at_ms,
                observation_source=source,
            )
            self._next_record_id += 1
            self._records_by_identity[identity] = record
            self._records_by_device_id[device_id] = record
        return record

    def _behavioral_alert(
        self,
        *,
        device_id: str,
        category: str,
        active: bool,
        evidence: Evidence,
        summary: str,
        timestamp_ms: int,
        now: float,
        deduplication_key: str | None = None,
    ) -> AlertResponse | None:
        key = (device_id, deduplication_key or category)
        was_active = key in self._active_rules
        if active:
            self._active_rules.add(key)
            if not was_active:
                return self._create_alert(
                    device_id,
                    category,
                    "HIGH",
                    evidence,
                    summary,
                    timestamp_ms,
                    now,
                    rule_key=key,
                )
            last_alert = self._last_alert_at.get(key)
            if (
                last_alert is None
                or now - last_alert >= self.settings.behavioral_alert_cooldown_seconds
            ):
                return self._create_alert(
                    device_id,
                    category,
                    "HIGH",
                    evidence,
                    summary,
                    timestamp_ms,
                    now,
                    rule_key=key,
                )
        else:
            self._active_rules.discard(key)
        return None

    def _maybe_alert(
        self,
        *,
        device_id: str,
        category: str,
        severity: str,
        evidence: Evidence,
        summary: str,
        timestamp_ms: int,
        now: float,
        cooldown: float,
    ) -> AlertResponse | None:
        key = (device_id, category)
        last_alert = self._last_alert_at.get(key)
        if last_alert is not None and now - last_alert < cooldown:
            return None
        return self._create_alert(
            device_id, category, severity, evidence, summary, timestamp_ms, now
        )

    def _create_alert(
        self,
        device_id: str,
        category: str,
        severity: str,
        evidence: Evidence,
        summary: str,
        timestamp_ms: int,
        now: float,
        rule_key: tuple[str, str] | None = None,
    ) -> AlertResponse:
        self._last_alert_at[rule_key or (device_id, category)] = now
        return self.alert_store.add(
            device_id=device_id,
            category=category,
            severity=severity,
            evidence=evidence,
            summary=summary,
            timestamp_ms=timestamp_ms,
        )
