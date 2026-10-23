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
)

UNREGISTERED_SUMMARY = "Message came from a device not present in the authorized registry."
MESSAGE_RATE_SUMMARY = "Message frequency exceeded the configured threshold."
DATA_VOLUME_SUMMARY = "Received request-body bytes exceeded the configured threshold."
Evidence = dict[str, int | float]


@dataclass
class _DeviceActivity:
    messages: deque[float] = field(default_factory=deque)
    body_bytes: deque[tuple[float, int]] = field(default_factory=deque)
    last_seen_ms: int | None = None


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
            activity.messages.append(now)
            activity.body_bytes.append((now, request_size_bytes))
            activity.last_seen_ms = received_at_ms

            self._prune(activity, now)
            message_count = len(activity.messages)
            byte_count = sum(size for _, size in activity.body_bytes)
            registered = self.registry.is_registered(message.device_id)
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

    def devices(self) -> list[DeviceResponse]:
        with self._lock:
            registered = self.registry.snapshot()
            device_ids = set(registered) | set(self._activity)
            now = self._monotonic_clock()
            result: list[DeviceResponse] = []
            for device_id in sorted(device_ids):
                activity = self._activity.get(device_id)
                message_count = 0
                byte_count = 0
                last_seen_ms = None
                if activity is not None:
                    self._prune(activity, now)
                    message_count = len(activity.messages)
                    byte_count = sum(size for _, size in activity.body_bytes)
                    last_seen_ms = activity.last_seen_ms
                device_type = registered.get(device_id)
                result.append(
                    DeviceResponse(
                        device_id=device_id,
                        device_type=device_type,
                        registered=device_type is not None,
                        authorized=device_type is not None,
                        last_seen_ms=last_seen_ms,
                        messages_in_window=message_count,
                        bytes_in_window=byte_count,
                    )
                )
            return result

    def _prune(self, activity: _DeviceActivity, now: float) -> None:
        message_cutoff = now - self.settings.message_window_seconds
        while activity.messages and activity.messages[0] < message_cutoff:
            activity.messages.popleft()

        byte_cutoff = now - self.settings.volume_window_seconds
        while activity.body_bytes and activity.body_bytes[0][0] < byte_cutoff:
            activity.body_bytes.popleft()

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
    ) -> AlertResponse | None:
        key = (device_id, category)
        was_active = key in self._active_rules
        if active:
            self._active_rules.add(key)
            if not was_active:
                return self._create_alert(
                    device_id, category, "HIGH", evidence, summary, timestamp_ms, now
                )
            last_alert = self._last_alert_at.get(key)
            if (
                last_alert is None
                or now - last_alert >= self.settings.behavioral_alert_cooldown_seconds
            ):
                return self._create_alert(
                    device_id, category, "HIGH", evidence, summary, timestamp_ms, now
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
    ) -> AlertResponse:
        self._last_alert_at[(device_id, category)] = now
        return self.alert_store.add(
            device_id=device_id,
            category=category,
            severity=severity,
            evidence=evidence,
            summary=summary,
            timestamp_ms=timestamp_ms,
        )
