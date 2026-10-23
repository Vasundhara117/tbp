"""Bounded, process-local alert history with increasing identifiers."""

from collections import deque
from threading import RLock

from .schemas import AlertResponse


class AlertStore:
    def __init__(self, history_limit: int) -> None:
        self._alerts: deque[AlertResponse] = deque(maxlen=history_limit)
        self._next_id = 1
        self._lock = RLock()

    def add(
        self,
        *,
        device_id: str,
        category: str,
        severity: str,
        evidence: dict[str, int],
        summary: str,
        timestamp_ms: int,
    ) -> AlertResponse:
        with self._lock:
            alert = AlertResponse(
                alert_id=f"ALT-{self._next_id:04d}",
                device_id=device_id,
                category=category,
                severity=severity,
                evidence=evidence,
                summary=summary,
                timestamp_ms=timestamp_ms,
            )
            self._next_id += 1
            self._alerts.append(alert)
            return alert

    def recent(self, limit: int) -> list[AlertResponse]:
        with self._lock:
            return list(reversed(list(self._alerts)[-limit:]))
