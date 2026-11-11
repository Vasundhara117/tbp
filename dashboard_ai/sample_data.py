"""Synthetic demonstration scenarios. These are never live observations."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone

_NOW = datetime.now(timezone.utc).replace(microsecond=0)
def _ts(minutes_ago: int) -> str:
    return (_NOW - timedelta(minutes=minutes_ago)).isoformat().replace("+00:00", "Z")

DEVICES = [
    {"device_id": "ESP32-01", "device_type": "esp32_device", "authorized": True, "registered": True, "last_seen": _ts(2), "message_frequency": 12, "received_data_volume": "18 KB", "_provenance": "synthetic"},
    {"device_id": "ESP32-GATEWAY-02", "device_type": "esp32_gateway", "authorized": True, "registered": True, "last_seen": _ts(6), "message_frequency": 4, "received_data_volume": "42 KB", "_provenance": "synthetic"},
]
ALERTS = [
    {"alert_id": "demo-alert-001", "device_id": "ESP32-01", "category": "behavioral", "severity": "low", "timestamp": _ts(18), "rule_name": "message_rate_threshold", "threshold": "20 messages/10 seconds", "evidence": {"observed_rate": "24 messages/10 seconds", "note": "Synthetic test scenario; increased rate may have a benign explanation."}, "_provenance": "synthetic"},
    {"alert_id": "demo-alert-002", "device_id": "ESP32-UNKNOWN-07", "category": "unauthorized_device", "severity": "high", "timestamp": _ts(11), "evidence": {"authorization": "not registered in synthetic inventory", "source": "synthetic test scenario"}, "_provenance": "synthetic"},
    {"alert_id": "demo-alert-003", "device_id": "ESP32-GATEWAY-02", "category": "high_data_volume", "severity": "medium", "timestamp": _ts(5), "rule_name": "data_volume_threshold", "threshold": "10 KiB / 10 seconds", "evidence": {"observed_volume": "12 KiB / 10 seconds", "source": "synthetic test scenario"}, "_provenance": "synthetic"},
]


def get_demo_data() -> tuple[list[dict], list[dict]]:
    """Return shallow copies of clearly synthetic records for display/testing."""
    return [dict(row) for row in DEVICES], [dict(row) for row in ALERTS]
