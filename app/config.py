"""Validated configuration for the security detection engine."""

from dataclasses import dataclass
import math
import os


@dataclass(frozen=True)
class Settings:
    message_window_seconds: float = 10.0
    message_threshold: int = 20
    volume_window_seconds: float = 10.0
    volume_threshold_bytes: int = 10_240
    unregistered_alert_cooldown_seconds: float = 60.0
    behavioral_alert_cooldown_seconds: float = 60.0
    alert_history_limit: int = 1_000
    max_request_body_bytes: int = 65_536
    passive_capture_enabled: bool = False
    passive_capture_interface: str | None = None

    def __post_init__(self) -> None:
        durations = {
            "message_window_seconds": self.message_window_seconds,
            "volume_window_seconds": self.volume_window_seconds,
            "unregistered_alert_cooldown_seconds": (
                self.unregistered_alert_cooldown_seconds
            ),
            "behavioral_alert_cooldown_seconds": (
                self.behavioral_alert_cooldown_seconds
            ),
        }
        for name, duration in durations.items():
            if not math.isfinite(duration):
                raise ValueError(f"{name} must be finite")
        if self.message_window_seconds <= 0:
            raise ValueError("message_window_seconds must be greater than zero")
        if self.volume_window_seconds <= 0:
            raise ValueError("volume_window_seconds must be greater than zero")
        if self.message_threshold < 0:
            raise ValueError("message_threshold cannot be negative")
        if self.volume_threshold_bytes < 0:
            raise ValueError("volume_threshold_bytes cannot be negative")
        if self.unregistered_alert_cooldown_seconds < 0:
            raise ValueError("unregistered alert cooldown cannot be negative")
        if self.behavioral_alert_cooldown_seconds < 0:
            raise ValueError("behavioral alert cooldown cannot be negative")
        if self.alert_history_limit < 1:
            raise ValueError("alert_history_limit must be at least one")
        if self.max_request_body_bytes < 1:
            raise ValueError("max_request_body_bytes must be at least one")

    @classmethod
    def from_env(cls) -> "Settings":
        """Build settings from SECURITY_ENGINE_* environment variables."""
        passive_capture_enabled = os.getenv(
            "SECURITY_ENGINE_PASSIVE_CAPTURE_ENABLED", "false"
        ).strip().lower()
        if passive_capture_enabled not in {"true", "false", "1", "0", "yes", "no"}:
            raise ValueError(
                "SECURITY_ENGINE_PASSIVE_CAPTURE_ENABLED must be a boolean"
            )
        return cls(
            message_window_seconds=float(
                os.getenv("SECURITY_ENGINE_MESSAGE_WINDOW_SECONDS", "10")
            ),
            message_threshold=int(
                os.getenv("SECURITY_ENGINE_MESSAGE_THRESHOLD", "20")
            ),
            volume_window_seconds=float(
                os.getenv("SECURITY_ENGINE_VOLUME_WINDOW_SECONDS", "10")
            ),
            volume_threshold_bytes=int(
                os.getenv("SECURITY_ENGINE_VOLUME_THRESHOLD_BYTES", "10240")
            ),
            unregistered_alert_cooldown_seconds=float(
                os.getenv(
                    "SECURITY_ENGINE_UNREGISTERED_COOLDOWN_SECONDS", "60"
                )
            ),
            behavioral_alert_cooldown_seconds=float(
                os.getenv("SECURITY_ENGINE_BEHAVIORAL_COOLDOWN_SECONDS", "60")
            ),
            alert_history_limit=int(
                os.getenv("SECURITY_ENGINE_ALERT_HISTORY_LIMIT", "1000")
            ),
            max_request_body_bytes=int(
                os.getenv("SECURITY_ENGINE_MAX_REQUEST_BODY_BYTES", "65536")
            ),
            passive_capture_enabled=passive_capture_enabled in {"true", "1", "yes"},
            passive_capture_interface=os.getenv(
                "SECURITY_ENGINE_PASSIVE_CAPTURE_INTERFACE"
            )
            or None,
        )
