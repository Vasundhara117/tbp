"""Short-lived command queue for the registered demonstration ESP32."""

from __future__ import annotations

from threading import Lock
import time
import uuid


COMMAND_TTL_SECONDS = 20


class DeviceCommandController:
    def __init__(self) -> None:
        self._lock = Lock()
        self._pending: dict[str, str | int] | None = None
        self._status: dict[str, str | int] = {
            "device_id": "ESP32-01",
            "status": "idle",
            "mode": "normal",
            "duration_seconds": 0,
            "command_id": "",
            "updated_at_ms": 0,
        }

    def issue(self, mode: str, duration_seconds: int) -> dict[str, str | int]:
        now = time.time()
        with self._lock:
            self._expire_pending(now)
            if self._pending is not None:
                raise RuntimeError("A device command is already waiting for the ESP32.")
            if (
                self._status["status"] in {"delivered", "started"}
                and mode == "burst"
            ):
                raise RuntimeError(
                    "A burst is already active. Send NORMAL to stop it first."
                )

            command = {
                "command_id": uuid.uuid4().hex,
                "device_id": "ESP32-01",
                "mode": mode,
                "duration_seconds": duration_seconds if mode == "burst" else 0,
                "status": "queued",
                "expires_at": now + COMMAND_TTL_SECONDS,
                "updated_at_ms": int(now * 1000),
            }
            self._pending = command.copy()
            self._status = {
                key: value
                for key, value in command.items()
                if key != "expires_at"
            }
            return self._public_status()

    def take_pending(self) -> dict[str, str | int] | None:
        with self._lock:
            self._expire_pending(time.time())
            command = self._pending
            if command is None:
                return None
            self._pending = None
            command["status"] = "delivered"
            command["updated_at_ms"] = int(time.time() * 1000)
            self._status = {
                key: value
                for key, value in command.items()
                if key != "expires_at"
            }
            return {
                "command_id": str(command["command_id"]),
                "device_id": str(command["device_id"]),
                "mode": str(command["mode"]),
                "duration_seconds": int(command["duration_seconds"]),
            }

    def acknowledge(self, command_id: str, status: str) -> bool:
        with self._lock:
            if self._status["command_id"] != command_id:
                return False
            if status == "started" and self._status["status"] not in {
                "delivered",
                "started",
            }:
                return False
            if status == "completed" and self._status["status"] not in {
                "delivered",
                "started",
                "completed",
            }:
                return False
            self._status["status"] = status
            self._status["updated_at_ms"] = int(time.time() * 1000)
            return True

    def status(self) -> dict[str, str | int]:
        with self._lock:
            self._expire_pending(time.time())
            return self._public_status()

    def _expire_pending(self, now: float) -> None:
        if self._pending is None or float(self._pending["expires_at"]) > now:
            return
        self._status["status"] = "expired"
        self._status["updated_at_ms"] = int(now * 1000)
        self._pending = None

    def _public_status(self) -> dict[str, str | int]:
        return {key: value for key, value in self._status.items()}
