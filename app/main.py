"""FastAPI application and versioned security-engine endpoints."""

import ipaddress
import secrets
import time
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from .alert_store import AlertStore
from .config import Settings
from .device_control import DeviceCommandController
from .detector import SecurityEngine
from .observers import (
    ObservationProviderError,
    ScapyPassiveObservationProvider,
    SyntheticObservationProvider,
)
from .registry import DeviceRegistry
from .schemas import (
    AlertListResponse,
    DeviceListResponse,
    DeviceCommandRequest,
    HealthResponse,
    MessageRequest,
    MessageResponse,
    MonitoringStatusResponse,
    NetworkObservation,
    ObservationIngestResponse,
)

DEVICE_HEARTBEAT_MAX_AGE_MS = 20_000


class RequestBodySizeLimitMiddleware:
    """Measures and limits raw request-body bytes before FastAPI parses JSON."""

    def __init__(self, app: Any, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if (
            scope["type"] != "http"
            or scope["method"] != "POST"
            or scope["path"] not in {
                "/api/v1/messages",
                "/api/v1/observations",
            }
        ):
            await self.app(scope, receive, send)
            return

        chunks: list[bytes] = []
        total_bytes = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            total_bytes += len(chunk)
            if total_bytes > self.max_body_bytes:
                response = JSONResponse(
                    status_code=413,
                    content={
                        "detail": (
                            "Request body exceeds the configured limit of "
                            f"{self.max_body_bytes} bytes."
                        )
                    },
                )
                await response(scope, receive, send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        body = b"".join(chunks)
        scope.setdefault("state", {})["request_size_bytes"] = total_bytes
        replayed = False

        async def replay_body() -> dict[str, Any]:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay_body, send)


def create_app(
    settings: Settings | None = None,
    registry: DeviceRegistry | None = None,
    *,
    passive_provider: ScapyPassiveObservationProvider | None = None,
) -> FastAPI:
    """Create an isolated app instance for tests or embedding."""
    selected_settings = settings if settings is not None else Settings.from_env()
    selected_registry = registry if registry is not None else DeviceRegistry()
    alert_store = AlertStore(selected_settings.alert_history_limit)
    engine = SecurityEngine(selected_settings, selected_registry, alert_store)
    synthetic_provider = SyntheticObservationProvider()
    selected_passive_provider = passive_provider or ScapyPassiveObservationProvider(
        selected_settings.passive_capture_interface,
        engine.process_observation,
    )

    app = FastAPI(title="SecureIoT Sentinel Security Engine", version="1.0.0")
    app.state.engine = engine
    app.state.synthetic_provider = synthetic_provider
    app.state.passive_provider = selected_passive_provider
    device_command_controller = DeviceCommandController()
    app.state.device_command_controller = device_command_controller
    app.add_middleware(
        RequestBodySizeLimitMiddleware,
        max_body_bytes=selected_settings.max_request_body_bytes,
    )

    @app.get("/api/v1/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(status="ok")

    @app.post("/api/v1/messages", response_model=MessageResponse)
    def receive_message(message: MessageRequest, request: Request) -> MessageResponse:
        return engine.process_message(message, request.state.request_size_bytes)

    @app.get("/api/v1/devices", response_model=DeviceListResponse)
    def devices() -> DeviceListResponse:
        items = engine.devices()
        return DeviceListResponse(devices=items, count=len(items))

    @app.get("/api/v1/alerts", response_model=AlertListResponse)
    def alerts(limit: int = Query(default=100, ge=1, le=1_000)) -> AlertListResponse:
        items = alert_store.recent(limit)
        return AlertListResponse(alerts=items, count=len(items))

    @app.get("/api/v1/device-control/status")
    def device_control_status(request: Request) -> dict[str, str | int | bool]:
        if not _request_is_loopback(request) or not _request_origin_is_loopback(request):
            raise HTTPException(
                status_code=403,
                detail="Device controls are restricted to loopback clients.",
            )
        status = device_command_controller.status()
        device = next(
            (item for item in engine.devices() if item.device_id == "ESP32-01"),
            None,
        )
        last_seen = device.last_seen_ms if device is not None else None
        is_recent = (
            last_seen is not None
            and 0 <= int(time.time() * 1000) - last_seen
            <= DEVICE_HEARTBEAT_MAX_AGE_MS
        )
        return {
            **status,
            "connected": is_recent,
            "last_seen_ms": last_seen or 0,
            "control_configured": bool(selected_settings.device_control_token),
        }

    @app.post("/api/v1/device-control/commands")
    def issue_device_command(
        body: DeviceCommandRequest,
        request: Request,
    ) -> dict[str, str | int]:
        if not _request_is_loopback(request) or not _request_origin_is_loopback(request):
            raise HTTPException(
                status_code=403,
                detail="Device controls are restricted to loopback clients.",
            )
        if not selected_settings.device_control_token:
            raise HTTPException(
                status_code=503,
                detail="Device control is not configured on the backend.",
            )
        device = next(
            (item for item in engine.devices() if item.device_id == "ESP32-01"),
            None,
        )
        last_seen = device.last_seen_ms if device is not None else None
        if (
            last_seen is None
            or not 0
            <= int(time.time() * 1000) - last_seen
            <= DEVICE_HEARTBEAT_MAX_AGE_MS
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    "ESP32-01 has not sent a heartbeat recently. Check its "
                    "Wi-Fi and server connection first."
                ),
            )
        try:
            return device_command_controller.issue(
                body.mode,
                body.duration_seconds,
            )
        except RuntimeError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.get(
        "/api/v1/device-control/commands/next",
        response_class=PlainTextResponse,
    )
    def take_device_command(
        device_id: str = Query(min_length=1, max_length=64),
        x_device_token: str | None = Header(default=None),
    ) -> Response:
        _validate_device_token(
            selected_settings.device_control_token,
            x_device_token,
        )
        if device_id != "ESP32-01":
            raise HTTPException(status_code=404, detail="Unknown controlled device.")
        command = device_command_controller.take_pending()
        if command is None:
            return Response(status_code=204)
        if command["mode"] == "burst":
            payload = (
                f'{command["command_id"]}|BURST|'
                f'{command["duration_seconds"]}'
            )
        else:
            payload = f'{command["command_id"]}|NORMAL|0'
        return PlainTextResponse(payload)

    @app.post("/api/v1/device-control/commands/ack")
    def acknowledge_device_command(
        command_id: str = Query(min_length=1, max_length=64),
        status: str = Query(pattern="^(started|completed)$"),
        x_device_token: str | None = Header(default=None),
    ) -> Response:
        _validate_device_token(
            selected_settings.device_control_token,
            x_device_token,
        )
        if not device_command_controller.acknowledge(command_id, status):
            raise HTTPException(
                status_code=409,
                detail="Command acknowledgement does not match the current device command.",
            )
        return Response(status_code=204)

    @app.post(
        "/api/v1/observations",
        response_model=ObservationIngestResponse,
    )
    def receive_observation(
        observation: NetworkObservation,
    ) -> ObservationIngestResponse:
        return engine.process_observation(observation)

    @app.get(
        "/api/v1/monitoring/status",
        response_model=MonitoringStatusResponse,
    )
    def monitoring_status() -> MonitoringStatusResponse:
        return MonitoringStatusResponse(
            synthetic_available=True,
            passive_capture_enabled=selected_settings.passive_capture_enabled,
            passive_capture_running=selected_passive_provider.running,
            passive_capture_interface=selected_settings.passive_capture_interface,
            platform=selected_passive_provider.platform_name(),
            scapy_available=selected_passive_provider.scapy_available(),
            error=selected_passive_provider.error,
        )

    @app.post(
        "/api/v1/monitoring/synthetic/next",
        response_model=ObservationIngestResponse,
    )
    def synthetic_observation() -> ObservationIngestResponse:
        observation = synthetic_provider.next_observation()
        return engine.process_observation(observation)

    @app.post("/api/v1/monitoring/passive/start")
    def start_passive_monitoring(request: Request) -> dict[str, str | bool]:
        if not _request_is_loopback(request):
            raise HTTPException(
                status_code=403,
                detail="Passive monitoring controls are restricted to loopback clients.",
            )
        if not selected_settings.passive_capture_enabled:
            raise HTTPException(
                status_code=403,
                detail=(
                    "Passive capture is disabled. Set "
                    "SECURITY_ENGINE_PASSIVE_CAPTURE_ENABLED=true to enable it."
                ),
            )
        try:
            selected_passive_provider.start()
        except ObservationProviderError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error
        return {"running": selected_passive_provider.running}

    @app.post("/api/v1/monitoring/passive/stop")
    def stop_passive_monitoring(request: Request) -> dict[str, str | bool]:
        if not _request_is_loopback(request):
            raise HTTPException(
                status_code=403,
                detail="Passive monitoring controls are restricted to loopback clients.",
            )
        try:
            selected_passive_provider.stop()
        except ObservationProviderError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error
        return {"running": selected_passive_provider.running}

    return app


def _request_is_loopback(request: Request) -> bool:
    client = request.client
    if client is None:
        return False
    try:
        return ipaddress.ip_address(client.host).is_loopback
    except ValueError:
        return False


def _request_origin_is_loopback(request: Request) -> bool:
    origin = request.headers.get("origin")
    if origin is None:
        return True
    try:
        hostname = urlparse(origin).hostname
    except ValueError:
        return False
    if hostname is None:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _validate_device_token(
    configured_token: str | None,
    presented_token: str | None,
) -> None:
    if not configured_token:
        raise HTTPException(
            status_code=503,
            detail="Device control is not configured on the backend.",
        )
    if presented_token is None or not secrets.compare_digest(
        configured_token,
        presented_token,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid device control token.",
        )


app = create_app()
