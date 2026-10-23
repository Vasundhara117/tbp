"""Request and response models used by the HTTP API."""

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr


class MessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    device_type: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    message_id: Annotated[StrictStr, Field(min_length=1, max_length=128)]
    timestamp_ms: Annotated[StrictInt, Field(ge=0)]
    data: dict[str, Any]


class AlertResponse(BaseModel):
    alert_id: str
    device_id: str
    category: str
    severity: str
    evidence: dict[str, int | float]
    summary: str
    timestamp_ms: int


class DeviceObservation(BaseModel):
    messages_in_window: int
    message_window_seconds: float
    bytes_in_window: int
    byte_window_seconds: float


class MessageResponse(BaseModel):
    device_id: str
    registered: bool
    message_id: str
    received_at_ms: int
    request_size_bytes: int
    observations: DeviceObservation
    alerts: list[AlertResponse]


class DeviceResponse(BaseModel):
    device_id: str
    device_type: str | None
    registered: bool
    authorized: bool
    last_seen_ms: int | None
    messages_in_window: int
    bytes_in_window: int


class DeviceListResponse(BaseModel):
    devices: list[DeviceResponse]
    count: int


class AlertListResponse(BaseModel):
    alerts: list[AlertResponse]
    count: int


class HealthResponse(BaseModel):
    status: str
