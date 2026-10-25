"""Request and response models used by the HTTP API."""

import ipaddress
import re
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
)


class MessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    device_type: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    message_id: Annotated[StrictStr, Field(min_length=1, max_length=128)]
    timestamp_ms: Annotated[StrictInt, Field(ge=0)]
    data: dict[str, Any]


class NetworkObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observation_id: Annotated[StrictStr, Field(min_length=1, max_length=128)] | None = None
    device_id: Annotated[StrictStr, Field(min_length=1, max_length=64)] | None = None
    mac_address: Annotated[StrictStr, Field(min_length=1, max_length=17)] | None = None
    ip_address: Annotated[StrictStr, Field(min_length=1, max_length=45)] | None = None
    timestamp_ms: Annotated[StrictInt, Field(ge=0)] | None = None
    source: Annotated[StrictStr, Field(min_length=1, max_length=64)] = "api"
    device_type: Annotated[StrictStr, Field(min_length=1, max_length=64)] | None = None
    message_count: Annotated[StrictInt, Field(ge=0, le=1_000_000)] | None = None
    packet_count: Annotated[StrictInt, Field(ge=0, le=1_000_000)] | None = None
    byte_count: Annotated[StrictInt, Field(ge=0, le=1_000_000_000)] | None = None
    destination_ip: Annotated[StrictStr, Field(min_length=1, max_length=45)] | None = None
    protocol: Annotated[StrictStr, Field(min_length=1, max_length=32)] | None = None
    simulated: StrictBool = False

    @field_validator("mac_address")
    @classmethod
    def normalize_mac_address(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", value):
            raise ValueError("mac_address must contain six hexadecimal octets")
        return value.replace("-", ":").lower()

    @field_validator("ip_address", "destination_ip")
    @classmethod
    def normalize_ip_address(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as error:
            raise ValueError("must be a valid IPv4 or IPv6 address") from error


class AlertResponse(BaseModel):
    alert_id: str
    device_id: str
    category: str
    severity: str
    evidence: dict[str, int | float | str | bool | None]
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
    device_record_id: str | None = None
    mac_address: str | None = None
    ip_address: str | None = None
    first_seen_ms: int | None = None
    observation_source: str | None = None
    packet_count_in_window: int = 0


class DeviceListResponse(BaseModel):
    devices: list[DeviceResponse]
    count: int


class AlertListResponse(BaseModel):
    alerts: list[AlertResponse]
    count: int


class HealthResponse(BaseModel):
    status: str


class ObservationIngestResponse(BaseModel):
    observation_id: str | None
    timestamp_ms: int | None
    observation_source: str
    simulated: bool
    device_record_id: str
    device_id: str
    authorized: bool
    alerts: list[AlertResponse]


class MonitoringStatusResponse(BaseModel):
    synthetic_available: bool
    passive_capture_enabled: bool
    passive_capture_running: bool
    passive_capture_interface: str | None
    platform: str
    scapy_available: bool
    error: str | None
