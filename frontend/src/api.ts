export type Device = {
  device_id?: string;
  device_type?: string | null;
  registered?: boolean;
  authorized?: boolean;
  last_seen_ms?: number | null;
  messages_in_window?: number;
  bytes_in_window?: number;
  ip_address?: string | null;
  mac_address?: string | null;
  [key: string]: unknown;
};

export type Alert = {
  alert_id?: string;
  device_id?: string;
  category?: string;
  severity?: string;
  summary?: string;
  timestamp_ms?: number;
  evidence?: Record<string, unknown>;
  [key: string]: unknown;
};

export type EndpointResult<T> = {
  data: T | null;
  error: string | null;
};

export type Snapshot = {
  health: EndpointResult<Record<string, unknown>>;
  devices: EndpointResult<Device[]>;
  alerts: EndpointResult<Alert[]>;
  fetchedAt: string;
};

export type DeviceControlStatus = {
  device_id: string;
  status: string;
  mode: string;
  duration_seconds: number;
  command_id: string;
  updated_at_ms: number;
  connected: boolean;
  last_seen_ms: number;
  control_configured: boolean;
};

async function responseError(response: Response, label: string): Promise<Error> {
  let detail = `HTTP ${response.status}`;
  try {
    const body: unknown = await response.json();
    if (body && typeof body === "object" && "detail" in body) {
      detail = String(body.detail);
    }
  } catch {
    // Keep the HTTP status when the server does not return a JSON error body.
  }
  return new Error(`${label}: ${detail}`);
}

export async function getDeviceControlStatus(): Promise<DeviceControlStatus> {
  const response = await fetch("/api/v1/device-control/status", {
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    throw await responseError(response, "Device status");
  }
  return (await response.json()) as DeviceControlStatus;
}

export async function sendHardwareCommand(
  mode: "normal" | "burst",
): Promise<{ command_id: string; status: string }> {
  const response = await fetch("/api/v1/device-control/commands", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ mode, duration_seconds: 10 }),
  });
  if (!response.ok) {
    throw await responseError(response, "ESP32 command");
  }
  return (await response.json()) as { command_id: string; status: string };
}

export async function sendDemoMessage(
  deviceId: string,
  runId: string,
  sequence: number,
): Promise<void> {
  const response = await fetch("/api/v1/messages", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      device_id: deviceId,
      device_type: "presentation_demo",
      message_id: `demo-${runId}-${sequence}`,
      timestamp_ms: Date.now(),
      data: {
        status: "online",
        activity: "presentation_demo",
        sequence,
      },
    }),
  });

  if (!response.ok) {
    throw new Error(`Demo message ${sequence} was rejected with HTTP ${response.status}.`);
  }
}

function extractRecords<T>(payload: unknown, keys: string[], label: string): T[] {
  const rows = Array.isArray(payload)
    ? payload
    : payload && typeof payload === "object"
      ? keys.map((key) => (payload as Record<string, unknown>)[key]).find(Array.isArray)
      : undefined;

  if (!Array.isArray(rows) || !rows.every((row) => row && typeof row === "object" && !Array.isArray(row))) {
    throw new Error(`Backend ${label} response has an unsupported shape.`);
  }
  return rows as T[];
}

async function getJson<T>(path: string, label: string): Promise<EndpointResult<T>> {
  try {
    const response = await fetch(path, { headers: { Accept: "application/json" } });
    if (!response.ok) {
      throw new Error(`Backend returned HTTP ${response.status}.`);
    }
    return { data: (await response.json()) as T, error: null };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Request failed.";
    return {
      data: null,
      error: message === "Failed to fetch" ? "Backend is unreachable." : `${label}: ${message}`,
    };
  }
}

export async function loadSnapshot(): Promise<Snapshot> {
  const [healthResult, devicesResult, alertsResult] = await Promise.all([
    getJson<Record<string, unknown>>("/api/v1/health", "Health check"),
    getJson<unknown>("/api/v1/devices", "Devices"),
    getJson<unknown>("/api/v1/alerts", "Alerts"),
  ]);

  let devices: EndpointResult<Device[]> = { data: null, error: devicesResult.error };
  if (devicesResult.data !== null) {
    try {
      devices = {
        data: extractRecords<Device>(devicesResult.data, ["devices", "items", "results"], "device"),
        error: null,
      };
    } catch (error) {
      devices = { data: null, error: error instanceof Error ? error.message : "Invalid device response." };
    }
  }

  let alerts: EndpointResult<Alert[]> = { data: null, error: alertsResult.error };
  if (alertsResult.data !== null) {
    try {
      alerts = {
        data: extractRecords<Alert>(alertsResult.data, ["alerts", "items", "results"], "alert"),
        error: null,
      };
    } catch (error) {
      alerts = { data: null, error: error instanceof Error ? error.message : "Invalid alert response." };
    }
  }

  return {
    health: healthResult,
    devices,
    alerts,
    fetchedAt: new Date().toISOString(),
  };
}
