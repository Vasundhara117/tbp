import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  getDeviceControlStatus,
  loadSnapshot,
  sendDemoMessage,
  sendHardwareCommand,
  type Alert,
  type Device,
  type DeviceControlStatus,
  type Snapshot,
} from "./api";

type View = "overview" | "devices" | "alerts";

const severityOrder = ["critical", "high", "medium", "low"];
const DEMO_MESSAGE_COUNT = 24;

function safeText(value: unknown, fallback = "Unavailable"): string {
  if (value === null || value === undefined || value === "") return fallback;
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function formatTime(value?: number | null): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "Unavailable";
  return new Date(value).toLocaleString();
}

function severity(alert: Alert): string {
  return safeText(alert.severity, "unknown").toLowerCase();
}

function authorized(device: Device): boolean | null {
  return typeof device.authorized === "boolean" ? device.authorized : null;
}

function App() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [view, setView] = useState<View>("overview");
  const [deviceQuery, setDeviceQuery] = useState("");
  const [alertQuery, setAlertQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [demoRunning, setDemoRunning] = useState(false);
  const [demoProgress, setDemoProgress] = useState(0);
  const [demoMessage, setDemoMessage] = useState("");
  const demoLock = useRef(false);
  const [hardwareStatus, setHardwareStatus] = useState<DeviceControlStatus | null>(null);
  const [hardwareStatusError, setHardwareStatusError] = useState("");
  const [hardwareCommandBusy, setHardwareCommandBusy] = useState(false);
  const [hardwareCommandMessage, setHardwareCommandMessage] = useState("");
  const activeHardwareCommandId = useRef<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setRefreshError(null);
    try {
      setSnapshot(await loadSnapshot());
    } catch (error) {
      setRefreshError(error instanceof Error ? error.message : "Could not load dashboard data.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!autoRefresh || demoRunning) return;
    const timer = window.setInterval(() => void refresh(), 10_000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, demoRunning, refresh]);

  const refreshHardwareStatus = useCallback(async () => {
    try {
      setHardwareStatus(await getDeviceControlStatus());
      setHardwareStatusError("");
    } catch (error) {
      setHardwareStatus(null);
      setHardwareStatusError(error instanceof Error ? error.message : "Could not read ESP32 control status.");
    }
  }, []);

  useEffect(() => {
    void refreshHardwareStatus();
    const timer = window.setInterval(() => void refreshHardwareStatus(), 2_000);
    return () => window.clearInterval(timer);
  }, [refreshHardwareStatus]);

  useEffect(() => {
    if (
      !hardwareStatus ||
      hardwareStatus.command_id !== activeHardwareCommandId.current
    ) {
      return;
    }

    if (hardwareStatus.status === "expired") {
      activeHardwareCommandId.current = null;
      setHardwareCommandMessage("The ESP32 did not collect the command in time. Confirm it is online and retry.");
      return;
    }

    if (hardwareStatus.status === "completed" && hardwareStatus.mode === "burst") {
      activeHardwareCommandId.current = null;
      setView("alerts");
      setAlertQuery("ESP32-01");
      setSeverityFilter("all");
      setCategoryFilter("all");
      setHardwareCommandMessage("ESP32 burst completed. Loading its backend alerts…");
      void refresh();
      return;
    }

    if (hardwareStatus.status === "completed") {
      activeHardwareCommandId.current = null;
    }
  }, [hardwareStatus, refresh]);

  const sendHardwareAction = useCallback(async (mode: "normal" | "burst") => {
    setHardwareCommandBusy(true);
    setHardwareCommandMessage("");
    try {
      const command = await sendHardwareCommand(mode);
      activeHardwareCommandId.current = command.command_id;
      setHardwareCommandMessage(
        mode === "burst"
          ? "10-second burst queued. The ESP32 will run it when it polls the backend."
          : "NORMAL mode queued. The ESP32 will stop its burst and resume five-second heartbeats.",
      );
      await refreshHardwareStatus();
      return command.command_id;
    } catch (error) {
      setHardwareCommandMessage(error instanceof Error ? error.message : "Could not send a command to the ESP32.");
      return null;
    } finally {
      setHardwareCommandBusy(false);
    }
  }, [refreshHardwareStatus]);

  const runPresentationDemo = useCallback(async () => {
    if (demoLock.current) return;
    demoLock.current = true;
    const runId = Date.now().toString(36).toUpperCase();
    const deviceId = `DEMO-${runId}`;
    setDemoRunning(true);
    setDemoProgress(0);
    setDemoMessage(`Starting a clearly labeled demo device: ${deviceId}.`);
    setAlertQuery("DEMO");
    setSeverityFilter("all");
    setCategoryFilter("all");
    setSelectedAlertId(null);

    try {
      await sendDemoMessage(`SIM-${runId}-02`, runId, 102);
      await sendDemoMessage(`SIM-${runId}-03`, runId, 103);
      for (let sequence = 1; sequence <= DEMO_MESSAGE_COUNT; sequence += 1) {
        await sendDemoMessage(deviceId, runId, sequence);
        setDemoProgress(sequence);
        setDemoMessage(`Sending presentation traffic · ${sequence} of ${DEMO_MESSAGE_COUNT}`);
        if (sequence < DEMO_MESSAGE_COUNT) {
          await new Promise((resolve) => window.setTimeout(resolve, 120));
        }
      }

      setDemoMessage("Demo traffic sent. Loading the resulting backend alerts…");
      setView("alerts");
      await refresh();
      setDemoMessage(`Demo complete: three clearly labeled virtual devices were generated. Review the alert for ${deviceId}.`);
    } catch (error) {
      setDemoMessage(error instanceof Error ? error.message : "The presentation demo failed.");
      await refresh();
    } finally {
      demoLock.current = false;
      setDemoRunning(false);
    }
  }, [refresh]);

  const devices = snapshot?.devices.data ?? [];
  const alerts = snapshot?.alerts.data ?? [];
  const hardwareOnline = hardwareStatus?.connected ?? false;
  const filteredDevices = useMemo(() => {
    const query = deviceQuery.trim().toLowerCase();
    return devices.filter((device) => !query || JSON.stringify(device).toLowerCase().includes(query));
  }, [devices, deviceQuery]);
  const filteredAlerts = useMemo(() => {
    const query = alertQuery.trim().toLowerCase();
    return alerts.filter((alert) => {
      const matchesText = !query || JSON.stringify(alert).toLowerCase().includes(query);
      const matchesSeverity = severityFilter === "all" || severity(alert) === severityFilter;
      const matchesCategory = categoryFilter === "all" || alert.category === categoryFilter;
      return matchesText && matchesSeverity && matchesCategory;
    });
  }, [alerts, alertQuery, categoryFilter, severityFilter]);
  const categories = [...new Set(alerts.map((alert) => alert.category).filter((category): category is string => typeof category === "string"))].sort();
  const selectedAlert = alerts.find((alert) => alert.alert_id === selectedAlertId) ?? filteredAlerts[0] ?? null;

  const authorizedCount = devices.filter((device) => authorized(device) === true).length;
  const unauthorizedCount = devices.filter((device) => authorized(device) === false).length;
  const criticalCount = alerts.filter((alert) => severity(alert) === "critical").length;
  const severeCount = alerts.filter((alert) => ["critical", "high"].includes(severity(alert))).length;
  const severityCounts = severityOrder.map((level) => ({
    level,
    count: alerts.filter((alert) => severity(alert) === level).length,
  })).filter((item) => item.count > 0);

  const endpointErrors = [
    snapshot?.health.error,
    snapshot?.devices.error,
    snapshot?.alerts.error,
    refreshError,
  ].filter((message): message is string => Boolean(message));
  const live = Boolean(snapshot?.devices.data && snapshot.alerts.data);
  const hardwareCommandWaiting = ["queued", "delivered"].includes(
    hardwareStatus?.status ?? "",
  );
  const hardwareBurstActive =
    hardwareStatus?.status === "started" && hardwareStatus.mode === "burst";
  const hardwareControlsReady =
    hardwareOnline &&
    Boolean(hardwareStatus?.control_configured) &&
    !hardwareCommandBusy &&
    !hardwareCommandWaiting &&
    !demoRunning;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">S</div>
          <div><strong>sentinel</strong><span>SECUREIOT</span></div>
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav className="nav-list" aria-label="Dashboard sections">
          {(["overview", "devices", "alerts"] as const).map((item) => (
            <button key={item} className={`nav-item ${view === item ? "active" : ""}`} onClick={() => setView(item)}>
              <span className="nav-icon">{item === "overview" ? "◫" : item === "devices" ? "▦" : "⌁"}</span>
              <span>{item === "overview" ? "Overview" : item === "devices" ? "Devices" : "Security alerts"}</span>
              {item === "devices" && <span className="nav-count">{devices.length}</span>}
              {item === "alerts" && alerts.length > 0 && <span className="nav-count">{alerts.length}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="connection-card">
            <span className={`status-dot ${live ? "online" : "offline"}`} />
            <div><strong>{live ? "Backend connected" : "Backend unavailable"}</strong><span>API · /api/v1</span></div>
          </div>
          <div className="sidebar-foot">SENTINEL CONSOLE <span>v1.0</span></div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">Security monitoring <span>/</span> <strong>{viewLabel(view)}</strong></div>
          <div className="topbar-actions">
            <label className="auto-refresh">
              <input type="checkbox" checked={autoRefresh} onChange={(event) => setAutoRefresh(event.target.checked)} />
              <span className="toggle-track" />
              <span>Auto-refresh</span>
            </label>
            <button className="refresh-button" onClick={() => void refresh()} disabled={loading || demoRunning}>
              <span className={loading ? "spin" : ""}>↻</span> {loading ? "Updating" : "Refresh"}
            </button>
          </div>
        </header>

        <div className="page-content">
          <section className="page-heading">
            <div>
              <div className="eyebrow"><span className={`status-dot ${live ? "online" : "offline"}`} /> {live ? "LIVE BACKEND DATA" : "CONNECTING TO BACKEND"}</div>
              <h1>{view === "overview" ? "Security overview" : view === "devices" ? "Device inventory" : "Security alerts"}</h1>
              <p>{viewDescription(view)}</p>
            </div>
            <div className="last-updated">
              <span>LAST UPDATED</span>
              <strong>{snapshot ? formatTime(Date.parse(snapshot.fetchedAt)) : "Waiting for backend"}</strong>
            </div>
          </section>

          {endpointErrors.length > 0 && (
            <div className="error-banner" role="status">
              <span className="error-icon">!</span>
              <div><strong>Some backend data could not be loaded</strong><p>{[...new Set(endpointErrors)].join(" ")}</p></div>
              <button onClick={() => void refresh()}>Retry</button>
            </div>
          )}

          {demoMessage && (
            <div className={`demo-status ${demoRunning ? "running" : demoMessage.startsWith("Demo complete") ? "complete" : "failed"}`} role="status">
              <span className="demo-status-icon">{demoRunning ? "↻" : demoMessage.startsWith("Demo complete") ? "✓" : "!"}</span>
              <div className="demo-status-copy">
                <strong>{demoRunning ? "Presentation demo in progress" : demoMessage.startsWith("Demo complete") ? "Presentation demo complete" : "Presentation demo update"}</strong>
                <p>{demoMessage}</p>
                {demoRunning && <div className="demo-progress-track"><span style={{ width: `${(demoProgress / DEMO_MESSAGE_COUNT) * 100}%` }} /></div>}
              </div>
              {!demoRunning && <button className="dismiss-button" onClick={() => setDemoMessage("")} aria-label="Dismiss demo status">×</button>}
            </div>
          )}

          {view === "overview" && (
            <>
              <section className="demo-banner">
                <div className="demo-art hardware-art" aria-hidden="true"><span>⌁</span><i /><i /><i /></div>
                <div className="demo-copy">
                  <div className="demo-eyebrow"><span className={`demo-live-dot ${hardwareOnline ? "" : "waiting"}`} /> PHYSICAL HARDWARE <span className="demo-pill hardware-pill">ESP32</span></div>
                  <h2>Run the alert demo on your device</h2>
                  <p>Use your actual ESP32 to generate traffic. The backend evaluates every message using its normal detection rules.</p>
                  <div className="hardware-seen">
                    <span className={`status-dot ${hardwareOnline ? "online" : "offline"}`} />
                    {hardwareOnline
                      ? <>ESP32-01 online · last heartbeat {formatTime(hardwareStatus?.last_seen_ms)}</>
                      : "ESP32-01 offline · waiting for a recent heartbeat"}
                  </div>
                </div>
                <div className="hardware-steps">
                  <div><span>01</span><p>Configure Wi-Fi and your PC’s LAN IP in the sketch</p></div>
                  <div><span>02</span><p>Upload firmware; open Serial Monitor at <b>115200</b></p></div>
                  <div><span>03</span><p>Enter <code>BURST 10</code> and press Enter</p></div>
                  <div><span>04</span><p>Refresh alerts; expect <b>HIGH_MESSAGE_RATE</b></p></div>
                </div>
                <div className="hardware-controls">
                  <div className="hardware-control-heading">
                    <div><strong>Hardware controls</strong><span>Commands run on ESP32-01; it must be online and paired.</span></div>
                    <span className={`command-state ${hardwareStatus?.status ?? "idle"}`}>{hardwareStatus?.status ?? "checking"}</span>
                  </div>
                  <div className="hardware-control-actions">
                    <button className="normal-control" onClick={() => void sendHardwareAction("normal")} disabled={!hardwareOnline || !hardwareStatus?.control_configured || hardwareCommandBusy || hardwareCommandWaiting || demoRunning}>
                      {hardwareCommandBusy ? "Sending…" : "Normal mode"}
                    </button>
                    <button className="burst-control" onClick={() => void sendHardwareAction("burst")} disabled={!hardwareControlsReady || hardwareBurstActive}>
                      {hardwareCommandBusy ? "Sending…" : hardwareCommandWaiting ? "Waiting for ESP32…" : hardwareBurstActive ? "Burst active" : "Start 10-second burst"}
                    </button>
                  </div>
                  {hardwareCommandWaiting && (
                    <p className="control-help">A command is waiting for the ESP32 to poll the backend. Keep the board powered and allow up to 20 seconds for delivery.</p>
                  )}
                  {hardwareStatus && !hardwareStatus.control_configured && (
                    <p className="control-help">Pairing is not configured. Set <code>SECURITY_ENGINE_DEVICE_CONTROL_TOKEN</code> on the backend and the matching token in the firmware, then restart both.</p>
                  )}
                  {hardwareCommandMessage && <p className={`control-message ${hardwareCommandMessage.includes("queued") ? "success" : "error"}`} role="status">{hardwareCommandMessage}</p>}
                  {hardwareStatusError && <p className="control-message error" role="status">{hardwareStatusError}</p>}
                </div>
              </section>
              <section className="browser-demo-strip">
                <div className="browser-demo-copy">
                  <span className="browser-demo-icon">⌘</span>
                  <div><strong>Need a fallback for recording?</strong><p>Generate three clearly labeled virtual devices if the physical ESP32 is unavailable.</p></div>
                </div>
                <button className="browser-demo-button" onClick={() => void runPresentationDemo()} disabled={demoRunning || !snapshot?.health.data}>
                  {demoRunning ? "Running simulation…" : "Simulate in browser"} <span>→</span>
                </button>
              </section>
              <section className="metric-grid">
                <MetricCard label="Device records" value={devices.length} note="Returned by the backend" icon="▦" tone="blue" />
                <MetricCard label="Authorized" value={authorizedCount} note={unauthorizedCount ? `${unauthorizedCount} unauthorized` : "Explicit backend classifications"} icon="✓" tone="green" />
                <MetricCard label="Security alerts" value={alerts.length} note="Current alert history" icon="⌁" tone="amber" />
                <MetricCard label="Critical alerts" value={criticalCount} note={severeCount ? `${severeCount} critical or high` : "No high severity alerts"} icon="!" tone="red" />
              </section>
              <div className="overview-grid">
                <section className="panel severity-panel">
                  <PanelHeading title="Alert severity" detail="Distribution of returned alerts" />
                  {severityCounts.length ? (
                    <div className="severity-list">
                      {severityCounts.map(({ level, count }) => (
                        <div className="severity-row" key={level}>
                          <span className={`severity-badge ${level}`}>{level}</span>
                          <div className="bar-track"><span className={`bar-fill ${level}`} style={{ width: `${Math.max(4, (count / Math.max(alerts.length, 1)) * 100)}%` }} /></div>
                          <strong>{count}</strong>
                        </div>
                      ))}
                    </div>
                  ) : <EmptyState title="No alerts to summarize" detail="Alerts returned by the backend will appear here." />}
                  <p className="panel-footnote">Counts reflect backend alert records; they are not unique incident counts.</p>
                </section>
                <section className="panel connection-panel">
                  <PanelHeading title="System connection" detail="Backend API status" />
                  <div className="connection-state">
                    <div className={`connection-symbol ${live ? "good" : "bad"}`}>{live ? "✓" : "!"}</div>
                    <div><strong>{live ? "Backend responding" : "Waiting for a backend response"}</strong><p>{snapshot?.health.data ? "Health endpoint responded successfully." : snapshot?.health.error ?? "Fetching API health and device data…"}</p></div>
                  </div>
                  <div className="endpoint-list">
                    <EndpointStatus label="Health check" ok={snapshot?.health.data !== null && snapshot?.health.data !== undefined} />
                    <EndpointStatus label="Device inventory" ok={snapshot?.devices.data !== null && snapshot?.devices.data !== undefined} />
                    <EndpointStatus label="Security alerts" ok={snapshot?.alerts.data !== null && snapshot?.alerts.data !== undefined} />
                  </div>
                </section>
              </div>
              <section className="panel table-panel">
                <PanelHeading title="Recent security alerts" detail="Latest records from the backend" action={<button className="text-button" onClick={() => setView("alerts")}>View all alerts <span>→</span></button>} />
                <AlertTable alerts={alerts.slice(0, 5)} onSelect={(alert) => { setSelectedAlertId(alert.alert_id ?? null); setView("alerts"); }} />
              </section>
              <section className="panel table-panel">
                <PanelHeading title="Connected devices" detail="Device records known to the backend" action={<button className="text-button" onClick={() => setView("devices")}>View devices <span>→</span></button>} />
                <DeviceTable devices={devices.slice(0, 5)} />
              </section>
            </>
          )}

          {view === "devices" && (
            <section className="panel table-panel full-panel">
              <PanelHeading title="All devices" detail={`${filteredDevices.length} device records`} />
              <div className="table-controls">
                <SearchInput value={deviceQuery} onChange={setDeviceQuery} placeholder="Search by device, type, IP…" />
              </div>
              <DeviceTable devices={filteredDevices} />
            </section>
          )}

          {view === "alerts" && (
            <div className="alerts-layout">
              <section className="panel table-panel full-panel">
                <PanelHeading title="All security alerts" detail={`${filteredAlerts.length} alert records`} />
                <div className="table-controls">
                  <SearchInput value={alertQuery} onChange={setAlertQuery} placeholder="Search alerts, devices, evidence…" />
                  <select className="filter-select" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)} aria-label="Filter by severity">
                    <option value="all">All severities</option>
                    {severityOrder.map((level) => <option value={level} key={level}>{capitalize(level)}</option>)}
                  </select>
                  <select className="filter-select" value={categoryFilter} onChange={(event) => setCategoryFilter(event.target.value)} aria-label="Filter by category">
                    <option value="all">All categories</option>
                    {categories.map((category) => <option value={category} key={category}>{category.replaceAll("_", " ")}</option>)}
                  </select>
                </div>
                <AlertTable alerts={filteredAlerts} onSelect={(alert) => setSelectedAlertId(alert.alert_id ?? null)} selectedId={selectedAlert?.alert_id} />
              </section>
              <AlertDetails alert={selectedAlert} />
            </div>
          )}

          <footer className="page-footer">SecureIoT Sentinel is a prototype. Review backend evidence before taking action.</footer>
        </div>
      </main>
    </div>
  );
}

function viewLabel(view: View): string {
  return view === "overview" ? "Overview" : view === "devices" ? "Devices" : "Security alerts";
}

function viewDescription(view: View): string {
  if (view === "devices") return "Review device records and their reported authorization and activity.";
  if (view === "alerts") return "Inspect alert evidence reported by the backend detection engine.";
  return "A clear view of device records, backend health, and reported security alerts.";
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function MetricCard({ label, value, note, icon, tone }: { label: string; value: number; note: string; icon: string; tone: string }) {
  return <article className="metric-card"><div className={`metric-icon ${tone}`}>{icon}</div><span className="metric-label">{label}</span><strong className="metric-value">{value}</strong><span className="metric-note">{note}</span></article>;
}

function PanelHeading({ title, detail, action }: { title: string; detail: string; action?: ReactNode }) {
  return <div className="panel-heading"><div><h2>{title}</h2><p>{detail}</p></div>{action}</div>;
}

function EndpointStatus({ label, ok }: { label: string; ok: boolean }) {
  return <div className="endpoint-row"><span><span className={`status-dot ${ok ? "online" : "offline"}`} />{label}</span><strong className={ok ? "endpoint-ok" : "endpoint-wait"}>{ok ? "Operational" : "Unavailable"}</strong></div>;
}

function EmptyState({ title, detail }: { title: string; detail: string }) {
  return <div className="empty-state"><div className="empty-mark">—</div><strong>{title}</strong><p>{detail}</p></div>;
}

function SearchInput({ value, onChange, placeholder }: { value: string; onChange: (value: string) => void; placeholder: string }) {
  return <label className="search-box"><span>⌕</span><input value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} /></label>;
}

function DeviceTable({ devices }: { devices: Device[] }) {
  if (!devices.length) return <EmptyState title="No device records" detail="Device records will show here when the backend receives messages." />;
  return (
    <div className="table-scroll"><table><thead><tr><th>DEVICE</th><th>KIND</th><th>TYPE</th><th>IP ADDRESS</th><th>REGISTERED</th><th>AUTHORIZATION</th><th>MESSAGES</th><th>LAST SEEN</th></tr></thead>
      <tbody>{devices.map((device, index) => {
        const id = safeText(device.device_id, "Unknown device");
        const auth = authorized(device);
        const simulated = id.startsWith("DEMO-") || id.startsWith("SIM-");
        return <tr key={`${id}-${index}`}><td><span className="device-cell"><span className="device-avatar">{id.slice(0, 1).toUpperCase()}</span><strong>{id}</strong></span></td><td><DeviceKindBadge simulated={simulated} /></td><td>{safeText(device.device_type)}</td><td className="mono">{safeText(device.ip_address)}</td><td>{safeText(device.registered)}</td><td><StatusBadge value={auth === null ? "unclassified" : auth ? "authorized" : "unauthorized"} /></td><td>{safeText(device.messages_in_window, "0")}</td><td>{formatTime(device.last_seen_ms)}</td></tr>;
      })}</tbody>
    </table></div>
  );
}

function DeviceKindBadge({ simulated }: { simulated: boolean }) {
  return <span className={`device-kind ${simulated ? "simulated" : "physical"}`}>{simulated ? "Simulated" : "Physical"}</span>;
}

function AlertTable({ alerts, onSelect, selectedId }: { alerts: Alert[]; onSelect?: (alert: Alert) => void; selectedId?: string }) {
  if (!alerts.length) return <EmptyState title="No alerts found" detail="No alert records match this view." />;
  return (
    <div className="table-scroll"><table><thead><tr><th>ALERT</th><th>DEVICE</th><th>CATEGORY</th><th>SEVERITY</th><th>TIME</th></tr></thead>
      <tbody>{alerts.map((alert, index) => {
        const id = safeText(alert.alert_id, `Alert ${index + 1}`);
        const row = <tr key={`${id}-${index}`} className={selectedId === alert.alert_id ? "selected-row" : ""} onClick={() => onSelect?.(alert)} tabIndex={onSelect ? 0 : undefined} onKeyDown={(event) => { if (onSelect && (event.key === "Enter" || event.key === " ")) onSelect(alert); }}>
          <td><span className="alert-id">{id}</span></td><td>{safeText(alert.device_id)}</td><td>{safeText(alert.category)}</td><td><SeverityBadge value={severity(alert)} /></td><td>{formatTime(alert.timestamp_ms)}</td>
        </tr>;
        return row;
      })}</tbody>
    </table></div>
  );
}

function StatusBadge({ value }: { value: string }) {
  return <span className={`status-badge ${value}`}>{value.replace("-", " ")}</span>;
}

function SeverityBadge({ value }: { value: string }) {
  return <span className={`severity-badge ${value}`}>{value}</span>;
}

function AlertDetails({ alert }: { alert: Alert | null }) {
  if (!alert) return <section className="panel detail-panel"><EmptyState title="Select an alert" detail="Choose a row to inspect the backend evidence." /></section>;
  const title = safeText(alert.category, "Security alert").replaceAll("_", " ");
  const recommendation = severity(alert) === "critical" || severity(alert) === "high"
    ? "Review the device activity and verify whether it is expected."
    : "Review the alert evidence and compare it with expected device activity.";
  return (
    <section className="panel detail-panel">
      <div className="detail-eyebrow"><SeverityBadge value={severity(alert)} /><span>ALERT DETAILS</span></div>
      <h2>{capitalize(title)}</h2>
      <p className="detail-summary">{safeText(alert.summary, "The backend reported an alert. The evidence alone does not establish intent or impact.")}</p>
      <div className="detail-meta"><div><span>DEVICE</span><strong>{safeText(alert.device_id)}</strong></div><div><span>REPORTED</span><strong>{formatTime(alert.timestamp_ms)}</strong></div></div>
      <div className="detail-section"><h3>Reported evidence</h3><pre>{JSON.stringify(alert.evidence ?? {}, null, 2)}</pre></div>
      <div className="recommendation"><span>REVIEW SUGGESTION</span><p>{recommendation}</p><small>Template guidance only · administrator review required</small></div>
      <details className="raw-record"><summary>View original alert record</summary><pre>{JSON.stringify(alert, null, 2)}</pre></details>
    </section>
  );
}

export default App;
