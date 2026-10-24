"""Streamlit dashboard for SecureIoT Sentinel."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

import streamlit as st

# Support the documented `streamlit run dashboard_ai/app.py` invocation.
_MODULE_DIR = str(Path(__file__).resolve().parent)
if _MODULE_DIR not in sys.path:
    sys.path.insert(0, _MODULE_DIR)

from api_client import load_snapshot
from incident_ai import generate_incident_report
from sample_data import get_demo_data

st.set_page_config(page_title="SecureIoT Sentinel | Security Monitor", layout="wide")
st.markdown("""
<style>
:root { --ink:#172334; --muted:#5d6978; --line:#d8dee7; --surface:#fff; }
[data-testid="stAppViewContainer"] { background:#f4f6f8; color:var(--ink); }
[data-testid="stHeader"] { background:rgba(244,246,248,.96); }
[data-testid="stMetric"] { background:var(--surface); border:1px solid var(--line); padding:12px 14px; border-radius:4px; }
[data-testid="stDataFrame"] { border:1px solid var(--line); }
hr { border-color:var(--line); }
.small-note { color:var(--muted); font-size:.88rem; }
</style>
""", unsafe_allow_html=True)

st.title("SecureIoT Sentinel")
st.caption("Security monitoring · local prototype")

if "snapshot" not in st.session_state:
    st.session_state.snapshot = None
if "load_time" not in st.session_state:
    st.session_state.load_time = None

col_refresh, col_state = st.columns([1, 4])
with col_refresh:
    refresh = st.button("Refresh backend", type="primary")
if st.session_state.snapshot is None or refresh:
    with st.spinner("Fetching backend data…"):
        st.session_state.snapshot = load_snapshot()
        st.session_state.load_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
snapshot = st.session_state.snapshot

health_ok = snapshot["health"].ok
live_data_ok = snapshot["devices"].ok and snapshot["alerts"].ok
if live_data_ok:
    devices = snapshot["devices"].data
    alerts = snapshot["alerts"].data
    mode = "LIVE BACKEND DATA"
    with col_state:
        st.success(f"{mode} · last fetched {st.session_state.load_time}")
    st.caption("The confirmed API fields do not report independent network-observer availability; records below are backend API responses.")
    if not health_ok:
        st.warning("Health check unavailable; device and alert endpoints responded successfully.")
else:
    devices, alerts = get_demo_data()
    mode = "DEMO MODE"
    with col_state:
        st.error("DEMO MODE: Synthetic data. These records are not live network observations.")
    failed = [name for name in ("health", "devices", "alerts") if not snapshot[name].ok]
    if failed:
        st.caption("Backend status: " + " · ".join(f"{n}: {snapshot[n].error}" for n in failed))
    st.info("Use **Refresh backend** to retry. Demo records are kept separate from backend data.")


def first(record, *keys):
    return next((record[k] for k in keys if k in record and record[k] is not None), None)

def display(value):
    if value is None or value == "": return "Unavailable"
    if isinstance(value, (dict, list)): return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)

def format_timestamp_ms(value):
    """Format a Unix timestamp in milliseconds in the machine's local timezone."""
    if value is None or value == "": return "Unavailable"
    try:
        return datetime.fromtimestamp(float(value) / 1000).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    except (TypeError, ValueError, OverflowError, OSError):
        return display(value)

def severity_label(value):
    return str(value).replace("_", " ").title() if value is not None else "Unknown"

def is_authorized(device):
    for key in ("authorized", "is_authorized", "authorization_status"):
        if key in device and device[key] is not None:
            return device[key]
    return None

def category_of(alert):
    return first(alert, "category", "alert_type", "type")

def category_group(value):
    text = str(value or "").lower()
    if "unauthor" in text or "unregistered" in text: return "Unauthorized/unregistered device"
    if "unknown" in text: return "Unknown-device alert"
    if any(part in text for part in ("behavior", "rate", "volume", "anomal", "abnormal", "traffic")): return "Behavioral alert"
    return "Other / backend category"

def device_table_row(device):
    auth = is_authorized(device)
    return {
        "Device ID": display(first(device, "device_id", "id")),
        "Type": display(first(device, "device_type", "type")),
        "MAC address": display(first(device, "mac_address", "mac")),
        "IP address": display(first(device, "ip_address", "ip")),
        "Registered": display(first(device, "registered", "is_registered")),
        "Authorization": display(auth),
        "First seen": format_timestamp_ms(first(device, "first_seen_ms", "first_seen_at", "first_seen")),
        "Last seen": format_timestamp_ms(first(device, "last_seen_ms")),
        "Messages in observation window": display(first(device, "messages_in_window")),
        "Received bytes in window": display(first(device, "bytes_in_window")),
        "Observation source": display(first(device, "observation_source", "observer_source", "discovery_source", "source")),
        "Record origin": "Synthetic demo" if device.get("_provenance") == "synthetic" else "Backend API record",
        "Record": device,
    }

def alert_table_row(alert, index):
    evidence = first(alert, "evidence")
    threshold = first(alert, "threshold")
    if threshold is None and isinstance(evidence, dict):
        threshold = first(evidence, "threshold")
    return {
        "_index": index,
        "Alert ID": display(first(alert, "alert_id", "id")),
        "Device ID": display(first(alert, "device_id")),
        "Category group": category_group(category_of(alert)),
        "Category": display(category_of(alert)),
        "Severity": severity_label(first(alert, "severity")),
        "Timestamp": format_timestamp_ms(first(alert, "timestamp_ms")),
        "Rule": display(first(alert, "rule_name", "rule", "summary")),
        "Threshold": display(threshold),
        "Evidence": display(evidence),
        "Record": alert,
    }

# Summary counts use only records from the selected source and explicit fields.
authorization_values = [is_authorized(d) for d in devices if is_authorized(d) is not None]
authorized_count = sum(1 for value in authorization_values if value is True or str(value).lower() == "authorized")
unauthorized_device_count = sum(1 for value in authorization_values if value is False or str(value).lower() == "unauthorized")
authorization_available = bool(authorization_values)
incident_ids = {str(first(a, "incident_id")) for a in alerts if first(a, "incident_id") is not None}
unauth_alerts = sum(category_group(category_of(a)) == "Unauthorized/unregistered device" for a in alerts)
behavior_alerts = sum(category_group(category_of(a)) == "Behavioral alert" for a in alerts)

st.subheader("Overview")
metrics_top = st.columns(4)
metrics_bottom = st.columns(4)
metrics_top[0].metric("Device records", len(devices), help="Number of records returned by /api/v1/devices; this is not a count of independently observed network devices.")
metrics_top[1].metric("Currently observed", "Unavailable", help="The confirmed response has last_seen_ms but no online status or observation cutoff, so current presence cannot be derived.")
metrics_top[2].metric("Authorized devices", authorized_count if authorization_available else "Unavailable", help="Counts explicit authorized/is_authorized/authorization_status classifications only.")
metrics_top[3].metric("Unauthorized devices", unauthorized_device_count if authorization_available else "Unavailable", help="Counts explicit unauthorized classifications only; registration status alone is not treated as authorization.")
metrics_bottom[0].metric("Unauthorized-device alerts", unauth_alerts if alerts else 0)
metrics_bottom[1].metric("Behavioral alerts", behavior_alerts if alerts else 0)
metrics_bottom[2].metric("Alerts returned", len(alerts))
metrics_bottom[3].metric("Recent incidents", len(incident_ids) if incident_ids else "Unavailable", help="The confirmed alert response has no incident identifier. Alerts are not assumed to be unique incidents.")

with st.expander("Severity distribution · alert counts", expanded=True):
    severity_counts = {}
    for alert in alerts:
        value = first(alert, "severity")
        label = severity_label(value)
        severity_counts[label] = severity_counts.get(label, 0) + 1
    if severity_counts:
        st.bar_chart(severity_counts)
        st.caption("Counts alerts by supplied severity; these are not unique incident counts.")
    else:
        st.write("No alerts are available to chart.")
    st.caption("No confirmed activity time series is available from the current device and alert responses; this view counts supplied alerts only.")

st.divider()
st.subheader("Devices")
device_search, auth_filter = st.columns([3, 1])
query = device_search.text_input("Search devices", key="device_search", placeholder="Device ID, type, or field value")
auth_options = ["All", "Authorized", "Unauthorized", "Unclassified"]
auth_choice = auth_filter.selectbox("Authorization", auth_options, key="device_auth_filter")
device_rows = []
for d in devices:
    auth = is_authorized(d)
    row = device_table_row(d)
    haystack = json.dumps(d, ensure_ascii=False, default=str).lower()
    if query.lower() in haystack and (auth_choice == "All" or (auth_choice == "Unclassified" and auth is None) or (auth_choice == "Authorized" and (auth is True or str(auth).lower() == "authorized")) or (auth_choice == "Unauthorized" and (auth is False or str(auth).lower() == "unauthorized"))):
        device_rows.append(row)
if device_rows:
    st.dataframe([{k: v for k, v in row.items() if k != "Record"} for row in device_rows], use_container_width=True, hide_index=True)
    st.caption("Record origin identifies the API or synthetic source. Network observation source is shown only when provided by the backend; an API record alone does not establish independent network observation.")
    with st.expander("Inspect original device record"):
        selected_dev = st.selectbox("Device record", range(len(device_rows)), format_func=lambda i: device_rows[i]["Device ID"], key="device_detail")
        st.json(device_rows[selected_dev]["Record"])
else:
    st.info("No devices match these filters." if devices else "No device records are available.")

st.divider()
st.subheader("Security Alerts")
alert_search, category_filter, severity_filter = st.columns([2, 2, 1])
alert_query = alert_search.text_input("Search alerts", key="alert_search", placeholder="ID, device, evidence, or rule")
category_values = sorted({str(category_of(a)) for a in alerts if category_of(a) is not None})
chosen_category = category_filter.selectbox("Category", ["All"] + category_values, key="alert_category")
severity_values = sorted({severity_label(first(a, "severity")) for a in alerts})
chosen_severity = severity_filter.selectbox("Severity", ["All"] + severity_values, key="alert_severity")
alert_rows = []
for index, a in enumerate(alerts):
    cat = category_of(a)
    row = alert_table_row(a, index)
    if alert_query.lower() in json.dumps(a, ensure_ascii=False, default=str).lower() and (chosen_category == "All" or str(cat) == chosen_category) and (chosen_severity == "All" or row["Severity"] == chosen_severity):
        alert_rows.append(row)
if alert_rows:
    st.dataframe([{k: row[k] for k in ("Alert ID", "Device ID", "Category group", "Category", "Severity", "Timestamp", "Rule", "Threshold", "Evidence")} for row in alert_rows], use_container_width=True, hide_index=True)
    st.subheader("Incident Intelligence")
    selection = st.selectbox("Select an alert", range(len(alert_rows)), format_func=lambda i: f"{alert_rows[i]['Alert ID']} · {alert_rows[i]['Category']} · {alert_rows[i]['Severity']}", key="selected_alert")
    chosen = alert_rows[selection]
    matching_device = next((d for d in devices if str(first(d, "device_id", "id")) == str(first(chosen["Record"], "device_id"))), None)
    report = generate_incident_report(chosen["Record"], matching_device)
    left, right = st.columns([1, 1])
    with left:
        st.markdown("**Observed facts**")
        st.write("Backend alert fields and evidence:")
        st.json(chosen["Record"])
        if matching_device:
            st.markdown("**Device context**")
            st.json(matching_device)
    with right:
        st.markdown(f"**{report['generation_method']}**")
        st.markdown("**Summary**")
        st.write(report["summary"])
        st.markdown("**Rule explanation**")
        st.write(report["rule_explanation"])
        st.markdown("**Potential impact (not confirmed)**")
        st.write(report["potential_impact"])
        st.markdown("**Recommended investigation and administrator-reviewed actions**")
        for action in report["recommended_actions"]: st.markdown(f"- {action}")
        st.markdown("**Uncertainties**")
        for uncertainty in report["uncertainties"]: st.markdown(f"- {uncertainty}")
else:
    st.info("No alerts match these filters." if alerts else "No alert records are available.")

st.caption("Prototype only. Backend detections and authorization classifications remain authoritative. Recommendations require administrator review; this dashboard does not execute containment.")
