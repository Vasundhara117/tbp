# SecureIoT Sentinel dashboard

A Streamlit monitoring interface and incident-summary module for the SecureIoT Sentinel prototype. Detection and authorization decisions remain in the backend; the dashboard does not execute containment actions.

## Architecture

- `app.py` renders overview, device and alert tables, filters, and incident details. It fetches at startup and on manual refresh, with an optional 10-second auto-refresh. Fetched records and incident reports are retained in Streamlit session state to avoid unnecessary requests and repeated LLM calls during UI interactions.
- `api_client.py` owns HTTP requests, timeouts, response validation, and user-safe errors.
- `incident_ai.py` creates a fixed-shape incident report. It uses deterministic templates by default and supports an optional OpenAI-compatible chat-completions endpoint.
- `sample_data.py` contains synthetic test scenarios, separate from API results.
- `tests/` contains isolated API, report, demo-data, and dashboard-guardrail checks.

## Backend contract

The dashboard uses `GET /api/v1/health`, `/api/v1/devices`, and `/api/v1/alerts`. The backend returns device and alert collections in named envelopes and provides explicit registration/authorization values, rolling message and byte counts, alert categories, severity, timestamps, and evidence. The UI preserves original records for inspection. Current presence is intentionally shown as unavailable: the API has no online-status or observation-cutoff definition.

Collections also accept bare lists and common `items`/`results` envelopes for compatibility. Unsupported response shapes or failed device/alert requests produce a visible error and clearly labeled synthetic demo data; live and demo records are never mixed.

## Requirements

Python 3.10 or newer is recommended. From the repository root:

```sh
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\\Scripts\\activate
python -m pip install -r dashboard_ai/requirements.txt
```

Set `BACKEND_URL` if the backend is not at the default `http://127.0.0.1:8000`:

```sh
export BACKEND_URL=http://127.0.0.1:8000
```

Start the backend separately, then launch the dashboard from the repository root:

```sh
streamlit run dashboard_ai/app.py
```

The dashboard fetches the three documented endpoints at startup and when **Refresh backend** is selected. **Auto-refresh every 10 seconds** can be enabled for periodic updates; it is off by default. A failed device or alert endpoint selects synthetic demo data for both tables, with a prominent notice; live and synthetic records are never combined. A health-only failure is shown while successfully fetched device and alert results remain usable. This is periodic refresh, not a guarantee of real-time network monitoring.

## LLM configuration (optional)

Without credentials the report generator works offline using deterministic templates. When configured, an OpenAI-compatible endpoint can generate summaries; the dashboard labels each report with its actual generation method. If the provider fails or returns invalid data, the report falls back to a template and says that the configured LLM was unavailable. To enable a provider, set these environment variables before launch:

```sh
export OPENAI_API_KEY='your-key'
export OPENAI_MODEL='gpt-4o-mini'                 # optional
export OPENAI_BASE_URL='https://api.openai.com/v1' # optional
```

Only selected alert and device fields are sent. The API key is sent to the configured endpoint as a bearer token; it is not shown in the UI. Evidence is treated as untrusted input, the model is constrained to summarization/recommendations, and its output must match the report schema. Network failures, rate limits, invalid JSON, and malformed output fall back to templates. Review any LLM output before acting; prompt instructions do not guarantee model behavior. Detection remains deterministic and rule-based regardless of LLM configuration.

## Demo data

Synthetic scenarios include normal authorized activity, a backend-style unregistered-device alert, an elevated message-rate scenario, and a high-volume scenario. They are clearly marked in the UI and each record carries `_provenance: synthetic`. The scenarios are examples, not observations or claims that the represented activity occurred.

## Tests

From repository root:

```sh
python -m pytest dashboard_ai/tests -q
```

Tests mock HTTP and LLM failures and need no hardware, backend, credentials, or internet access.

## Walkthrough

1. Start the backend and open the dashboard. Confirm the live indicator and fetch time.
2. Use the Python simulator or ESP32 firmware to send normal heartbeats, then run its burst mode to trigger a message-rate alert. An unregistered device ID demonstrates the authorization alert.
3. Use **Refresh backend** or enable **Auto-refresh every 10 seconds** to display the latest records.
3. Search or filter the device and alert tables; open original records to inspect the supplied fields.
4. Select an alert and compare its original evidence with the generated summary, uncertainties, and administrator-reviewed suggestions.
5. Stop/unavailable backend and refresh to view the prominently labeled synthetic demo mode.

## Troubleshooting and limitations

- **DEMO MODE:** verify backend startup, `BACKEND_URL`, and that all required routes are reachable. The UI shows safe endpoint error summaries.
- **Unsupported response shape:** align the collection envelope with the confirmed contract or extend the defensive adapter after agreement with Member 2.
- **Missing values:** optional fields display as unavailable; absence is not inferred as a negative classification.
- **LLM not used:** check `OPENAI_API_KEY`; if set, provider errors intentionally fall back without exposing details.
- **Observed-device and recent-incident counts:** only explicit definitions/IDs can support these metrics. No online status is inferred from registration or last-seen.

The backend's registered device ID is a policy label, not cryptographic device authentication. MAC addresses can be spoofed; the project does not reliably detect MAC spoofing. Passive capture is optional and disabled by default, and alerts do not block devices. This is a college prototype, not a production security system. Before deployment, review device authentication, transport security, secret management, data retention and access controls, logging, rate limits, dependency updates, and operational monitoring. No production-readiness claim is included.
