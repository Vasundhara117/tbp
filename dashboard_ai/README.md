# SecureIoT Sentinel dashboard

A restrained Streamlit monitoring interface and incident-summary module for the local SecureIoT Sentinel prototype. It does not make detection or authorization decisions and does not execute containment actions.

## Architecture

- `app.py` renders overview, device and alert tables, filters, and incident details. It fetches at startup and on manual refresh, then retains the fetched snapshot in Streamlit session state to avoid repeated requests during filter changes.
- `api_client.py` owns HTTP requests, timeouts, response validation, and user-safe errors.
- `incident_ai.py` creates a fixed-shape incident report. It uses deterministic templates by default and supports an optional OpenAI-compatible chat-completions endpoint.
- `sample_data.py` contains synthetic test scenarios, separate from API results.
- `tests/` contains isolated API, report, demo-data, and dashboard-guardrail checks.

## Contract status

The repository supplied for this implementation contained no backend source or API documentation. Consequently, no response schema, alert category vocabulary, authorization field, severity set, timestamp convention, rule/evidence schema, or definition of “currently observed” could be confirmed. The dashboard uses the documented endpoints only (`GET /api/v1/health`, `/api/v1/devices`, `/api/v1/alerts`). Device and alert collections accept a bare list or an object with `devices`/`alerts`, `items`, or `results` as a list; other shapes produce a visible error and demo mode. Health accepts a JSON object without assuming status field names. Individual fields are read defensively using common candidate names, while original records are retained for inspection.

Before integrating with Member 2's backend, confirm exact collection envelopes and fields for device ID/type, authorization, last-seen, message rate, received volume, alert ID/device/category/severity/time/evidence/rule/threshold, and whether an observed-device or incident identifier/count is available. “Currently observed” remains unavailable until its definition is confirmed. The registered-device KPI counts only explicit `registered`/`is_registered` values; it is unavailable when those fields are absent. Alert category grouping is a display aid based on supplied category words and does not modify backend classifications.

## Requirements

Python 3.9 or newer is recommended. From the repository root:

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

The dashboard calls the three documented endpoints once at startup and when **Refresh backend** is selected. It does not poll automatically. A failed device or alert endpoint selects synthetic demo data for both tables, with a prominent notice; live and synthetic records are never combined. A health-only failure is shown while successfully fetched device and alert results remain usable.

## LLM configuration (optional)

Without credentials the report generator works offline and labels reports **Template-generated (deterministic; no LLM used)**. To enable an OpenAI-compatible endpoint, set these environment variables before launch:

```sh
export OPENAI_API_KEY='your-key'
export OPENAI_MODEL='gpt-4o-mini'                 # optional
export OPENAI_BASE_URL='https://api.openai.com/v1' # optional
```

Only selected alert and device fields are sent. Evidence is treated as untrusted input, the model is constrained to summarization/recommendations, and its output must match the report schema. Network failures, rate limits, invalid JSON, and malformed output fall back to templates. Provider details and credentials are not shown in the UI. Review any LLM output before acting; prompt instructions do not guarantee model behavior.

## Demo data

Synthetic scenarios include normal authorized activity, a backend-style unregistered-device alert, an elevated message-rate scenario, and a high-volume scenario. They are clearly marked in the UI and each record carries `_provenance: synthetic`. The scenarios are examples, not observations or claims that the represented activity occurred.

## Tests

From repository root:

```sh
python -m pytest dashboard_ai/tests -q
```

Tests mock HTTP and LLM failures and need no hardware, backend, credentials, or internet access.

## Walkthrough

1. Start the backend if available and open the dashboard. Confirm the live indicator and fetch time.
2. Use **Refresh backend** after generating activity in the backend/simulator.
3. Search or filter the device and alert tables; open original records to inspect the supplied fields.
4. Select an alert and compare its original evidence with the generated summary, uncertainties, and administrator-reviewed suggestions.
5. Stop/unavailable backend and refresh to view the prominently labeled synthetic demo mode.

## Troubleshooting and limitations

- **DEMO MODE:** verify backend startup, `BACKEND_URL`, and that all required routes are reachable. The UI shows safe endpoint error summaries.
- **Unsupported response shape:** align the collection envelope with the confirmed contract or extend the defensive adapter after agreement with Member 2.
- **Missing values:** optional fields display as unavailable; absence is not inferred as a negative classification.
- **LLM not used:** check `OPENAI_API_KEY`; if set, provider errors intentionally fall back without exposing details.
- **Observed-device and recent-incident counts:** only explicit definitions/IDs can support these metrics. No online status is inferred from registration or last-seen.

This is a college prototype, not a production security system. Before deployment, review authentication and authorization, transport security, secret management, data retention and access controls, logging, rate limits, dependency updates, and operational monitoring. No custom domain, legal policy, or production-readiness claim is included.
