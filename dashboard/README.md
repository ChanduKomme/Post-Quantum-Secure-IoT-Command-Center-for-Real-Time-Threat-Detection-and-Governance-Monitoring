# PQC IoT Security Command Center Frontend

This dashboard replaces repeated Splunk searches and manual governance script runs with one web UI.

## Architecture

```text
BL602 Sender / Receiver -> Splunk HEC index=pqc_iot -> FastAPI backend -> React frontend
```

The browser never receives Splunk credentials. The backend reads them from `.env` and queries Splunk REST API on port `8089`.

## Prerequisites

- Splunk running locally
- HEC enabled on port `8088`
- Splunk management API running on port `8089`
- Project root `.env` containing `SPLUNK_USER` and `SPLUNK_PASS`
- Node.js/npm for the frontend

## Required `.env` values

Create/edit `/PQC_final/.env`:

```bash
SPLUNK_INDEX=pqc_iot
SPLUNK_HOST=localhost
SPLUNK_PORT=8089
SPLUNK_USER=admin
SPLUNK_PASS=YOUR_SPLUNK_WEB_LOGIN_PASSWORD
SPLUNK_VERIFY_TLS=false

SPLUNK_HEC_URL=http://localhost:8088
SPLUNK_HEC_TOKEN=YOUR_SPLUNK_HEC_TOKEN
SPLUNK_SOURCETYPE=pqc:iot:event
```

## Run backend

```bash
cd ~/sdk/bl602_iot_sdk/PQC_final/dashboard/backend
pyenv activate bl_venv
pip install -r requirements.txt
python3 app.py
```

Backend URL:

```text
http://localhost:8090
```

Health check:

```bash
curl http://localhost:8090/api/health
```

## Run frontend

Open another terminal:

```bash
cd ~/sdk/bl602_iot_sdk/PQC_final/dashboard/frontend
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

## One-command helpers

Development mode, backend on `8090` and Vite frontend on `5173`:

```bash
bash tools/run_security_command_center.sh
```

Single-port mode, builds React and serves everything from backend on `8090`:

```bash
bash tools/run_security_command_center_single_port.sh
```

Press `Ctrl+C` to stop.

## What the dashboard shows

- Splunk connection status
- Total live events
- Sender/Receiver status
- Successful PQC message delivery/decryption
- Attack evidence: replay, AEAD tamper, PK substitution, flood/rate limit, wrong sender
- Governance posture and 70% compliance score
- Risk register with live Splunk evidence mapping
- Recent event timeline
