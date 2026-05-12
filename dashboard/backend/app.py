import os
from pathlib import Path
from typing import Any, Dict, List

from dotenv import load_dotenv
from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from splunk_client import SplunkClient
from governance_service import build_governance_summary, event_count_map, load_risks

ROOT = Path(__file__).resolve().parents[2]
# Load project root .env first, then optional dashboard/backend/.env override.
load_dotenv(ROOT / ".env", override=False)
load_dotenv(Path(__file__).resolve().parent / ".env", override=True)

app = FastAPI(
    title="PQC IoT Security Command Center API",
    version="1.0.0",
    description="Backend API for live Splunk telemetry, attack evidence, and governance reporting.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the built React frontend from the same backend port when dashboard/frontend/dist exists.
FRONTEND_DIST = ROOT / "dashboard/frontend/dist"
if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")

    @app.get("/")
    def dashboard_index():
        return FileResponse(str(FRONTEND_DIST / "index.html"))



def client() -> SplunkClient:
    return SplunkClient()


def normalize_time(row: Dict[str, Any]) -> Dict[str, Any]:
    if "_time" in row:
        row["time"] = row.get("_time")
    return row


@app.get("/api/health")
def health():
    c = client()
    return {"ok": True, "project_root": str(ROOT), "splunk": c.status()}


@app.get("/api/splunk/status")
def splunk_status():
    return client().status()


@app.get("/api/events/recent")
def recent_events(limit: int = Query(50, ge=1, le=500), earliest: str = "-24h"):
    c = client()
    pipe = f'| sort -_time | head {limit} | table _time event_type device_id role severity action src_ip message'
    rows, err = c.index_query(pipe, earliest=earliest, count=limit)
    return {"ok": err is None, "error": err, "events": [normalize_time(r) for r in rows]}


@app.get("/api/events/counts")
def event_counts(earliest: str = "-24h"):
    c = client()
    rows, err = c.index_query('| stats count by event_type severity | sort -count', earliest=earliest)
    counts = event_count_map(rows) if not err else {}
    return {"ok": err is None, "error": err, "rows": rows, "counts": counts, "total": sum(counts.values())}


@app.get("/api/events/timeline")
def event_timeline(earliest: str = "-2h"):
    c = client()
    pipe = '| bin _time span=5m | stats count by _time event_type | sort _time'
    rows, err = c.index_query(pipe, earliest=earliest, count=2000)
    return {"ok": err is None, "error": err, "timeline": rows}


@app.get("/api/devices")
def devices(earliest: str = "-24h"):
    c = client()
    pipe = '| stats latest(_time) as last_seen count values(event_type) as event_types by device_id role | sort -last_seen'
    rows, err = c.index_query(pipe, earliest=earliest)
    return {"ok": err is None, "error": err, "devices": rows}


@app.get("/api/attacks/summary")
def attacks_summary(earliest: str = "-24h"):
    c = client()
    events = '"REPLAY_REJECT","AEAD_AUTH_FAIL","PK_AUTH_FAIL","RATE_LIMIT_HIT","SOURCE_BLOCKED","SENDER_AUTH_FAIL","MALFORMED_PACKET","KEY_ROTATION_REQUIRED","KEY_ID_FAIL"'
    pipe = f'event_type IN ({events}) | stats count by event_type severity | sort -count'
    rows, err = c.index_query(pipe, earliest=earliest)
    counts = event_count_map(rows) if not err else {}
    return {"ok": err is None, "error": err, "rows": rows, "counts": counts, "total": sum(counts.values())}


@app.get("/api/governance/summary")
def governance_summary(earliest: str = "-24h"):
    c = client()
    rows, err = c.index_query('| stats count by event_type', earliest=earliest)
    counts = event_count_map(rows) if not err else {}
    return build_governance_summary(counts, splunk_ok=(err is None), splunk_error=err)


@app.get("/api/governance/risks")
def governance_risks():
    return load_risks()


@app.get("/api/overview")
def overview(earliest: str = "-24h"):
    c = client()
    status = c.status()

    count_rows, count_err = c.index_query('| stats count by event_type severity | sort -count', earliest=earliest)
    counts = event_count_map(count_rows) if not count_err else {}

    recent_rows, recent_err = c.index_query('| sort -_time | head 20 | table _time event_type device_id role severity action src_ip message', earliest=earliest, count=20)
    device_rows, device_err = c.index_query('| stats latest(_time) as last_seen count by device_id role | sort -last_seen', earliest=earliest)
    severity_rows, severity_err = c.index_query('| stats count by severity | sort -count', earliest=earliest)
    timeline_rows, timeline_err = c.index_query('| bin _time span=5m | stats count by _time event_type | sort _time', earliest='-2h', count=2000)

    governance = build_governance_summary(counts, splunk_ok=(count_err is None), splunk_error=count_err)

    return {
        "ok": count_err is None,
        "splunk": status,
        "errors": {
            "counts": count_err,
            "recent": recent_err,
            "devices": device_err,
            "severity": severity_err,
            "timeline": timeline_err,
        },
        "counts": counts,
        "count_rows": count_rows,
        "total_events": sum(counts.values()),
        "recent_events": [normalize_time(r) for r in recent_rows],
        "devices": device_rows,
        "severity": severity_rows,
        "timeline": timeline_rows,
        "governance": governance,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("DASHBOARD_API_PORT", "8090")), reload=True)
