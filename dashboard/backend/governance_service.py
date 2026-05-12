import csv
from pathlib import Path
from typing import Any, Dict, List

ATTACK_EVENTS = {
    "REPLAY_REJECT": {"risk": "R-001", "label": "Replay blocked", "severity": "high"},
    "AEAD_AUTH_FAIL": {"risk": "R-002", "label": "AEAD tamper detected", "severity": "high"},
    "PK_AUTH_FAIL": {"risk": "R-003", "label": "Public-key substitution blocked", "severity": "high"},
    "RATE_LIMIT_HIT": {"risk": "R-005", "label": "Flooding rate limited", "severity": "medium"},
    "SOURCE_BLOCKED": {"risk": "R-005", "label": "Host temporarily blocked", "severity": "medium"},
    "SENDER_AUTH_FAIL": {"risk": "R-007", "label": "Unauthorized sender rejected", "severity": "high"},
    "MALFORMED_PACKET": {"risk": "R-007", "label": "Malformed packet rejected", "severity": "medium"},
    "KEY_ROTATION_REQUIRED": {"risk": "R-006", "label": "Expired/revoked key rejected", "severity": "medium"},
    "KEY_ID_FAIL": {"risk": "R-006", "label": "Wrong key id rejected", "severity": "medium"},
}

RISK_EVIDENCE = {
    "R-001": ["REPLAY_REJECT"],
    "R-002": ["AEAD_AUTH_FAIL", "AEAD_DECRYPT_OK"],
    "R-003": ["PK_AUTH_FAIL", "PK_AUTH_OK"],
    "R-005": ["RATE_LIMIT_HIT", "SOURCE_BLOCKED"],
    "R-006": ["KEY_ROTATION_REQUIRED", "KEY_ID_FAIL", "KEY_ACTIVE", "KEY_ROTATED"],
    "R-007": ["SENDER_AUTH_FAIL", "MALFORMED_PACKET", "SOURCE_BLOCKED"],
    "R-008": ["MSG_DECRYPTED", "MSG_DELIVERED"],
}


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def risk_register_path() -> Path:
    root = project_root()
    candidates = [
        root / "integrations/splunk_hackerone_jira/governance/risk_register.csv",
        root / "thesis_demo/governance/risk_register.csv",
        root / "tests/risk_register.csv",
    ]
    for item in candidates:
        if item.exists():
            return item
    raise FileNotFoundError("risk_register.csv not found")


def load_risks() -> Dict[str, Any]:
    path = risk_register_path()
    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    risks = [r for r in rows if r.get("Risk ID", "").startswith("R-")]
    excluded = [r for r in rows if r.get("OWASP IoT Top 10 Mapping", "").startswith("I") and not r.get("Risk ID", "").startswith("R-")]

    residual = {"High": 0, "Medium": 0, "Low": 0}
    statuses: Dict[str, int] = {}
    categories: Dict[str, int] = {}
    for r in risks:
        level = r.get("Residual Risk", "").strip().title()
        if level in residual:
            residual[level] += 1
        statuses[r.get("Status", "Unknown").strip() or "Unknown"] = statuses.get(r.get("Status", "Unknown").strip() or "Unknown", 0) + 1
        categories[r.get("Category", "Unknown").strip() or "Unknown"] = categories.get(r.get("Category", "Unknown").strip() or "Unknown", 0) + 1

    yes = sum(1 for r in risks if r.get("Control Implemented", "").strip().lower() == "yes")
    partial = sum(1 for r in risks if r.get("Control Implemented", "").strip().lower() == "partial")
    no = sum(1 for r in risks if r.get("Control Implemented", "").strip().lower() == "no")
    compliance = round((yes / len(risks)) * 100) if risks else 0
    posture = "ACCEPTABLE" if residual["High"] == 0 else "NEEDS REVIEW"

    return {
        "path": str(path),
        "risks": risks,
        "excluded": excluded,
        "risk_count": len(risks),
        "excluded_count": len(excluded),
        "residual": residual,
        "controls": {"yes": yes, "partial": partial, "no": no, "total": len(risks)},
        "compliance": compliance,
        "posture": posture,
        "statuses": statuses,
        "categories": categories,
    }


def event_count_map(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for row in rows:
        name = row.get("event_type", "unknown") or "unknown"
        try:
            count = int(float(row.get("count", 0)))
        except Exception:
            count = 0
        out[name] = out.get(name, 0) + count
    return out


def build_governance_summary(event_counts: Dict[str, int], splunk_ok: bool, splunk_error: str | None = None) -> Dict[str, Any]:
    base = load_risks()
    risks_out = []
    for risk in base["risks"]:
        rid = risk.get("Risk ID", "")
        evidence_names = RISK_EVIDENCE.get(rid, [])
        evidence_count = sum(event_counts.get(name, 0) for name in evidence_names)
        risks_out.append({
            "id": rid,
            "title": risk.get("Risk Title", ""),
            "category": risk.get("Category", ""),
            "status": risk.get("Status", ""),
            "residual": risk.get("Residual Risk", ""),
            "implemented": risk.get("Control Implemented", ""),
            "owasp": risk.get("OWASP IoT Top 10 Mapping", ""),
            "evidence_events": evidence_names,
            "evidence_count": evidence_count,
            "live_status": "LIVE" if splunk_ok and evidence_count > 0 else ("NO_MATCH" if splunk_ok else "OFFLINE"),
        })

    total_events = sum(event_counts.values())
    attack_events = []
    for name, meta in ATTACK_EVENTS.items():
        attack_events.append({"event_type": name, "count": event_counts.get(name, 0), **meta})

    return {
        "splunk_ok": splunk_ok,
        "splunk_error": splunk_error,
        "risk_count": base["risk_count"],
        "excluded_count": base["excluded_count"],
        "compliance": base["compliance"],
        "posture": base["posture"],
        "residual": base["residual"],
        "controls": base["controls"],
        "statuses": base["statuses"],
        "categories": base["categories"],
        "total_events": total_events,
        "event_counts": event_counts,
        "risks": risks_out,
        "attack_events": attack_events,
        "excluded": base["excluded"],
    }
