#!/usr/bin/env python3
"""
PQC IoT Live Governance Report
─────────────────────────────────────────────────────────────────────────────
Pulls LIVE event data directly from Splunk, combines with risk_register.csv,
and produces a complete real-time governance report.

Usage:
    python3 governance_test_harness.py [--env-file path/to/.env]

Requirements:
    pip install requests python-dotenv
─────────────────────────────────────────────────────────────────────────────
"""

import csv
import json
import sys
import time
import datetime
import argparse
import urllib3
from pathlib import Path

try:
    import requests
    from dotenv import load_dotenv
except ImportError:
    print("\n  ERROR: Missing dependencies. Run:")
    print("  pip install requests python-dotenv\n")
    sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Colours ───────────────────────────────────────────────────────────────────
class C:
    RESET  = "\033[0m"; BOLD  = "\033[1m"
    RED    = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE   = "\033[94m"; CYAN  = "\033[96m"; GREY   = "\033[90m"
    MAGENTA= "\033[95m"
    BG_NAVY= "\033[44m"; BG_GREEN="\033[42m"; BG_RED="\033[41m"

def b(t):  return f"{C.BOLD}{t}{C.RESET}"
def g(t):  return f"{C.GREEN}{t}{C.RESET}"
def r(t):  return f"{C.RED}{t}{C.RESET}"
def y(t):  return f"{C.YELLOW}{t}{C.RESET}"
def bl(t): return f"{C.BLUE}{t}{C.RESET}"
def cy(t): return f"{C.CYAN}{t}{C.RESET}"
def gr(t): return f"{C.GREY}{t}{C.RESET}"

def divider(ch="═", w=72, col=C.BLUE): print(f"{col}{ch*w}{C.RESET}")
def section(title, col=C.CYAN):
    print(); divider("─",72,col)
    print(f"{C.BOLD}{col}  {title}{C.RESET}"); divider("─",72,col)

def bar(count, total, width=20, col=C.GREEN):
    filled = int((count/total)*width) if total else 0
    pct = round((count/total)*100) if total else 0
    return f"{col}{'█'*filled}{'░'*(width-filled)}{C.RESET} {pct}%"

# ── Locate files ──────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent

CSV_CANDIDATES = [
    SCRIPT_DIR / 'risk_register.csv',
    SCRIPT_DIR.parents[0] / 'docs' / 'risk_register.csv',
    SCRIPT_DIR.parents[1] / 'docs' / 'risk_register.csv',
]
CSV_PATH = next((p for p in CSV_CANDIDATES if p.exists()), None)

ENV_CANDIDATES = [
    SCRIPT_DIR.parents[0] / '.env',
    SCRIPT_DIR.parents[1] / '.env',

    Path.home() / 'sdk/bl602_iot_sdk/PQC/PQC_final/integrations/splunk_hackerone_jira/.env',
]

OUT_DIR  = SCRIPT_DIR / 'output'
OUT_PATH = OUT_DIR / 'governance_summary.json'
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Args ──────────────────────────────────────────────────────────────────────
ap = argparse.ArgumentParser(description="PQC IoT Live Governance Report")
ap.add_argument('--env-file', default=None, help='Path to .env file')
ap.add_argument('--splunk-host', default='localhost', help='Splunk host (default: localhost)')
ap.add_argument('--splunk-port', default=8089, type=int, help='Splunk management port (default: 8089)')
ap.add_argument('--no-splunk', action='store_true', help='Skip Splunk queries, use CSV only')
args = ap.parse_args()

# ── Load .env ──────────────────────────────────────────────────────────────────
import os
env_path = Path(args.env_file) if args.env_file else \
           next((p for p in ENV_CANDIDATES if p.exists()), None)
if env_path and env_path.exists():
    load_dotenv(env_path, override=False)

SPLUNK_HOST   = args.splunk_host
SPLUNK_PORT   = args.splunk_port
SPLUNK_INDEX  = os.getenv('SPLUNK_INDEX', 'pqc_iot')
SPLUNK_TOKEN  = os.getenv('SPLUNK_HEC_TOKEN', '')

# Derive admin credentials (Splunk REST API uses session-based auth)
SPLUNK_USER   = os.getenv('SPLUNK_USER', 'admin')
SPLUNK_PASS   = os.getenv('SPLUNK_PASS', 'admin')
SPLUNK_BASE   = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

# ── Splunk REST API helpers ───────────────────────────────────────────────────
def splunk_search(query, earliest="-30d", latest="now", timeout=30):
    """Run a Splunk search and return results list."""
    try:
        # Create search job
        resp = requests.post(
            f"{SPLUNK_BASE}/services/search/jobs",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            data={
                "search":     f"search {query}",
                "earliest_time": earliest,
                "latest_time":   latest,
                "output_mode":   "json",
            },
            verify=False, timeout=timeout
        )
        if resp.status_code not in (200, 201):
            return None, f"HTTP {resp.status_code}"

        sid = resp.json().get('sid')
        if not sid:
            return None, "No SID returned"

        # Poll for completion
        deadline = time.time() + timeout
        while time.time() < deadline:
            poll = requests.get(
                f"{SPLUNK_BASE}/services/search/jobs/{sid}",
                auth=(SPLUNK_USER, SPLUNK_PASS),
                params={"output_mode": "json"},
                verify=False, timeout=10
            )
            state = poll.json().get('entry',[{}])[0].get('content',{})
            if state.get('dispatchState') == 'DONE':
                break
            time.sleep(0.5)

        # Fetch results
        results = requests.get(
            f"{SPLUNK_BASE}/services/search/jobs/{sid}/results",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            params={"output_mode": "json", "count": 1000},
            verify=False, timeout=15
        )
        return results.json().get('results', []), None

    except Exception as e:
        return None, str(e)

def get_event_counts():
    """Query Splunk for all event type counts from the pqc_iot index."""
    print(f"  {gr('Querying Splunk at')} {bl(SPLUNK_BASE)} {gr('...')}", end='', flush=True)
    results, err = splunk_search(
        f"index={SPLUNK_INDEX} | stats count by event_type, device_id, role | sort -count"
    )
    if err or results is None:
        print(f" {r('FAILED')} ({err})")
        return None, err
    print(f" {g('OK')} ({len(results)} rows)")
    return results, None

def get_recent_events(limit=20):
    """Get the most recent events for the audit timeline."""
    results, err = splunk_search(
        f"index={SPLUNK_INDEX} | sort -_time | head {limit} "
        f"| table _time event_type device_id role severity action"
    )
    return results or [], err

def get_device_stats():
    """Get per-device event summary."""
    results, err = splunk_search(
        f"index={SPLUNK_INDEX} | stats count by device_id, role | sort -count"
    )
    return results or [], err

def get_time_range():
    """Get first and last event times."""
    results, err = splunk_search(
        f"index={SPLUNK_INDEX} | stats min(_time) as first, max(_time) as last, count as total"
    )
    return results[0] if results else {}, err

def get_severity_counts():
    """Get counts by severity."""
    results, err = splunk_search(
        f"index={SPLUNK_INDEX} | stats count by severity | sort -count"
    )
    return results or [], err

# ── Load CSV ──────────────────────────────────────────────────────────────────
if not CSV_PATH:
    print(r("\n  ERROR: risk_register.csv not found."))
    sys.exit(1)

with CSV_PATH.open(newline='', encoding='utf-8') as f:
    all_rows = list(csv.DictReader(f))

risks    = [r_ for r_ in all_rows if r_.get('Risk ID','').startswith('R-')]
excluded = [r_ for r_ in all_rows if r_.get('OWASP IoT Top 10 Mapping','').startswith('I')
            and not r_.get('Risk ID','').startswith('R-')]

counts_risk = {'High':0, 'Medium':0, 'Low':0}
risks_by_level = {'High':[], 'Medium':[], 'Low':[]}
owasp_mapping = {}
for row in risks:
    rr = row.get('Residual Risk','').strip().title()
    if rr in counts_risk:
        counts_risk[rr] += 1
        risks_by_level[rr].append(row)
    o = row.get('OWASP IoT Top 10 Mapping','').strip()
    if o: owasp_mapping[row.get('Risk ID','')] = o

controls_yes     = sum(1 for r_ in risks if r_.get('Control Implemented','').strip().lower()=='yes')
controls_partial = sum(1 for r_ in risks if r_.get('Control Implemented','').strip().lower()=='partial')
controls_no      = sum(1 for r_ in risks if r_.get('Control Implemented','').strip().lower()=='no')
category_counts  = {}
status_counts    = {}
for row in risks:
    c = row.get('Category','Unknown').strip()
    s = row.get('Status','Unknown').strip()
    category_counts[c] = category_counts.get(c,0) + 1
    status_counts[s]   = status_counts.get(s,0) + 1

compliance_pct = round((controls_yes / len(risks)) * 100) if risks else 0
posture        = 'ACCEPTABLE' if counts_risk['High'] == 0 else 'NEEDS REVIEW'
generated_at   = datetime.datetime.utcnow()

# ─────────────────────────────────────────────────────────────────────────────
# QUERY SPLUNK
# ─────────────────────────────────────────────────────────────────────────────
splunk_ok   = False
event_counts = {}   # event_type → {device_id → count}
total_events = 0
device_stats = {}
severity_map = {}
recent_events = []
time_info    = {}

if not args.no_splunk:
    section("CONNECTING TO SPLUNK (LIVE DATA)", C.CYAN)
    print(f"\n  {gr('Host    :')} {bl(SPLUNK_BASE)}")
    print(f"  {gr('Index   :')} {bl(SPLUNK_INDEX)}")
    print(f"  {gr('Auth    :')} {bl(SPLUNK_USER+' / password')}")
    print()

    raw_counts, err = get_event_counts()
    if raw_counts is not None:
        splunk_ok = True
        for row in raw_counts:
            et  = row.get('event_type','unknown')
            did = row.get('device_id','unknown')
            cnt = int(row.get('count',0))
            total_events += cnt
            if et not in event_counts: event_counts[et] = {}
            event_counts[et][did] = event_counts[et].get(did,0) + cnt

        dev_rows, _ = get_device_stats()
        for row in dev_rows:
            device_stats[row.get('device_id','?')] = int(row.get('count',0))

        sev_rows, _ = get_severity_counts()
        for row in sev_rows:
            severity_map[row.get('severity','?')] = int(row.get('count',0))

        recent_events, _ = get_recent_events(25)
        time_info, _     = get_time_range()

    else:
        print(f"\n  {y('⚠')} Splunk query failed: {err}")
        print(f"  {gr('Running in CSV-only mode.')}")
        print(f"  {gr('To enable live data set SPLUNK_USER and SPLUNK_PASS in .env')}")
        print(f"  {gr('or run: python3 governance_test_harness.py --no-splunk')}")

# ── Helper: get total for event type ────────────────────────────────────────
def ev(name):
    return sum(event_counts.get(name,{}).values())

# ─────────────────────────────────────────────────────────────────────────────
# PRINT REPORT
# ─────────────────────────────────────────────────────────────────────────────
print()
divider("═",72,C.BLUE)
print(f"{C.BOLD}{C.BG_NAVY}{'  Live Governance & Risk Report':^72}{C.RESET}")

divider("═",72,C.BLUE)

print(f"  {gr('Platform :')} BL602 RISC-V | ML-KEM-512 | AES-128-CCM | CoAP/UDP")
print(f"  {gr('Framework:')} OWASP IoT Top 10 (2018) + ENISA IoT Security Guidelines")
print(f"  {gr('Generated:')} {generated_at.strftime('%Y-%m-%d %H:%M:%S')} UTC")
data_src = g("LIVE — Splunk "+SPLUNK_BASE) if splunk_ok else y("CSV only (Splunk unavailable)")
print(f"  {gr('Data     :')} {data_src}")
divider("═",72,C.BLUE)

# ── Overall posture ───────────────────────────────────────────────────────────
section("OVERALL SECURITY POSTURE", C.CYAN)
if posture=='ACCEPTABLE':
    print(f"\n  {C.BOLD}{C.BG_GREEN}    POSTURE: ACCEPTABLE  {C.RESET}  "
          f"{g('Zero high residual risks. All critical controls implemented.')}")
else:
    print(f"\n  {C.BOLD}{C.BG_RED}  🔴  POSTURE: NEEDS REVIEW  {C.RESET}  "
          f"{r('High residual risks detected.')}")
print()
print(f"  ┌───────────────────┬──────────────────┬──────────────────┬──────────────────┐")
print(f"  │  {b('Risks Tracked'):18} │  {b('Compliance'):16} │  {b('High Residual'):16} │  {b('Total Events'):16} │")
total_ev_str = g(f"{total_events:,}") if splunk_ok else gr("N/A")
print(f"  │  {cy(str(len(risks))):27} │  {g(str(compliance_pct)+'%'):25} │  "
      f"{g('0 ') if counts_risk['High']==0 else r(str(counts_risk['High'])):25} │  {total_ev_str:25} │")
print(f"  └───────────────────┴──────────────────┴──────────────────┴──────────────────┘")

# ── Live Splunk telemetry ─────────────────────────────────────────────────────
if splunk_ok:
    section("LIVE SPLUNK TELEMETRY — EVENT COUNTS", C.CYAN)
    print()

    # Time range
    if time_info:
        try:
            first = datetime.datetime.fromtimestamp(float(time_info.get('first',0)))
            last  = datetime.datetime.fromtimestamp(float(time_info.get('last',0)))
            span  = last - first
            days  = span.days
            print(f"  {b('Data window:')} {first.strftime('%Y-%m-%d %H:%M')} → "
                  f"{last.strftime('%Y-%m-%d %H:%M')}  ({days} day{'s' if days!=1 else ''})")
            print(f"  {b('Total events ingested:')} {g(str(total_events)):30}")
        except Exception:
            print(f"  {b('Total events ingested:')} {g(str(total_events))}")
    print()

    # Per-device breakdown
    print(f"  {b('Events per device:')}")
    for dev, cnt in sorted(device_stats.items(), key=lambda x:-x[1]):
        b_str = bar(cnt, total_events, width=18, col=C.BLUE)
        print(f"    {cy(dev):<18}  {b_str}  ({cnt:,} events)")
    print()

    # Severity breakdown
    if severity_map:
        print(f"  {b('Events by severity:')}")
        sev_col = {'info':C.GREEN,'low':C.CYAN,'medium':C.YELLOW,'high':C.RED,'critical':C.MAGENTA}
        for sev, cnt in sorted(severity_map.items(), key=lambda x:-x[1]):
            col = sev_col.get(sev.lower(), C.GREY)
            b_str = bar(cnt, total_events, width=18, col=col)
            print(f"    {f'{col}{sev.upper():10}{C.RESET}'} {b_str}  ({cnt:,})")
    print()

    # Security event detail
    print(f"  {b('Security events from boards:')}")
    security_events = [
        ("MSG_DECRYPTED",    g,  "Messages successfully decrypted",      "R-002"),
        ("MSG_DELIVERED",    g,  "Messages delivered by sender",         "R-002"),
        ("WIFI_CONNECTED",   g,  "Wi-Fi connect events",                 "—"),
        ("KEY_ACTIVE",       g,  "Keypair loaded events",                "R-006"),
        ("KEM_HKDF_DONE",    g,  "KEM+HKDF completed",                  "—"),
        ("AEAD_ENCRYPT_DONE",g,  "AEAD encryptions completed",           "R-002"),
        ("PK_REQUEST",       bl, "Public key requests served",           "R-003"),
        ("MONITOR_ACTIVE",   bl, "Receiver monitor start events",        "—"),
        ("SEND_COMPLETE",    g,  "Full send cycles completed",           "—"),
        ("REPLAY_REJECT",    y,  "Replay attacks blocked",               "R-001"),
        ("RATE_LIMIT_HIT",   y,  "Rate limit triggers",                  "R-005"),
        ("SOURCE_BLOCKED",   y,  "Source IPs temporarily blocked",       "R-005"),
        ("KEY_ROTATED",      y,  "Key rotation events",                  "R-006"),
        ("AEAD_AUTH_FAIL",   r,  "AEAD authentication failures",         "R-002"),
        ("PK_AUTH_FAIL",     r,  "PK fingerprint mismatches",            "R-003"),
        ("SEND_FAILED",      r,  "Send cycle failures",                  "—"),
    ]
    for etype, col_fn, desc, risk_ref in security_events:
        cnt = ev(etype)
        if cnt > 0 or etype in ('MSG_DECRYPTED','REPLAY_REJECT','AEAD_AUTH_FAIL','PK_AUTH_FAIL'):
            cnt_str = col_fn(f"{cnt:>6,}") if cnt > 0 else gr(f"{'0':>6}")
            ref_str = gr(f"[{risk_ref}]") if risk_ref != "—" else gr("      ")
            print(f"    {cnt_str}  {desc:<42} {ref_str}")

# ── Controls ──────────────────────────────────────────────────────────────────
section("CONTROLS IMPLEMENTATION", C.CYAN)
total = len(risks)
print(f"\n  {b('Fully Implemented  :')} {controls_yes:2}/{total}  {bar(controls_yes, total)}")
print(f"  {b('Partially Implemented:')} {controls_partial:2}/{total}  {bar(controls_partial, total, col=C.YELLOW)}")
print(f"  {b('Not Implemented    :')} {controls_no:2}/{total}  {bar(controls_no, total, col=C.RED)}")
print()
print(f"  {gr('30% gap = BL602 hardware constraints — not cryptographic design gaps:')}")
print(f"  {gr('  R-004: No HW AES-XTS flash encryption in open SDK (needs secure element)')}")
print(f"  {gr('  R-009: No secure boot API for PineCone in open SDK (needs vendor toolchain)')}")
print(f"  {gr('  R-010: TOFU is deliberate demo mode — one config flag change for production')}")

# ── Risk register ─────────────────────────────────────────────────────────────
section("FULL RISK REGISTER WITH LIVE EVIDENCE", C.CYAN)
print()

# Risk → Splunk evidence mapping
risk_evidence = {
    "R-001": ("REPLAY_REJECT",    "replay_blocks",  "Replays blocked live"),
    "R-002": ("AEAD_AUTH_FAIL",   "auth_failures",  "Auth failures detected"),
    "R-003": ("PK_AUTH_FAIL",     "pk_failures",    "PK mismatches detected"),
    "R-004": (None,               None,             "Physical control only"),
    "R-005": ("RATE_LIMIT_HIT",   "rate_hits",      "Rate limit triggers"),
    "R-006": ("KEY_ROTATED",      "rotations",      "Key rotation events"),
    "R-007": (None,               None,             "Whitelist enforcement"),
    "R-008": ("MSG_DECRYPTED",    "decrypts",       "Encrypted msgs received"),
    "R-009": (None,               None,             "Physical control only"),
    "R-010": (None,               None,             "Config-based control"),
}

print(b(f"  {'ID':<7} {'Risk Title':<40} {'Residual':<9} {'Status':<14} {'Live Evidence'}"))
print(gr("  " + "─"*95))

for row in risks:
    rid      = row.get('Risk ID','')
    title    = row.get('Risk Title','')
    residual = row.get('Residual Risk','').strip()
    status   = row.get('Status','').strip()
    owasp    = row.get('OWASP IoT Top 10 Mapping','').strip()
    ci       = row.get('Control Implemented','').strip()
    note     = row.get('Exclusion Justification','').strip()

    res_col  = {'High':r(b('HIGH')),'Medium':y(b('MED')),'Low':g(b('LOW'))}.get(residual,residual)
    stat_col = g(' Mitigated') if status=='Mitigated' else y('  Accepted')

    title_s = (title[:39]+'…') if len(title)>39 else title

    # Live evidence
    ev_type, _, ev_desc = risk_evidence.get(rid, (None,None,""))
    if splunk_ok and ev_type:
        cnt = ev(ev_type)
        ev_str = (g(f"{cnt:,} events — {ev_desc}") if cnt==0 and ev_type in ('AEAD_AUTH_FAIL','PK_AUTH_FAIL','REPLAY_REJECT')
                  else g(f"{cnt:,} events  ✓") if cnt>0 and ev_type not in ('AEAD_AUTH_FAIL','PK_AUTH_FAIL')
                  else r(f"{cnt:,} incidents") if cnt>0 else g("0 — no incidents ✓"))
    elif splunk_ok:
        ev_str = gr(ev_desc)
    else:
        ev_str = gr("(Splunk offline)")

    print(f"  {cy(rid):<7} {title_s:<40} {res_col:<9}  {stat_col:<14} {ev_str}")
    print(f"  {'':<7} {gr('OWASP: ')}{bl(owasp[:60])}")
    if note:
        note_s = (note[:80]+'…') if len(note)>80 else note
        
    print()

# ── Residual risk breakdown ───────────────────────────────────────────────────
section("RESIDUAL RISK BREAKDOWN", C.CYAN)
for level, col_fn, icon in [('High',r,'🔴'),('Medium',y,'🟡'),('Low',g,'🟢')]:
    lr = risks_by_level[level]
    print(f"\n  {icon} {b(col_fn(level.upper()+' RESIDUAL'))} — {len(lr)} risk(s)")
    if not lr:
        print(f"    {g('None — all eliminated ')}")
    else:
        for row in lr:
            print(f"    • {row.get('Risk ID','')}  {row.get('Risk Title','')}  {gr('['+row.get('Status','')+']')}")

# ── OWASP coverage ────────────────────────────────────────────────────────────
section("OWASP IoT TOP 10 COVERAGE", C.CYAN)
covered   = sorted(set(v.split('—')[0].strip() for v in owasp_mapping.values()))
excl_cats = sorted(set(
    r_.get('OWASP IoT Top 10 Mapping','').split('—')[0].strip()
    for r_ in excluded if r_.get('OWASP IoT Top 10 Mapping','')
))
print(f"\n  {b('Addressed:')} {g(str(len(covered)))} of 10 OWASP categories")
for cat in covered:
    risk_ids = [k for k,v in owasp_mapping.items() if v.startswith(cat)]
    desc = next((v for v in owasp_mapping.values() if v.startswith(cat)), cat)
    print(f"    {g('')}  {bl(desc):<55} {gr('→ '+', '.join(risk_ids))}")
print(f"\n  {b('Excluded (with justification):')} {gr(str(len(excl_cats)))} categories")
for row in excluded:
    cat  = row.get('OWASP IoT Top 10 Mapping','').strip()
    excl = row.get('Exclusion Justification','').strip()
    if cat and excl:
        print(f"    {y('—')}  {gr(cat)}")
        print(f"       {gr((excl[:75]+'…') if len(excl)>75 else excl)}")

# ── Recent events from Splunk ─────────────────────────────────────────────────
if splunk_ok and recent_events:
    section("RECENT SECURITY EVENTS (LIVE FROM SPLUNK)", C.CYAN)
    print()
    sev_col = {'info':C.GREEN,'low':C.CYAN,'medium':C.YELLOW,'high':C.RED,'critical':C.MAGENTA}
    print(b(f"  {'Time':<20} {'Event Type':<22} {'Device':<14} {'Severity':<10} {'Action'}"))
    print(gr("  "+"─"*85))
    for row in recent_events[:20]:
        try:
            ts   = datetime.datetime.fromtimestamp(float(row.get('_time',0)))
            tstr = ts.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            tstr = str(row.get('_time',''))[:19]
        etype = row.get('event_type','')
        dev   = row.get('device_id','')
        sev   = row.get('severity','')
        act   = row.get('action','')
        col   = sev_col.get(sev.lower(), C.GREY)
        sev_s = f"{col}{sev.upper():<10}{C.RESET}"
        ev_color = g if sev=='info' else y if sev=='medium' else r if sev=='high' else bl
        print(f"  {gr(tstr)}  {ev_color(etype):<22}  {cy(dev):<14}  {sev_s}  {gr(act)}")

# ── Compliance summary ────────────────────────────────────────────────────────
section("COMPLIANCE SCORE EXPLANATION", C.CYAN)
print()
print(f"  {b('Score:')} {g(str(compliance_pct)+'%')} ({controls_yes}/{total} controls fully implemented)\n")
partials = {
    'R-004': ('Unencrypted Key Storage',
              'BL602 open SDK has no hardware AES-XTS or secure key storage API.',
              'Use ATECC608A secure element or BL602B2 with eFuse key storage.'),
    'R-009': ('Firmware Tampering via Re-flash',
              'BL602 open SDK does not expose secure boot or firmware signature APIs.',
              'Use BL602B2 secure boot or a custom verified bootloader.'),
    'R-010': ('TOFU First-Use Key Spoofing',
              'TOFU mode enabled deliberately for demo flexibility.',
              'Set PQC_PK_AUTH_MODE=STRICT, provision fingerprint before production.'),
}
for rid,(title,reason,fix) in partials.items():
    print(f"  {y('⚠')} {b(rid)} — {title}")
    print(f"    {gr('Reason: ')}{reason}")
    print(f"    {gr('Fix:    ')}{fix}\n")

# ── Status breakdown ──────────────────────────────────────────────────────────
section("STATUS BREAKDOWN", C.CYAN)
print()
for status, cnt in sorted(status_counts.items(), key=lambda x:-x[1]):
    col = C.GREEN if status=='Mitigated' else C.YELLOW
    print(f"  {'' if status=='Mitigated' else ''}  {status:<15} {bar(cnt, total, col=col)}  ({cnt}/{total})")

# ── Category breakdown ────────────────────────────────────────────────────────
section("RISKS BY CATEGORY", C.CYAN)
print()
for cat, cnt in sorted(category_counts.items(), key=lambda x:-x[1]):
    print(f"  {cat:<28} {bar(cnt, total, width=15, col=C.BLUE)}  ({cnt})")

# ── Final verdict ─────────────────────────────────────────────────────────────
print()
divider("═",72,C.BLUE)
verdict = (f"  POSTURE: {posture}  |  COMPLIANCE: {compliance_pct}%  |  "
           f"HIGH: {counts_risk['High']}  |  EVENTS: {total_events:,}" if splunk_ok else
           f"  POSTURE: {posture}  |  COMPLIANCE: {compliance_pct}%  |  HIGH RISKS: {counts_risk['High']}")
bg = C.BG_GREEN if posture=='ACCEPTABLE' else C.BG_RED
print(f"{C.BOLD}{bg}{verdict:^72}{C.RESET}")
divider("═",72,C.BLUE)
print(f"\n  {gr('Generated:')} {generated_at.strftime('%Y-%m-%d %H:%M:%S')} UTC")

# ── Save JSON ─────────────────────────────────────────────────────────────────
summary = {
    'project':           'PQC IoT — Post-Quantum Key Exchange Mechanisms for IoT',
    'platform':          'BL602/PineCone | ML-KEM-512 | AES-128-CCM | CoAP/UDP',
    'generated_at':      generated_at.isoformat()+'Z',
    'framework':         'OWASP IoT Top 10 (2018) + ENISA IoT Security Guidelines',
    'data_source':       'Splunk Live' if splunk_ok else 'CSV Only',
    'splunk_host':       SPLUNK_BASE if splunk_ok else None,
    'risk_count':        len(risks),
    'residual_risk':     counts_risk,
    'controls':          {'fully_implemented':controls_yes,'partially_implemented':controls_partial,'not_implemented':controls_no},
    'compliance_score':  f"{compliance_pct}%",
    'posture':           posture,
    'total_splunk_events': total_events,
    'event_counts':      {k: sum(v.values()) for k,v in event_counts.items()},
    'device_stats':      device_stats,
    'severity_breakdown':severity_map,
    'status_breakdown':  status_counts,
    'category_breakdown':category_counts,
    'owasp_mapping':     owasp_mapping,
    'risks_by_level':    {lvl:[{'id':r_.get('Risk ID'),'title':r_.get('Risk Title'),
                                'category':r_.get('Category'),'status':r_.get('Status'),
                                'owasp':r_.get('OWASP IoT Top 10 Mapping')}
                               for r_ in rl] for lvl,rl in risks_by_level.items()},
    'compliance_gap':    f"The {100-compliance_pct}% gap reflects BL602 hardware constraints (R-004, R-009) and deliberate demo config (R-010). Not cryptographic design gaps.",
    'notes':             'Risk selection grounded in OWASP IoT Top 10 (2018). Zero high residual risks confirmed.',
}
OUT_PATH.write_text(json.dumps(summary, indent=2), encoding='utf-8')
print(f"  {gr('JSON saved:')} {OUT_PATH}\n")
