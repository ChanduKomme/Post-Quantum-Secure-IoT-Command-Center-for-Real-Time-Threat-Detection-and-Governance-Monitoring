#!/usr/bin/env python3
"""
Quick connectivity test for Splunk HEC.
Works with both:
  SPLUNK_HEC_URL=https://localhost:8088
  SPLUNK_HEC_URL=https://localhost:8088/services/collector/event
"""
import argparse
import os
import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--env-file', default='.env')
    args = ap.parse_args()
    load_dotenv(args.env_file, override=False)

    url   = os.getenv('SPLUNK_HEC_URL', '').rstrip('/')
    token = os.getenv('SPLUNK_HEC_TOKEN')

    if not url or not token:
        raise SystemExit('Missing SPLUNK_HEC_URL or SPLUNK_HEC_TOKEN in .env')
    if token == 'REPLACE_WITH_YOUR_SPLUNK_HEC_TOKEN':
        raise SystemExit('SPLUNK_HEC_TOKEN is still the placeholder; copy .env.example to .env and configure a real local token.')

    # Always ensure the correct endpoint path
    if not url.endswith('/services/collector/event'):
        url = url.rstrip('/services/collector') + '/services/collector/event'

    payload = {
        "index":      os.getenv('SPLUNK_INDEX', 'pqc_iot'),
        "sourcetype": os.getenv('SPLUNK_SOURCETYPE', 'pqc:iot:event'),
        "event": {
            "event_type": "hec_connectivity_check",
            "status": "ok",
            "device_id": "hec-test",
            "severity": "info"
        }
    }

    resp = requests.post(
        url,
        json=payload,
        headers={"Authorization": f"Splunk {token}"},
        timeout=10,
        verify=False
    )
    print('HTTP', resp.status_code)
    print(resp.text)
    resp.raise_for_status()
    print('\n[OK] HEC connectivity confirmed.')


if __name__ == '__main__':
    main()
