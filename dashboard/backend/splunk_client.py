import os
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class SplunkClient:
    """Small Splunk Search REST API client for local dashboard use."""

    def __init__(self) -> None:
        self.host = os.getenv("SPLUNK_HOST", "localhost")
        self.port = int(os.getenv("SPLUNK_PORT", "8089"))
        self.user = os.getenv("SPLUNK_USER", "admin")
        self.password = os.getenv("SPLUNK_PASS", "")
        self.index = os.getenv("SPLUNK_INDEX", "pqc_iot")
        self.verify_tls = _env_bool("SPLUNK_VERIFY_TLS", False)
        self.base_url = f"https://{self.host}:{self.port}"

    def status(self) -> Dict[str, Any]:
        try:
            if not self.password:
                return {"ok": False, "reason": "SPLUNK_PASS is empty", "base_url": self.base_url, "index": self.index}
            resp = requests.get(
                f"{self.base_url}/services/server/info",
                auth=(self.user, self.password),
                params={"output_mode": "json"},
                verify=self.verify_tls,
                timeout=8,
            )
            if resp.status_code == 200:
                payload = resp.json()
                content = payload.get("entry", [{}])[0].get("content", {}) if isinstance(payload, dict) else {}
                return {
                    "ok": True,
                    "base_url": self.base_url,
                    "index": self.index,
                    "version": content.get("version"),
                    "server_name": content.get("serverName"),
                }
            return {"ok": False, "reason": f"HTTP {resp.status_code}", "base_url": self.base_url, "index": self.index}
        except Exception as exc:
            return {"ok": False, "reason": str(exc), "base_url": self.base_url, "index": self.index}

    def search(self, spl: str, earliest: str = "-24h", latest: str = "now", count: int = 1000, timeout: int = 30) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Run a Splunk SPL search and return (results, error)."""
        if not self.password:
            return [], "SPLUNK_PASS is empty"
        try:
            resp = requests.post(
                f"{self.base_url}/services/search/jobs",
                auth=(self.user, self.password),
                data={
                    "search": f"search {spl}",
                    "earliest_time": earliest,
                    "latest_time": latest,
                    "output_mode": "json",
                },
                verify=self.verify_tls,
                timeout=timeout,
            )
            if resp.status_code not in (200, 201):
                return [], f"HTTP {resp.status_code}: {resp.text[:180]}"
            sid = resp.json().get("sid")
            if not sid:
                return [], "Splunk did not return a search id"

            deadline = time.time() + timeout
            while time.time() < deadline:
                poll = requests.get(
                    f"{self.base_url}/services/search/jobs/{sid}",
                    auth=(self.user, self.password),
                    params={"output_mode": "json"},
                    verify=self.verify_tls,
                    timeout=8,
                )
                if poll.status_code != 200:
                    return [], f"Polling failed: HTTP {poll.status_code}"
                content = poll.json().get("entry", [{}])[0].get("content", {})
                if content.get("isDone") or content.get("dispatchState") == "DONE":
                    break
                time.sleep(0.35)
            else:
                return [], "Splunk search timed out"

            results = requests.get(
                f"{self.base_url}/services/search/jobs/{sid}/results",
                auth=(self.user, self.password),
                params={"output_mode": "json", "count": count},
                verify=self.verify_tls,
                timeout=15,
            )
            if results.status_code != 200:
                return [], f"Results failed: HTTP {results.status_code}"
            return results.json().get("results", []), None
        except Exception as exc:
            return [], str(exc)

    def index_query(self, pipe: str = "", earliest: str = "-24h", latest: str = "now", count: int = 1000):
        spl = f"index={self.index} {pipe}".strip()
        return self.search(spl, earliest=earliest, latest=latest, count=count)
