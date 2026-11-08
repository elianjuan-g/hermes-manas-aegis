"""Threat-intel fetcher for Manas Aegis (v2.4.0-alpha).

Fetches GLOBAL threat intelligence from free, public, no-key sources:
- CISA KEV (Known Exploited Vulnerabilities): the authoritative list of
  vulnerabilities known to be exploited in the wild.
- NVD CVE API 2.0 (recent CVEs, small page, no key).

The data is GLOBAL awareness only. The plugin does NOT check whether
this device is affected, and a fetched CVE is NEVER presented as
"found on this device". If there is no internet, the last saved cache
is kept and the caller is told the refresh failed.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
NVD_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
    "?resultsPerPage=20&sortBy=published&sortOrder=desc"
)
CACHE_MAX_BYTES = 2_000_000
FETCH_TIMEOUT_S = 12


def fetch_json(
    url: str,
    timeout: int = FETCH_TIMEOUT_S,
    opener: Optional[Callable[[str, int], Any]] = None,
) -> Dict[str, Any]:
    """Fetch one JSON document. Raises on any failure (caller records it)."""
    if opener is not None:
        raw = opener(url, timeout)
    else:
        req = urllib.request.Request(url, headers={"User-Agent": "Manas-Aegis/2.4.0-alpha"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(CACHE_MAX_BYTES + 1)
    if isinstance(raw, (bytes, bytearray)) and len(raw) > CACHE_MAX_BYTES:
        raise ValueError("response too large")
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("response is not a JSON object")
    return data


def parse_kev(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Normalize CISA KEV entries to the shared intel item shape."""
    out: List[Dict[str, Any]] = []
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        return out
    for v in vulns:
        if not isinstance(v, dict):
            continue
        cve_id = v.get("cveID")
        if not isinstance(cve_id, str) or not cve_id:
            continue
        out.append({
            "id": cve_id,
            "vendor": str(v.get("vendorProject", "") or ""),
            "product": str(v.get("product", "") or ""),
            "name": str(v.get("vulnerabilityName", "") or ""),
            "date": str(v.get("dateAdded", "") or ""),
            "level": "Actively exploited",
            "description": str(v.get("shortDescription", "") or ""),
            "action": str(v.get("requiredAction", "") or ""),
            "source": "CISA KEV",
        })
    out.sort(key=lambda item: item["date"], reverse=True)
    return out[:25]


def parse_nvd(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Normalize NVD CVE API results to the shared intel item shape."""
    out: List[Dict[str, Any]] = []
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        return out
    for entry in vulns:
        if not isinstance(entry, dict):
            continue
        cve = entry.get("cve")
        if not isinstance(cve, dict):
            continue
        cve_id = cve.get("id")
        if not isinstance(cve_id, str) or not cve_id:
            continue
        description = ""
        for d in cve.get("descriptions", []) or []:
            if isinstance(d, dict) and d.get("lang") == "en":
                description = str(d.get("value", "") or "")
                break
        level = ""
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key)
            if isinstance(metric_list, list) and metric_list:
                first = metric_list[0] if isinstance(metric_list[0], dict) else {}
                cvss = first.get("cvssData") if isinstance(first, dict) else None
                if isinstance(cvss, dict):
                    score = cvss.get("baseScore")
                    severity = cvss.get("baseSeverity", "")
                    if score is not None:
                        level = f"{score} {severity}".strip()
                break
        out.append({
            "id": cve_id,
            "vendor": "",
            "product": "",
            "name": description[:120],
            "date": str(cve.get("published", "") or "")[:10],
            "level": level,
            "description": description,
            "action": "",
            "source": "NVD",
        })
    out.sort(key=lambda item: item["date"], reverse=True)
    return out[:15]


def empty_cache() -> Dict[str, Any]:
    return {"fetched_at": "", "sources": {}, "items": []}


def load_threat_intel(state_dir: Path) -> Dict[str, Any]:
    path = state_dir / "threat_intel.json"
    if not path.exists():
        return empty_cache()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return empty_cache()
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        return empty_cache()
    return data


def refresh_threat_intel(
    state_dir: Path,
    opener: Optional[Callable[[str, int], Any]] = None,
) -> Dict[str, Any]:
    """Fetch both sources, merge, and save the cache. Never raises; the
    returned status records per-source success or failure."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    items: List[Dict[str, Any]] = []
    sources: Dict[str, Any] = {}
    for source_name, url, parser in (
        ("CISA KEV", KEV_URL, parse_kev),
        ("NVD", NVD_URL, parse_nvd),
    ):
        try:
            data = fetch_json(url, opener=opener)
            parsed = parser(data)
            items.extend(parsed)
            sources[source_name] = {"ok": True, "count": len(parsed), "error": ""}
        except Exception as exc:
            sources[source_name] = {"ok": False, "count": 0, "error": str(exc)[:160]}
    items.sort(key=lambda item: item.get("date", ""), reverse=True)
    items = items[:40]
    previous = load_threat_intel(state_dir)
    if not items and previous.get("items"):
        # Keep the old cache when both sources failed.
        status = {
            "fetched_at": now,
            "sources": sources,
            "items": previous["items"],
            "stale": True,
        }
    else:
        status = {"fetched_at": now, "sources": sources, "items": items, "stale": False}
    try:
        (state_dir / "threat_intel.json").write_text(json.dumps(status, indent=2), encoding="utf-8")
    except Exception:
        pass
    return status
