"""
Threat intelligence tools — Person 2 (Toolsmith).

Provides CVE lookup for Person 1's CVE Agent:
  - cve_lookup_tool — NVD API v2.0 lookup with patch intelligence
"""

import json
import uuid
from typing import Any

import httpx
from crewai.tools import tool

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = 15.0


def _make_result(tool_name: str, target: str, data: Any) -> str:
    """Serialize intel output to standard JSON envelope."""
    vulnerable = False
    if isinstance(data, dict):
        cves = data.get("cves", [])
        vulnerable = len(cves) > 0
    return json.dumps({
        "tool": tool_name,
        "target": target,
        "vulnerable": vulnerable,
        "data": data,
    })


@tool("CVE Lookup")
def cve_lookup_tool(query: str) -> str:
    """
    Search the NIST National Vulnerability Database for known CVEs.

    Accepts a software name + version string (e.g. "Apache 2.4.49",
    "Werkzeug 3.0.1", "OpenSSH 8.9") and returns matching CVE entries
    with CVSS scores, descriptions, and patch/fix information.
    """
    try:
        # Query NVD API v2.0 with keyword search
        params = {
            "keywordSearch": query,
            "resultsPerPage": 20,
        }

        # Use NVD API key if available for higher rate limits
        headers = {}
        import os
        nvd_key = os.environ.get("NVD_API_KEY")
        if nvd_key:
            headers["apiKey"] = nvd_key

        resp = httpx.get(
            NVD_API_BASE,
            params=params,
            headers=headers,
            timeout=TIMEOUT,
        )

        if resp.status_code != 200:
            return _make_result("cve_lookup", query, {
                "error": f"NVD API returned HTTP {resp.status_code}",
                "cves": [],
            })

        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])

        cves = []
        for vuln_wrapper in vulnerabilities[:20]:
            cve = vuln_wrapper.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")

            # Extract description
            descriptions = cve.get("descriptions", [])
            desc_en = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available",
            )

            # Extract CVSS scores (prefer v3.1, fallback to v3.0, then v2.0)
            metrics = cve.get("metrics", {})
            cvss_score = None
            cvss_severity = None
            cvss_vector = None

            for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(version_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get("baseSeverity")
                    cvss_vector = cvss_data.get("vectorString")
                    break

            # Extract references for patch intelligence
            references = cve.get("references", [])
            patch_refs = []
            advisory_refs = []
            for ref in references:
                url = ref.get("url", "")
                tags = ref.get("tags", [])
                if "Patch" in tags or "patch" in url.lower():
                    patch_refs.append(url)
                elif any(t in tags for t in ("Vendor Advisory", "Third Party Advisory")):
                    advisory_refs.append(url)
                elif "github.com" in url and ("commit" in url or "pull" in url):
                    patch_refs.append(url)

            # Extract affected configurations for "fixed-in" version detection
            configurations = cve.get("configurations", [])
            affected_versions = _extract_affected_versions(configurations)

            cves.append({
                "cve_id": cve_id,
                "description": desc_en[:500],
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "cvss_vector": cvss_vector,
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "patch_urls": patch_refs[:5],
                "advisory_urls": advisory_refs[:5],
                "affected_versions": affected_versions,
            })

        return _make_result("cve_lookup", query, {
            "query": query,
            "total_results": data.get("totalResults", 0),
            "cves_returned": len(cves),
            "cves": cves,
        })

    except httpx.HTTPError as exc:
        return _make_result("cve_lookup", query, {
            "error": f"NVD API request failed: {exc}",
            "cves": [],
        })
    except Exception as exc:
        return _make_result("cve_lookup", query, {
            "error": f"CVE lookup failed: {exc}",
            "cves": [],
        })


def _extract_affected_versions(configurations: list) -> list[dict]:
    """Extract affected version ranges from NVD configuration nodes."""
    affected = []
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable"):
                    entry = {
                        "criteria": cpe_match.get("criteria", ""),
                    }
                    if "versionStartIncluding" in cpe_match:
                        entry["from_version"] = cpe_match["versionStartIncluding"]
                    if "versionEndExcluding" in cpe_match:
                        entry["fixed_in"] = cpe_match["versionEndExcluding"]
                    if "versionEndIncluding" in cpe_match:
                        entry["last_affected"] = cpe_match["versionEndIncluding"]
                    affected.append(entry)
    return affected[:10]
