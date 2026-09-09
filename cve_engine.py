#!/usr/bin/env python3
"""
VulnSync-Mapper (VSM) - Asynchronous CVE Correlation
"""

import asyncio
import aiohttp
import json
import logging
from typing import Dict, List, Any

logging.basicConfig(level=logging.INFO, format='[*] %(message)s')

class VulnerabilityCorrelator:
    def __init__(self, config_path: str = "config.json"):
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.circl_url = "https://cve.circl.lu/api/cvefor/"
        self.epss_url = "https://api.first.org/data/v1/epss"

    async def fetch_epss_score(self, session: aiohttp.ClientSession, cve_id: str) -> float:
        """Fetches real-time Exploit Prediction Scoring System (EPSS) rating."""
        try:
            async with session.get(f"{self.epss_url}?cve={cve_id}", timeout=5) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("data"):
                        return float(data["data"][0].get("epss", 0.0))
        except Exception as e:
            logging.debug(f"EPSS fetch failed for {cve_id}: {e}")
        return 0.0

    async def query_cpe_vulnerabilities(self, session: aiohttp.ClientSession, cpe_str: str) -> List[Dict[str, Any]]:
        """Queries NIST NVD API with automatic CIRCL fallback handling."""
        headers = {}
        if self.config.get("nvd_api_key"):
            headers["apiKey"] = self.config["nvd_api_key"]

        params = {"cpeName": cpe_str}
        results = []

        try:
            async with session.get(self.nvd_url, params=params, headers=headers, timeout=8) as resp:
                if resp.status == 200:
                    payload = await resp.json()
                    vulnerabilities = payload.get("vulnerabilities", [])
                    for item in vulnerabilities:
                        cve = item.get("cve", {})
                        cve_id = cve.get("id")
                        metrics = cve.get("metrics", {})
                        
                        cvss_score = 0.0
                        if "cvssMetricV31" in metrics:
                            cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                        elif "cvssMetricV30" in metrics:
                            cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

                        if cvss_score >= self.config["min_cvss_score"]:
                            epss_score = await self.fetch_epss_score(session, cve_id)
                            results.append({
                                "cve_id": cve_id,
                                "cvss": cvss_score,
                                "epss": epss_score,
                                "summary": cve.get("descriptions", [{}])[0].get("value", "No description available.")
                            })
                    return results
                elif resp.status == 429 and self.config["fallback_to_circl"]:
                    logging.warning(f"NVD Rate Limit Hit for {cpe_str}. Falling back to CIRCL API...")
                    return await self._query_circl_fallback(session, cpe_str)
        except Exception as e:
            logging.error(f"Error querying NVD for {cpe_str}: {e}")
            if self.config["fallback_to_circl"]:
                return await self._query_circl_fallback(session, cpe_str)
        return results

    async def _query_circl_fallback(self, session: aiohttp.ClientSession, cpe_str: str) -> List[Dict[str, Any]]:
        """Fallback API lookup when primary NVD endpoint is rate-limited."""
        results = []
        try:
            async with session.get(f"{self.circl_url}{cpe_str}", timeout=6) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data[:10]:  # Cap at top 10 relevant records
                        cvss = float(entry.get("cvss", 0.0))
                        if cvss >= self.config["min_cvss_score"]:
                            cve_id = entry.get("id")
                            epss = await self.fetch_epss_score(session, cve_id)
                            results.append({
                                "cve_id": cve_id,
                                "cvss": cvss,
                                "epss": epss,
                                "summary": entry.get("summary", "No summary.")
                            })
        except Exception as e:
            logging.error(f"CIRCL fallback failed for {cpe_str}: {e}")
        return results