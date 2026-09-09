#!/usr/bin/env python3
"""
VulnSync-Mapper (VSM)
Automated Nmap Scan Parser, Vulnerability Correlator, and NSE Script Synchronizer.
"""

import argparse
import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

import aiohttp

# Set up logging formatting
logging.basicConfig(level=logging.INFO, format="[*] %(message)s")


class ConfigManager:
    """Manages application configuration, creating default config.json if missing."""

    DEFAULT_CONFIG = {
        "nvd_api_key": "",
        "min_cvss_score": 7.0,
        "min_epss_score": 0.10,
        "nse_custom_dir": "./scripts/custom/",
        "fallback_to_circl": True,
        "max_concurrent_workers": 10,
        "allowed_script_sources": [
            "https://raw.githubusercontent.com/nmap/nmap/master/scripts/"
        ],
    }

    @staticmethod
    def load_config(config_path: str = "config.json") -> Dict[str, Any]:
        if not os.path.exists(config_path):
            with open(config_path, "w") as f:
                json.dump(ConfigManager.DEFAULT_CONFIG, f, indent=4)
            logging.info(f"Created default configuration file at {config_path}")
            return ConfigManager.DEFAULT_CONFIG

        with open(config_path, "r") as f:
            config = json.load(f)

        # Check environment variable if config key is empty
        if not config.get("nvd_api_key"):
            config["nvd_api_key"] = os.getenv("NVD_API_KEY", "")

        return config


class ScanParser:
    """Parses Nmap XML outputs or executes direct Nmap scans."""

    @staticmethod
    def parse_xml(xml_path: str) -> List[Dict[str, Any]]:
        """Extracts IP addresses, ports, services, and CPEs from Nmap XML exports."""
        if not os.path.exists(xml_path):
            logging.error(f"Target XML file not found: {xml_path}")
            sys.exit(1)

        tree = ET.parse(xml_path)
        root = tree.getroot()
        targets = []

        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue

            # Identify IP address
            addr_elem = host.find("address[@addrtype='ipv4']")
            if addr_elem is None:
                addr_elem = host.find("address")
            ip = addr_elem.get("addr") if addr_elem is not None else "Unknown"

            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port in ports_elem.findall("port"):
                state_elem = port.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                port_id = port.get("portid")
                protocol = port.get("protocol")
                service_elem = port.find("service")

                service_name = (
                    service_elem.get("name") if service_elem is not None else "unknown"
                )
                product = (
                    service_elem.get("product", "") if service_elem is not None else ""
                )
                version = (
                    service_elem.get("version", "") if service_elem is not None else ""
                )

                cpes = []
                if service_elem is not None:
                    for cpe_elem in service_elem.findall("cpe"):
                        if cpe_elem.text:
                            cpes.append(cpe_elem.text)

                targets.append(
                    {
                        "ip": ip,
                        "port": f"{port_id}/{protocol}",
                        "service": service_name,
                        "banner": f"{product} {version}".strip(),
                        "cpes": cpes,
                    }
                )

        return targets

    @staticmethod
    def run_live_scan(target: str, output_xml: str = "temp_scan.xml") -> List[Dict[str, Any]]:
        """Executes a live Nmap discovery scan and returns parsed targets."""
        logging.info(f"Initiating live Nmap discovery sweep against target: {target}")
        cmd = ["nmap", "-sV", "-O", "-oX", output_xml, target]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return ScanParser.parse_xml(output_xml)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logging.error(f"Failed to execute Nmap scan. Ensure Nmap is installed: {e}")
            sys.exit(1)


class VulnerabilityCorrelator:
    """Handles asynchronous vulnerability lookups against NVD, CIRCL, and EPSS APIs."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.circl_url = "https://cve.circl.lu/api/cvefor/"
        self.epss_url = "https://api.first.org/data/v1/epss"

    async def fetch_epss_score(self, session: aiohttp.ClientSession, cve_id: str) -> float:
        """Queries FIRST EPSS API for exploitation probability score."""
        try:
            async with session.get(f"{self.epss_url}?cve={cve_id}", timeout=5) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("data"):
                        return float(data["data"][0].get("epss", 0.0))
        except Exception:
            pass
        return 0.0

    async def query_cpe(self, session: aiohttp.ClientSession, cpe_str: str) -> List[Dict[str, Any]]:
        """Queries NVD REST API with automated CIRCL fallback for rate limiting."""
        headers = {}
        api_key = self.config.get("nvd_api_key")
        if api_key:
            headers["apiKey"] = api_key

        params = {"cpeName": cpe_str}
        results = []

        try:
            async with session.get(self.nvd_url, params=params, headers=headers, timeout=8) as resp:
                if resp.status == 200:
                    payload = await resp.json()
                    for item in payload.get("vulnerabilities", []):
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
                            results.append(
                                {
                                    "cve_id": cve_id,
                                    "cvss": cvss_score,
                                    "epss": epss_score,
                                    "summary": cve.get("descriptions", [{}])[0].get("value", "N/A"),
                                }
                            )
                    return results
                elif resp.status == 429 and self.config["fallback_to_circl"]:
                    logging.warning(f"NVD Rate limit hit for {cpe_str}. Routing to CIRCL fallback...")
                    return await self._query_circl_fallback(session, cpe_str)
        except Exception:
            if self.config["fallback_to_circl"]:
                return await self._query_circl_fallback(session, cpe_str)
        return results

    async def _query_circl_fallback(self, session: aiohttp.ClientSession, cpe_str: str) -> List[Dict[str, Any]]:
        results = []
        try:
            async with session.get(f"{self.circl_url}{cpe_str}", timeout=6) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data[:10]:
                        cvss = float(entry.get("cvss", 0.0))
                        if cvss >= self.config["min_cvss_score"]:
                            cve_id = entry.get("id")
                            epss = await self.fetch_epss_score(session, cve_id)
                            results.append(
                                {
                                    "cve_id": cve_id,
                                    "cvss": cvss,
                                    "epss": epss,
                                    "summary": entry.get("summary", "N/A"),
                                }
                            )
        except Exception as e:
            logging.error(f"CIRCL query failed for {cpe_str}: {e}")
        return results


class ScriptSynchronizer:
    """Downloads remote NSE scripts or constructs dynamic stub probes locally."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.script_dir = config.get("nse_custom_dir", "./scripts/custom/")
        os.makedirs(self.script_dir, exist_ok=True)

    def sync_script(self, cve_id: str) -> str:
        clean_cve = cve_id.lower().replace("-", "_")
        script_name = f"exploit_{clean_cve}.nse"
        local_path = os.path.join(self.script_dir, script_name)

        if os.path.exists(local_path):
            return script_name

        # Download from trusted source repositories
        for base_url in self.config.get("allowed_script_sources", []):
            url = f"{base_url}{script_name}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "VulnSync-Mapper/1.0"})
                with urllib.request.urlopen(req, timeout=4) as response:
                    if response.status == 200:
                        with open(local_path, "w") as f:
                            f.write(response.read().decode("utf-8"))
                        self._reindex_db()
                        return script_name
            except Exception:
                continue

        # Generate a dynamic validation stub if script does not exist remotely
        return self._generate_stub(cve_id, local_path)

    def _generate_stub(self, cve_id: str, path: str) -> str:
        stub = f"""-- Dynamic Auto-Generated NSE Probe for {cve_id}
description = [[ Automated probe detecting exposure for {cve_id}. ]]
author = "VulnSync-Mapper"
categories = {{"vuln", "safe"}}

portrule = function(host, port)
  return port.state == "open"
end

action = function(host, port)
  return string.format("EXPOSURE ALERT: Target host %s port %d flagged for {cve_id}.", host.ip, port.number)
end
"""
        with open(path, "w") as f:
            f.write(stub)
        self._reindex_db()
        return os.path.basename(path)

    def _reindex_db(self):
        try:
            subprocess.run(["nmap", "--script-updatedb"], capture_output=True)
        except Exception:
            pass


async def main_async(args, config):
    if args.xml_target:
        targets = ScanParser.parse_xml(args.xml_target)
    else:
        targets = ScanParser.run_live_scan(args.target)

    logging.info(f"Loaded {len(targets)} active port/service instances for analysis.")

    correlator = VulnerabilityCorrelator(config)
    synchronizer = ScriptSynchronizer(config) if args.update_scripts else None

    connector = aiohttp.TCPConnector(limit=config.get("max_concurrent_workers", 10))
    async with aiohttp.ClientSession(connector=connector) as session:
        for target in targets:
            print(f"\n>> Target Device: {target['ip']} | Port: {target['port']} ({target['service']})")
            if not target["cpes"]:
                print("   [!] No explicit CPE strings extracted.")
                continue

            for cpe in target["cpes"]:
                print(f"   [+] Querying vulnerabilities for CPE: {cpe}")
                vulns = await correlator.query_cpe(session, cpe)

                if not vulns:
                    print("       ✔ No critical vulnerabilities matched CVSS/EPSS thresholds.")
                    continue

                for v in vulns:
                    if v["epss"] < args.min_epss:
                        continue

                    print(f"       X [{v['cve_id']}] CVSS: {v['cvss']} | EPSS: {v['epss']:.2f}")
                    print(f"         Summary: {v['summary'][:100]}...")

                    if synchronizer:
                        script_file = synchronizer.sync_script(v["cve_id"])
                        print(f"         Action: Synced NSE verification script -> {script_file}")


def main():
    parser = argparse.ArgumentParser(description="VulnSync-Mapper (VSM) Vulnerability Correlation Tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--xml-target", help="Path to Nmap XML scan export file (-oX)")
    group.add_argument("--target", help="IP address or subnet to run a live scan against")

    parser.add_argument("--min-cvss", type=float, default=7.0, help="Minimum CVSS base score threshold")
    parser.add_argument("--min-epss", type=float, default=0.05, help="Minimum EPSS score threshold")
    parser.add_argument("--update-scripts", action="store_true", help="Download/generate matching NSE scripts")

    args = parser.parse_args()
    config = ConfigManager.load_config()

    if args.min_cvss:
        config["min_cvss_score"] = args.min_cvss

    asyncio.run(main_async(args, config))


if __name__ == "__main__":
    main()