#!/usr/bin/env python3
"""
VulnSync-Mapper (VSM)
Quick CVE/EPSS correlator and NSE script sync for Nmap scans.
"""

import argparse
import asyncio
import json
import logging
import os
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

import aiohttp

logging.basicConfig(level=logging.INFO, format="[+] %(message)s")

DEFAULT_CONFIG = {
    "nvd_api_key": "",
    "min_cvss_score": 7.0,
    "min_epss_score": 0.10,
    "nmap_path": "nmap",
    "nse_custom_dir": "./scripts/custom/",
    "fallback_to_circl": True,
    "max_concurrent_workers": 10,
    "allowed_script_sources": [
        "https://raw.githubusercontent.com/nmap/nmap/master/scripts/"
    ],
}


def load_config(config_path: str = "config.json") -> Dict[str, Any]:
    """Loads JSON config or generates default if missing."""
    if not os.path.exists(config_path):
        with open(config_path, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        logging.info(f"Created default config at {config_path}")
        return DEFAULT_CONFIG

    with open(config_path, "r") as f:
        config = json.load(f)

    # Pull from environment if not explicitly set in config file
    if not config.get("nvd_api_key"):
        config["nvd_api_key"] = os.getenv("NVD_API_KEY", "")

    return config


def parse_nmap_xml(xml_path: str) -> List[Dict[str, Any]]:
    """Extracts IP, open ports, banners, and CPEs from Nmap XML exports."""
    if not os.path.exists(xml_path):
        logging.error(f"Scan file not found: {xml_path}")
        sys.exit(1)

    tree = ET.parse(xml_path)
    root = tree.getroot()
    targets = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addr_elem = host.find("address[@addrtype='ipv4']") or host.find("address")
        ip = addr_elem.get("addr") if addr_elem is not None else "Unknown"

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port in ports_elem.findall("port"):
            state_elem = port.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            port_id = port.get("portid")
            proto = port.get("protocol")
            service_elem = port.find("service")

            svc_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
            product = service_elem.get("product", "") if service_elem is not None else ""
            version = service_elem.get("version", "") if service_elem is not None else ""

            cpes = []
            if service_elem is not None:
                for cpe_elem in service_elem.findall("cpe"):
                    if cpe_elem.text:
                        cpes.append(cpe_elem.text)

            targets.append({
                "ip": ip,
                "port": f"{port_id}/{proto}",
                "service": svc_name,
                "banner": f"{product} {version}".strip(),
                "cpes": cpes,
            })

    return targets


def run_live_scan(target: str, nmap_bin: str = "nmap", output_xml: str = "temp_scan.xml") -> List[Dict[str, Any]]:
    """Runs a quick live scan against the target and returns parsed results."""
    logging.info(f"Running live scan on target: {target}")
    cmd = [nmap_bin, "-sV", "-O", "-oX", output_xml, target]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return parse_nmap_xml(output_xml)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logging.error(f"Nmap execution failed. Verify your installation/path: {e}")
        sys.exit(1)


class VulnLookup:
    """Handles NVD API lookups with CIRCL fallback and EPSS scoring."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.circl_url = "https://cve.circl.lu/api/cvefor/"
        self.epss_url = "https://api.first.org/data/v1/epss"

    async def get_epss(self, session: aiohttp.ClientSession, cve_id: str) -> float:
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
        headers = {}
        api_key = self.config.get("nvd_api_key")
        if api_key:
            headers["apiKey"] = api_key

        results = []
        try:
            async with session.get(self.nvd_url, params={"cpeName": cpe_str}, headers=headers, timeout=8) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get("vulnerabilities", []):
                        cve = item.get("cve", {})
                        cve_id = cve.get("id")
                        metrics = cve.get("metrics", {})

                        cvss = 0.0
                        if "cvssMetricV31" in metrics:
                            cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                        elif "cvssMetricV30" in metrics:
                            cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

                        if cvss >= self.config["min_cvss_score"]:
                            epss = await self.get_epss(session, cve_id)
                            results.append({
                                "cve_id": cve_id,
                                "cvss": cvss,
                                "epss": epss,
                                "summary": cve.get("descriptions", [{}])[0].get("value", "N/A"),
                            })
                    return results
                
                # NVD rate limit hit, drop to fallback
                if resp.status == 429 and self.config.get("fallback_to_circl"):
                    logging.warning(f"Rate limited by NVD for {cpe_str}. Trying CIRCL API...")
                    return await self._circl_fallback(session, cpe_str)

        except Exception:
            if self.config.get("fallback_to_circl"):
                return await self._circl_fallback(session, cpe_str)

        return results

    async def _circl_fallback(self, session: aiohttp.ClientSession, cpe_str: str) -> List[Dict[str, Any]]:
        results = []
        try:
            async with session.get(f"{self.circl_url}{cpe_str}", timeout=6) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data[:10]:
                        cvss = float(entry.get("cvss", 0.0))
                        if cvss >= self.config["min_cvss_score"]:
                            cve_id = entry.get("id")
                            epss = await self.get_epss(session, cve_id)
                            results.append({
                                "cve_id": cve_id,
                                "cvss": cvss,
                                "epss": epss,
                                "summary": entry.get("summary", "N/A"),
                            })
        except Exception as e:
            logging.error(f"CIRCL query failed for {cpe_str}: {e}")
        return results


class ScriptSync:
    """Fetches NSE scripts remotely or generates basic detection stubs."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.script_dir = config.get("nse_custom_dir", "./scripts/custom/")
        os.makedirs(self.script_dir, exist_ok=True)

    def sync(self, cve_id: str) -> str:
        script_name = f"exploit_{cve_id.lower().replace('-', '_')}.nse"
        local_path = os.path.join(self.script_dir, script_name)

        if os.path.exists(local_path):
            return script_name

        # Try downloading from remote repos
        for base_url in self.config.get("allowed_script_sources", []):
            url = f"{base_url}{script_name}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=4) as resp:
                    if resp.status == 200:
                        with open(local_path, "w") as f:
                            f.write(resp.read().decode("utf-8"))
                        self._reindex_db()
                        return script_name
            except Exception:
                continue

        # Generate local fallback stub
        return self._make_stub(cve_id, local_path)

    def _make_stub(self, cve_id: str, path: str) -> str:
        stub = f"""-- Auto-generated stub for {cve_id}
description = [[ Check host exposure for {cve_id}. ]]
author = "VSM"
categories = {{"vuln", "safe"}}

portrule = function(host, port)
  return port.state == "open"
end

action = function(host, port)
  return string.format("EXPOSURE ALERT: Target %s:%d flagged for {cve_id}.", host.ip, port.number)
end
"""
        with open(path, "w") as f:
            f.write(stub)
        self._reindex_db()
        return os.path.basename(path)

    def _reindex_db(self):
        nmap_bin = self.config.get("nmap_path", "nmap")
        try:
            subprocess.run([nmap_bin, "--script-updatedb"], capture_output=True)
        except Exception:
            pass


async def main_async(args, config):
    nmap_bin = config.get("nmap_path", "nmap")
    
    if args.xml_target:
        targets = parse_nmap_xml(args.xml_target)
    else:
        targets = run_live_scan(args.target, nmap_bin=nmap_bin)

    logging.info(f"Loaded {len(targets)} active service instances.")

    vuln_lookup = VulnLookup(config)
    script_sync = ScriptSync(config) if args.update_scripts else None

    connector = aiohttp.TCPConnector(limit=config.get("max_concurrent_workers", 10))
    async with aiohttp.ClientSession(connector=connector) as session:
        for target in targets:
            print(f"\n[>] Host: {target['ip']} | Port: {target['port']} ({target['service']})")
            
            if not target["cpes"]:
                print("    [-] No CPE strings found.")
                continue

            for cpe in target["cpes"]:
                print(f"    [*] Querying CPE: {cpe}")
                vulns = await vuln_lookup.query_cpe(session, cpe)

                if not vulns:
                    print("        [+] No matching high-severity CVEs found.")
                    continue

                for v in vulns:
                    if v["epss"] < args.min_epss:
                        continue

                    print(f"        [!] {v['cve_id']} (CVSS: {v['cvss']} | EPSS: {v['epss']:.2f})")
                    print(f"            {v['summary'][:110]}...")

                    if script_sync:
                        script_file = script_sync.sync(v["cve_id"])
                        print(f"            └─ Staged NSE script: {script_file}")


def main():
    parser = argparse.ArgumentParser(description="VulnSync-Mapper (VSM) - Scan parser & threat correlator")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--xml-target", help="Path to Nmap XML scan results (-oX)")
    group.add_argument("--target", help="Target IP or CIDR for live scan")

    parser.add_argument("--min-cvss", type=float, default=7.0, help="Minimum CVSS threshold")
    parser.add_argument("--min-epss", type=float, default=0.05, help="Minimum EPSS probability threshold")
    parser.add_argument("--update-scripts", action="store_true", help="Download or generate matching NSE verification scripts")

    args = parser.parse_args()
    config = load_config()

    if args.min_cvss:
        config["min_cvss_score"] = args.min_cvss

    asyncio.run(main_async(args, config))


if __name__ == "__main__":
    main()