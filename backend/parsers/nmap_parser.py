import re
from typing import List, Dict


def parse_nmap(output: str) -> List[Dict]:
    findings = []
    for line in output.splitlines():
        if re.search(r"\d+/tcp\s+open", line):
            findings.append(
                {
                    "title": "Open Port Detected",
                    "description": "An open TCP port was identified on the target.",
                    "evidence": line.strip(),
                    "severity": "Low",
                    "remediation": "Close unused ports and restrict access with firewall rules.",
                    "source_tool": "nmap",
                }
            )
        if "Service Info:" in line or "version" in line.lower() and "open" in line.lower():
            findings.append(
                {
                    "title": "Potential Outdated Service",
                    "description": "Service/version disclosure can indicate outdated software components.",
                    "evidence": line.strip(),
                    "severity": "Medium",
                    "remediation": "Patch services and minimize version disclosure where possible.",
                    "source_tool": "nmap",
                }
            )
    return findings
