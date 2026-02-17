import json
from typing import List, Dict


WAPITI_MAP = {
    "xss": ("Reflected/Stored XSS", "High", "Sanitize user input and apply contextual output encoding."),
    "sql": ("SQL Injection", "Critical", "Use prepared statements and avoid string-built SQL queries."),
    "backup": ("Sensitive Backup File Exposure", "High", "Remove backup files from web roots and restrict access."),
    "exec": ("Command Injection Risk", "Critical", "Validate input and avoid shell interpolation on user data."),
}


def parse_wapiti(output: str) -> List[Dict]:
    findings = []
    try:
        data = json.loads(output or "{}")
    except json.JSONDecodeError:
        return findings

    vulns = data.get("vulnerabilities", {})
    for key, entries in vulns.items():
        for entry in entries:
            title, sev, rem = WAPITI_MAP.get(
                key.lower(),
                (f"Wapiti finding: {key}", "Medium", "Review and remediate the discovered input validation issue."),
            )
            findings.append(
                {
                    "title": title,
                    "description": entry.get("info", "Web vulnerability discovered by Wapiti."),
                    "evidence": f"Path: {entry.get('path', '')} Parameter: {entry.get('parameter', '')}",
                    "severity": sev,
                    "remediation": rem,
                    "source_tool": "wapiti",
                }
            )
    return findings
