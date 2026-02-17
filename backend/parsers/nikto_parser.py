from typing import List, Dict


def parse_nikto(output: str) -> List[Dict]:
    findings = []
    for line in output.splitlines():
        l = line.lower()
        if "+ " not in line:
            continue
        severity = "Medium"
        title = "Nikto Finding"
        remediation = "Review server configuration and patch identified issues."

        if "xss" in l:
            severity = "High"
            title = "Potential XSS Indicator"
            remediation = "Apply output encoding and strict input validation."
        elif "sql" in l and "inject" in l:
            severity = "Critical"
            title = "Potential SQL Injection Indicator"
            remediation = "Use parameterized queries and rigorous server-side validation."
        elif "admin" in l:
            severity = "High"
            title = "Exposed Admin Interface"
            remediation = "Restrict admin interfaces by IP and enforce MFA."
        elif "header" in l:
            severity = "Medium"
            title = "Missing/Weak Security Headers"
            remediation = "Add HSTS, CSP, X-Frame-Options, and related headers."

        findings.append(
            {
                "title": title,
                "description": "Potential web server weakness identified by Nikto.",
                "evidence": line.strip(),
                "severity": severity,
                "remediation": remediation,
                "source_tool": "nikto",
            }
        )
    return findings
