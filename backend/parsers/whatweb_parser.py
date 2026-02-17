from typing import List, Dict


def parse_whatweb(output: str) -> List[Dict]:
    findings = []
    if output.strip():
        findings.append(
            {
                "title": "Technology Fingerprint Identified",
                "description": "Publicly visible technology stack details can help attackers profile your surface.",
                "evidence": output.strip()[:700],
                "severity": "Low",
                "remediation": "Reduce unnecessary banners and keep exposed technologies fully patched.",
                "source_tool": "whatweb",
            }
        )

    for keyword in ["X-Powered-By", "Server"]:
        if keyword.lower() in output.lower():
            findings.append(
                {
                    "title": "Header/Banner Exposure",
                    "description": "Server or framework identification headers were discovered.",
                    "evidence": keyword,
                    "severity": "Medium",
                    "remediation": "Limit version-revealing headers and enforce a hardened server config.",
                    "source_tool": "whatweb",
                }
            )
    return findings
