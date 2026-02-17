from datetime import datetime
from jinja2 import Environment, FileSystemLoader

from scoring import calculate_risk_score

try:
    from weasyprint import HTML
except Exception:  # if Cairo deps unavailable
    HTML = None


def build_report(scan_id: str, target_url: str, findings: list):
    env = Environment(loader=FileSystemLoader("backend/templates"))
    tpl = env.get_template("report.html.j2")
    risk = calculate_risk_score(findings)
    grouped = {
        "Critical": [f for f in findings if f.get("severity") == "Critical"],
        "High": [f for f in findings if f.get("severity") == "High"],
        "Medium": [f for f in findings if f.get("severity") == "Medium"],
        "Low": [f for f in findings if f.get("severity") == "Low"],
    }
    html = tpl.render(
        scan_id=scan_id,
        target_url=target_url,
        generated_at=datetime.utcnow().isoformat() + "Z",
        findings=findings,
        grouped=grouped,
        risk=risk,
    )
    pdf_bytes = b""
    if HTML:
        pdf_bytes = HTML(string=html).write_pdf()
    return {"html": html, "pdf_bytes": pdf_bytes}
