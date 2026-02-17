import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List
from urllib.parse import urlparse

from kali_executor import KaliExecutor
from parsers.nikto_parser import parse_nikto
from parsers.nmap_parser import parse_nmap
from parsers.wapiti_parser import parse_wapiti
from parsers.whatweb_parser import parse_whatweb
from report_generator import build_report
from scoring import calculate_risk_score

MAX_SCAN_SECONDS = 300
DEMO_TARGET = "http://testphp.vulnweb.com"


@dataclass
class ScanState:
    scan_id: str
    target_url: str
    mode: str
    created_at: str
    status: str = "queued"
    current_tool: str = "pending"
    logs: List[str] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)
    progress: int = 0
    report_html: str = ""
    report_pdf_path: str = ""
    error: str = ""


class ScannerController:
    def __init__(self):
        self.scans: Dict[str, ScanState] = {}
        self.lock = threading.Lock()

    def start_scan(self, target_url: str, mode: str, demo_safe_target: bool = False) -> str:
        scan_id = str(uuid.uuid4())
        final_url = DEMO_TARGET if demo_safe_target else target_url
        mode = mode.lower().strip()
        if mode not in {"docker", "wsl"}:
            mode = "docker"

        state = ScanState(
            scan_id=scan_id,
            target_url=final_url,
            mode=mode,
            created_at=datetime.utcnow().isoformat() + "Z",
        )
        with self.lock:
            self.scans[scan_id] = state

        thread = threading.Thread(target=self._run_scan, args=(scan_id,), daemon=True)
        thread.start()
        return scan_id

    def get_scan(self, scan_id: str):
        with self.lock:
            state = self.scans.get(scan_id)
            if not state:
                return None
            risk_score = calculate_risk_score(state.findings)
            return {
                "scan_id": state.scan_id,
                "target_url": state.target_url,
                "mode": state.mode,
                "created_at": state.created_at,
                "status": state.status,
                "current_tool": state.current_tool,
                "progress": state.progress,
                "logs": state.logs,
                "findings": state.findings,
                "risk_score": risk_score,
                "error": state.error,
            }

    def get_report_html(self, scan_id: str):
        with self.lock:
            s = self.scans.get(scan_id)
            return s.report_html if s else ""

    def get_report_pdf(self, scan_id: str):
        with self.lock:
            s = self.scans.get(scan_id)
            return s.report_pdf_path if s else ""

    def tools_status(self, mode: str):
        executor = KaliExecutor(mode)
        return executor.check_connectivity()

    def _append_log(self, scan_id: str, message: str):
        with self.lock:
            self.scans[scan_id].logs.append(message)

    def _set_state(self, scan_id: str, **kwargs):
        with self.lock:
            state = self.scans[scan_id]
            for k, v in kwargs.items():
                setattr(state, k, v)

    def _run_scan(self, scan_id: str):
        with self.lock:
            state = self.scans[scan_id]
        parsed = urlparse(state.target_url)
        domain = parsed.netloc
        if not domain:
            self._set_state(scan_id, status="failed", error="Invalid target URL")
            return

        executor = KaliExecutor(state.mode)
        self._set_state(scan_id, status="running")

        started = time.time()
        findings: List[dict] = []
        toolchain = [
            ("nmap", ["nmap", "-sV", "-T4", "-Pn", domain]),
            ("whatweb", ["whatweb", state.target_url]),
            ("nikto", ["nikto", "-h", state.target_url]),
            ("wapiti", ["wapiti", "-u", state.target_url, "-f", "json", "-o", f"/tmp/{scan_id}-wapiti.json"]),
        ]

        for idx, (tool, cmd) in enumerate(toolchain, start=1):
            if time.time() - started > MAX_SCAN_SECONDS:
                self._set_state(scan_id, status="failed", error="Scan timed out after 5 minutes")
                return

            self._set_state(scan_id, current_tool=tool, progress=int((idx - 1) / len(toolchain) * 100))
            self._append_log(scan_id, f"[+] Running {tool}: {' '.join(cmd)}")
            result = executor.run(cmd, timeout=120)
            self._append_log(scan_id, result.get("log", ""))

            output = result.get("stdout", "") + "\n" + result.get("stderr", "")
            if tool == "nmap":
                findings.extend(parse_nmap(output))
            elif tool == "whatweb":
                findings.extend(parse_whatweb(output))
            elif tool == "nikto":
                findings.extend(parse_nikto(output))
            elif tool == "wapiti":
                json_out = executor.read_file(f"/tmp/{scan_id}-wapiti.json")
                findings.extend(parse_wapiti(json_out or "{}"))

        self._set_state(scan_id, progress=100, current_tool="done", findings=findings, status="completed")
        report = build_report(scan_id=scan_id, target_url=state.target_url, findings=findings)
        os.makedirs("reports", exist_ok=True)
        html_path = os.path.join("reports", f"{scan_id}.html")
        pdf_path = os.path.join("reports", f"{scan_id}.pdf")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(report["html"])
        if report.get("pdf_bytes"):
            with open(pdf_path, "wb") as f:
                f.write(report["pdf_bytes"])

        self._set_state(scan_id, report_html=report["html"], report_pdf_path=pdf_path if os.path.exists(pdf_path) else "")


scanner_controller = ScannerController()
