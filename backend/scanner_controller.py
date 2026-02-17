import os
import threading
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List
from urllib.error import URLError
from urllib.parse import quote_plus, urlparse
from urllib.request import urlopen

from kali_executor import KaliExecutor
from parsers.nikto_parser import parse_nikto
from parsers.nmap_parser import parse_nmap
from parsers.wapiti_parser import parse_wapiti
from parsers.whatweb_parser import parse_whatweb
from report_generator import build_report
from scoring import calculate_risk_score

MAX_SCAN_SECONDS = 300
DEMO_TARGET = "http://testphp.vulnweb.com"
SAFE_SIMULATION_PAYLOADS = [
    "<script>alert(1)</script>",
    "' OR '1'='1",
    "../../etc/passwd",
    "admin'--",
]


@dataclass
class ScanState:
    scan_id: str
    target_url: str
    mode: str
    created_at: str
    simulate_attack: bool = False
    compare_to_scan_id: str = ""
    status: str = "queued"
    current_tool: str = "pending"
    logs: List[str] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)
    progress: int = 0
    report_html: str = ""
    report_pdf_path: str = ""
    metrics: dict = field(default_factory=dict)
    error: str = ""


class ScannerController:
    def __init__(self):
        self.scans: Dict[str, ScanState] = {}
        self.lock = threading.Lock()

    def start_scan(
        self,
        target_url: str,
        mode: str,
        demo_safe_target: bool = False,
        simulate_attack: bool = False,
        compare_to_scan_id: str = "",
    ) -> str:
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
            simulate_attack=simulate_attack,
            compare_to_scan_id=compare_to_scan_id,
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
            comparison = self.compare_scans(state.compare_to_scan_id, scan_id) if state.compare_to_scan_id else None
            return {
                "scan_id": state.scan_id,
                "target_url": state.target_url,
                "mode": state.mode,
                "simulate_attack": state.simulate_attack,
                "compare_to_scan_id": state.compare_to_scan_id,
                "created_at": state.created_at,
                "status": state.status,
                "current_tool": state.current_tool,
                "progress": state.progress,
                "logs": state.logs,
                "findings": state.findings,
                "risk_score": risk_score,
                "metrics": state.metrics,
                "comparison": comparison,
                "error": state.error,
            }

    def compare_scans(self, baseline_scan_id: str, candidate_scan_id: str):
        baseline = self.scans.get(baseline_scan_id)
        candidate = self.scans.get(candidate_scan_id)
        if not baseline or not candidate:
            return None

        base_risk = calculate_risk_score(baseline.findings)
        cand_risk = calculate_risk_score(candidate.findings)
        base_dist = Counter(f.get("severity", "Low") for f in baseline.findings)
        cand_dist = Counter(f.get("severity", "Low") for f in candidate.findings)

        return {
            "baseline_scan_id": baseline_scan_id,
            "candidate_scan_id": candidate_scan_id,
            "risk_score_delta": cand_risk["score"] - base_risk["score"],
            "severity_delta": {sev: cand_dist.get(sev, 0) - base_dist.get(sev, 0) for sev in ["Critical", "High", "Medium", "Low"]},
            "findings_delta": len(candidate.findings) - len(baseline.findings),
            "latency_delta_ms": candidate.metrics.get("post_scan_http", {}).get("avg_latency_ms", 0)
            - baseline.metrics.get("post_scan_http", {}).get("avg_latency_ms", 0),
            "blocked_rate_delta": candidate.metrics.get("simulation", {}).get("blocked_rate", 0)
            - baseline.metrics.get("simulation", {}).get("blocked_rate", 0),
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

    def _collect_http_metrics(self, url: str, sample_count: int = 6):
        latencies = []
        statuses = Counter()
        errors = 0
        for _ in range(sample_count):
            started = time.time()
            try:
                response = urlopen(url, timeout=6)
                statuses[str(response.status)] += 1
            except URLError:
                errors += 1
            finally:
                latencies.append((time.time() - started) * 1000)
        avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0
        return {
            "avg_latency_ms": avg_latency,
            "status_distribution": dict(statuses),
            "error_rate": round(errors / sample_count, 2),
        }

    def _run_safe_attack_simulation(self, target_url: str):
        statuses = Counter()
        latencies = []
        blocked = 0
        total = 0
        separator = "&" if "?" in target_url else "?"
        for payload in SAFE_SIMULATION_PAYLOADS:
            for idx in range(4):
                test_url = f"{target_url}{separator}autovuln_probe_{idx}={quote_plus(payload)}"
                started = time.time()
                total += 1
                try:
                    response = urlopen(test_url, timeout=6)
                    statuses[str(response.status)] += 1
                    if response.status in {403, 406, 429}:
                        blocked += 1
                except URLError:
                    blocked += 1
                finally:
                    latencies.append((time.time() - started) * 1000)

        avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0
        return {
            "requests_sent": total,
            "blocked_rate": round(blocked / total, 2) if total else 0,
            "avg_latency_ms": avg_latency,
            "status_distribution": dict(statuses),
            "note": "Simulation uses benign query-string probes only; no exploit payload execution attempted.",
        }

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
        baseline_http = self._collect_http_metrics(state.target_url)
        self._append_log(scan_id, f"[+] Baseline HTTP metrics: {baseline_http}")

        if state.simulate_attack:
            self._set_state(scan_id, current_tool="safe-simulation", progress=5)
            sim = self._run_safe_attack_simulation(state.target_url)
            self._append_log(scan_id, f"[+] Safe attack simulation complete: {sim}")
        else:
            sim = {"requests_sent": 0, "blocked_rate": 0, "avg_latency_ms": 0, "status_distribution": {}}

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

            self._set_state(scan_id, current_tool=tool, progress=int(idx / len(toolchain) * 95))
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

        post_http = self._collect_http_metrics(state.target_url)
        metrics = {
            "baseline_http": baseline_http,
            "simulation": sim,
            "post_scan_http": post_http,
            "duration_seconds": round(time.time() - started, 2),
        }
        self._set_state(scan_id, progress=100, current_tool="done", findings=findings, metrics=metrics, status="completed")
        report = build_report(scan_id=scan_id, target_url=state.target_url, findings=findings, metrics=metrics)
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
