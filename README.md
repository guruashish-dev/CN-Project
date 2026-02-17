# AutoVuln — Automated Vulnerability Assessment & Reporting Platform

AutoVuln orchestrates **safe**, controlled vulnerability assessments by driving Kali tools (`nmap`, `whatweb`, `nikto`, `wapiti`) through a FastAPI automation layer and React dashboard.

## Architecture

Frontend (React) → FastAPI Backend (Controller + Parsers) → Kali Runner (Docker or WSL) → Tools

## Features

- URL input + execution mode selection (Docker preferred, WSL fallback)
- Safe sequential scan workflow with timeout (5 minutes max)
- Structured parser output:
  - title, description, evidence, severity, remediation, source_tool
- Severity-aware dashboard + risk scoring
- Professional HTML and PDF report generation (WeasyPrint)
- Demo mode toggle targeting `http://testphp.vulnweb.com`
- **Safe attack simulation mode** using benign query-string probes for measurable before/after behavior
- **Scan comparison** support to measure deltas in risk score, findings, latency, and blocked-rate
- Tool connectivity status API

## APIs

- `POST /scan` — start scan, returns `scan_id`
  - supports `simulate_attack` and `compare_to_scan_id`
- `GET /scan/{id}` — poll progress + findings + metrics + optional comparison
- `GET /scan/compare?baseline_scan_id=...&candidate_scan_id=...` — direct comparison endpoint
- `GET /report/{id}` — HTML report
- `GET /report/{id}/pdf` — PDF report
- `GET /tools/status?mode=docker|wsl` — connectivity check

## Quick Start (Docker Compose)

```bash
docker compose up --build
```

Then open:
- Frontend: http://localhost:5173
- Backend docs: http://localhost:8000/docs

## Local Setup (WSL fallback available)

### 1) Install backend dependencies
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 2) Install frontend dependencies
```bash
cd frontend
npm install
npm run dev
```

### 3) WSL Kali mode prerequisites (Windows)
```bash
wsl --install -d kali-linux
wsl -d kali-linux -- sudo apt update
wsl -d kali-linux -- sudo apt install -y nmap nikto whatweb wapiti
```

## Safety Constraints Implemented

- Scans only provided URL/domain
- Tool sequence fixed and bounded
- 5-minute maximum scan runtime
- No brute force, no payload flooding, no subdomain enumeration
- Passive/safe active checks only
- Attack simulation uses benign URL query probes only (no exploit execution)

## How to Simulate Attack and Measure Difference

1. Run a normal baseline scan and save its `scan_id`.
2. Start a second scan with:
   - **Simulate Attack** toggle ON
   - **Compare Against Previous Scan ID** filled with the baseline ID
3. Review deltas in Results Dashboard:
   - Risk delta
   - Findings delta by severity
   - Latency delta
   - Blocked-rate delta
4. Export HTML/PDF report for judging.

## Troubleshooting

- **`/tools/status` shows missing tools in Docker mode**:
  - Ensure `kali_scanner` is running: `docker ps | grep kali_scanner`
  - Rebuild Kali image: `./kali/setup.sh`
- **PDF not generated**:
  - Ensure backend container has required system libs (already in `backend/Dockerfile`)
- **WSL mode fails**:
  - Confirm distro name `kali-linux`: `wsl -l -v`
  - Adjust `kali_executor.py` if distro label differs.

## Demo Tips for Judges

1. Enable **Demo Safe Target** toggle in Home page.
2. Run baseline scan first.
3. Run second scan with **Simulate Attack** enabled and baseline ID set.
4. Show comparison section in dashboard and download PDF report.
