from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, HttpUrl

from scanner_controller import scanner_controller


app = FastAPI(title="AutoVuln API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: HttpUrl
    mode: str = "docker"
    demo_safe_target: bool = False


@app.post("/scan")
def start_scan(payload: ScanRequest):
    scan_id = scanner_controller.start_scan(
        target_url=str(payload.url),
        mode=payload.mode,
        demo_safe_target=payload.demo_safe_target,
    )
    return {"scan_id": scan_id}


@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    scan = scanner_controller.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/report/{scan_id}", response_class=HTMLResponse)
def get_report(scan_id: str):
    html = scanner_controller.get_report_html(scan_id)
    if not html:
        raise HTTPException(status_code=404, detail="Report not found")
    return html


@app.get("/report/{scan_id}/pdf")
def get_report_pdf(scan_id: str):
    path = scanner_controller.get_report_pdf(scan_id)
    if not path:
        raise HTTPException(status_code=404, detail="PDF report not found")
    return FileResponse(path=path, media_type="application/pdf", filename=f"autovuln-{scan_id}.pdf")


@app.get("/tools/status")
def tools_status(mode: str = "docker"):
    return scanner_controller.tools_status(mode)


@app.get("/health")
def health():
    return {"status": "ok"}
