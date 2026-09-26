"""
BobPulse FastAPI Application Server.
Hosts API endpoints for codebase modernization, diff generation, and test sandboxing,
and serves the BobPulse Studio Frontend.
"""

import os
from fastapi import FastAPI, HTTPException, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any

from backend.presets import PRESETS
from backend.engine import BobPulseEngine
from backend.patch_generator import generate_pull_request_payload

app = FastAPI(
    title="BobPulse API",
    description="Autonomous Code Modernization & Self-Healing Gateway powered by IBM Bob 2.0",
    version="2.0.0"
)

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = BobPulseEngine()

class AnalyzeRequest(BaseModel):
    code: str
    language: str = "python"
    preset_id: Optional[str] = None
    filename: Optional[str] = "service.py"

class TestRunRequest(BaseModel):
    modernized_code: str
    test_code: str
    language: str = "python"

class PRExportRequest(BaseModel):
    filename: str
    diff_unified: str
    metrics: Dict[str, Any]
    issues: Dict[str, Any]

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "system": "BobPulse Gateway",
        "version": "2.0.0",
        "ibm_bob_status": "ONLINE (Connected)",
        "models_available": ["IBM Granite 20B Code", "IBM Bob 2.0 Agentic Reasoner", "Self-Healing Sandbox"]
    }

@app.get("/api/presets")
def get_presets():
    """Returns available enterprise legacy benchmarks."""
    result = []
    for k, v in PRESETS.items():
        result.append({
            "id": v["id"],
            "name": v["name"],
            "language": v["language"],
            "category": v["category"],
            "description": v["description"],
            "original_code": v["original_code"]
        })
    return {"presets": result}

@app.post("/api/analyze")
def analyze_code(req: AnalyzeRequest):
    """Executes the full BobPulse 5-stage modernization pipeline."""
    if not req.code or not req.code.strip():
        raise HTTPException(status_code=400, detail="Source code must not be empty.")

    try:
        result = engine.analyze_and_modernize(
            code=req.code,
            language=req.language,
            preset_id=req.preset_id
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/run-tests")
def run_tests(req: TestRunRequest):
    """Executes sandbox verification test suite."""
    return engine._verify_in_sandbox(req.modernized_code, req.test_code, req.language)

@app.post("/api/export-pr")
def export_pr(req: PRExportRequest):
    """Generates GitHub Pull Request metadata and patch."""
    payload = generate_pull_request_payload(
        original_filename=req.filename,
        diff_unified=req.diff_unified,
        metrics=req.metrics,
        issues=req.issues
    )
    return payload

@app.post("/api/download-patch")
def download_patch(req: PRExportRequest):
    """Returns downloadable .patch file content."""
    payload = generate_pull_request_payload(
        original_filename=req.filename,
        diff_unified=req.diff_unified,
        metrics=req.metrics,
        issues=req.issues
    )
    diff_text = payload.get("diff_unified", "")
    return Response(
        content=diff_text,
        media_type="text/x-diff",
        headers={"Content-Disposition": f"attachment; filename=bobpulse-{req.filename}.patch"}
    )

# Mount frontend directory
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
