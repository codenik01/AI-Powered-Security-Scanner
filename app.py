from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, HttpUrl
from typing import Optional, Dict, Any
import json
import uuid
from datetime import datetime
import asyncio

from scanner.core import SecurityScanner
from reports.generator import ReportGenerator
from scanner.ai_analyzer import AIAnalyzer

app = FastAPI(title="AI-Powered Security Scanner", version="1.0.0")

class ScanRequest(BaseModel):
    target: HttpUrl
    scan_type: str = "full"  # full, quick, api-only
    max_depth: int = 3
    auth_token: Optional[str] = None

class RawRequest(BaseModel):
    method: str
    url: str
    headers: Dict[str, str] = {}
    body: Optional[str] = None

@app.post("/api/scan/url")
async def scan_url(request: ScanRequest):
    """Scan a website/API endpoint"""
    scan_id = str(uuid.uuid4())
    scanner = SecurityScanner(target=str(request.target))
    
    # Run scan in background
    results = await scanner.scan_full(
        scan_type=request.scan_type,
        max_depth=request.max_depth,
        auth_token=request.auth_token
    )
    
    # AI Analysis
    ai_analyzer = AIAnalyzer()
    analyzed_results = await ai_analyzer.analyze(results)
    
    # Generate report
    report_gen = ReportGenerator()
    pdf_bytes = await report_gen.generate_pdf(analyzed_results, scan_id)
    json_report = analyzed_results
    
    return {
        "scan_id": scan_id,
        "summary": analyzed_results["summary"],
        "vulnerabilities": analyzed_results["vulnerabilities"],
        "severity_score": analyzed_results["severity_score"],
        "pdf_report": f"/api/report/{scan_id}/pdf",
        "json_report": f"/api/report/{scan_id}/json"
    }

@app.post("/api/scan/raw")
async def scan_raw_request(raw_req: RawRequest):
    """Analyze raw HTTP request/response"""
    scanner = SecurityScanner(target=raw_req.url)
    results = await scanner.analyze_raw_request(raw_req)
    
    ai_analyzer = AIAnalyzer()
    analyzed = await ai_analyzer.analyze(results)
    
    return {
        "target": raw_req.url,
        "analysis": analyzed,
        "recommendations": analyzed.get("fix_recommendations", [])
    }

@app.get("/api/report/{scan_id}/pdf")
async def get_pdf_report(scan_id: str):
    """Download PDF report"""
    report_gen = ReportGenerator()
    pdf_bytes = await report_gen.get_pdf(scan_id)
    return StreamingResponse(
        pdf_bytes, 
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={scan_id}_report.pdf"}
    )

@app.get("/api/report/{scan_id}/json")
async def get_json_report(scan_id: str):
    """Download JSON report"""
    report_gen = ReportGenerator()
    json_data = await report_gen.get_json(scan_id)
    return StreamingResponse(
        json_data,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={scan_id}_report.json"}
    )

@app.get("/")
async def root():
    return {"message": "AI-Powered Security Scanner is running!"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)