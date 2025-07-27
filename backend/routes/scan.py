from fastapi import APIRouter, HTTPException
from core.models import (
    ScanRequest, ScanResponse, TestResult, TestStatus, Vulnerability, Severity
)
from engine.scan_engine import ScanEngine
from engine.security_tests.headers import SecurityHeadersTest
from engine.security_tests.secret_scanner import SecretScanner
from engine.security_tests.api_analyzer import ApiAnalyzer
from engine.security_tests.database_scanner import DatabaseScanner
import logging

router = APIRouter()
scan_engine = ScanEngine()

@router.post("/scan", response_model=ScanResponse)
async def run_security_scan(request: ScanRequest):
    try:
        result = await scan_engine.run_all(request)
        return result
    except Exception as e:
        logging.error(f"Scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e)) 