from uuid import uuid4
from datetime import datetime
from core.models import (
    ScanRequest, ScanResponse, TestResult, TestStatus, Vulnerability
)
from engine.security_tests.headers import SecurityHeadersTest
from engine.security_tests.secret_scanner import SecretScanner
from engine.security_tests.api_analyzer import ApiAnalyzer
from engine.security_tests.database_scanner import DatabaseScanner
import asyncio

class ScanEngine:
    def __init__(self):
        self.headers_test = SecurityHeadersTest()
        self.secret_scanner = SecretScanner()
        self.api_analyzer = ApiAnalyzer()
        self.database_scanner = DatabaseScanner()

    async def run_all(self, request: ScanRequest) -> ScanResponse:
        """
        Main entry point for running all security scans
        """
        url = str(request.url)
        
        # Run security tests in parallel for better performance
        headers_result, secrets_result, api_result, db_result = await asyncio.gather(
            self.headers_test.run(url),
            self.secret_scanner.run(url),
            self.api_analyzer.run(url),
            self.database_scanner.run(url)
        )
        
        # Compile all results
        results = {
            "Security Headers": headers_result,
            "Secret Scanner": secrets_result,
            "API Security": api_result,
            "Database Security": db_result,
            "Authentication Tests": TestResult(
                status=TestStatus.NOT_TESTED,
                vulnerabilities=[]
            ),
            "Infrastructure Tests": TestResult(
                status=TestStatus.NOT_TESTED,
                vulnerabilities=[]
            )
        }
        
        return ScanResponse(
            url=url,
            scan_id=str(uuid4()),
            timestamp=datetime.utcnow().isoformat(),
            results=results
        )
