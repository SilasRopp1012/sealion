from pydantic import BaseModel, HttpUrl
from typing import Dict, Any, Optional, List
from enum import Enum

class TestStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    NOT_TESTED = "not_tested"

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Vulnerability(BaseModel):
    test_name: str
    severity: Severity
    description: str
    evidence: Optional[Any] = None
    recommendation: str

class TestResult(BaseModel):
    status: TestStatus
    details: Dict[str, Any] = {}
    vulnerabilities: List[Vulnerability] = []

class LoginCredentials(BaseModel):
    login_url: str
    username_field: str
    password_field: str
    username: str
    password: str
    extra_fields: Optional[Dict[str, str]] = None # For things like the "Login" button name

class AuthDetails(BaseModel):
    # The user will provide the name and value of their session cookie
    cookie_name: str
    cookie_value: str
    # The domain the cookie is for (e.g., ".example.com")
    cookie_domain: str

class ScanRequest(BaseModel):
    url: HttpUrl
    # --- The Production-Ready Auth Model ---
    authentication: Optional[AuthDetails] = None

class ScanResponse(BaseModel):
    url: str
    scan_id: str
    timestamp: str
    results: Dict[str, TestResult] 