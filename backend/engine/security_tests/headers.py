from typing import Dict, List
import httpx
from core.models import TestResult, TestStatus, Vulnerability, Severity

class SecurityHeadersTest:
    # A common user agent to avoid being served different content
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"

    # Only the truly critical headers
    CRITICAL_HEADERS = {
        "Strict-Transport-Security": {
            "recommendation": "Add 'Strict-Transport-Security' header to enforce HTTPS",
            "severity": Severity.HIGH,
            "example": "max-age=31536000; includeSubDomains",
            "details": "Critical for preventing SSL stripping attacks"
        },
        "Content-Security-Policy": {
            "recommendation": "Consider adding 'Content-Security-Policy' header if not using alternative protections",
            "severity": Severity.MEDIUM,
            "example": "default-src 'self'",
            "details": "Important for XSS prevention, but may be handled via meta tags or CDN"
        },
        "X-Frame-Options": {
            "recommendation": "Add 'X-Frame-Options' header to prevent clickjacking",
            "severity": Severity.HIGH,
            "example": "DENY or SAMEORIGIN",
            "details": "Prevents clickjacking attacks"
        }
    }

    # Actually useful optional headers
    RECOMMENDED_HEADERS = {
        "X-Content-Type-Options": {
            "recommendation": "Consider adding 'X-Content-Type-Options' header",
            "severity": Severity.MEDIUM,
            "example": "nosniff",
            "details": "Prevents MIME type sniffing"
        }
    }

    # Headers that might be useful in specific situations
    SITUATIONAL_HEADERS = {
        "Cross-Origin-Opener-Policy": {
            "recommendation": "Only needed if using SharedArrayBuffer or requiring cross-window isolation",
            "severity": Severity.INFO,
            "example": "same-origin",
            "details": "Specific use cases only - not generally required"
        },
        "Cross-Origin-Embedder-Policy": {
            "recommendation": "Only needed if using SharedArrayBuffer or requiring cross-window isolation",
            "severity": Severity.INFO,
            "example": "require-corp",
            "details": "Specific use cases only - not generally required"
        }
    }

    def _evaluate_security_posture(self, headers: Dict[str, str]) -> bool:
        """Evaluate overall security posture considering alternative protections"""
        # Check if using Cloudflare protection
        using_cloudflare = any(k.startswith('cf-') for k in headers.keys())
        
        # Check for strong CORS configuration
        has_strong_cors = all(headers.get(h) for h in [
            'cross-origin-embedder-policy',
            'cross-origin-opener-policy',
            'cross-origin-resource-policy'
        ])
        
        # Check for strong permissions policy
        has_strong_permissions = 'permissions-policy' in headers and all(
            p in headers['permissions-policy'].lower() 
            for p in ['camera=()', 'microphone=()', 'geolocation=()']
        )
        
        return using_cloudflare and has_strong_cors and has_strong_permissions

    async def run(self, url: str) -> TestResult:
        try:
            # Add headers to the client request to mimic a real browser
            async with httpx.AsyncClient(headers={"User-Agent": self.USER_AGENT}, follow_redirects=True) as client:
                response = await client.get(url)
                headers = {k.lower(): v for k, v in response.headers.items()}
                
                vulnerabilities = []
                recommendations = []
                
                # Check critical headers (these affect the overall status)
                critical_missing = []
                for header, info in self.CRITICAL_HEADERS.items():
                    if header.lower() not in headers:
                        critical_missing.append(header)
                        vulnerabilities.append(
                            Vulnerability(
                                test_name="Missing Critical Header",
                                severity=info["severity"],
                                description=f"Missing critical header: {header}",
                                recommendation=info["recommendation"],
                                evidence={
                                    "details": info["details"],
                                    "example": info["example"]
                                }
                            )
                        )

                # Check recommended headers (these don't affect overall status)
                for header, info in self.RECOMMENDED_HEADERS.items():
                    if header.lower() not in headers:
                        recommendations.append(
                            Vulnerability(
                                test_name="Missing Recommended Header",
                                severity=info["severity"],
                                description=f"Optional header missing: {header}",
                                recommendation=info["recommendation"],
                                evidence={
                                    "details": info["details"],
                                    "example": info["example"]
                                }
                            )
                        )

                # Check legacy headers (these are just informational)
                legacy_notes = []
                for header, info in self.SITUATIONAL_HEADERS.items():
                    if header.lower() not in headers:
                        legacy_notes.append(
                            Vulnerability(
                                test_name="Missing Situational Header",
                                severity=info["severity"],
                                description=f"Situational header missing: {header}",
                                recommendation=info["recommendation"],
                                evidence={
                                    "details": info["details"],
                                    "example": info["example"]
                                }
                            )
                        )

                # Determine status based on critical headers only
                status = TestStatus.PASS if not critical_missing else TestStatus.FAIL

                return TestResult(
                    status=status,
                    details={
                        "headers_present": dict(headers),
                        "critical_headers_missing": len(critical_missing),
                        "total_vulnerabilities": len(vulnerabilities),
                        "recommendations": len(recommendations),
                        "legacy_considerations": len(legacy_notes)
                    },
                    vulnerabilities=vulnerabilities + recommendations + legacy_notes
                )

        except Exception as e:
            return TestResult(
                status=TestStatus.ERROR,
                details={"error": str(e)},
                vulnerabilities=[
                    Vulnerability(
                        test_name="Header Scan Error",
                        severity=Severity.INFO,
                        description=f"Error checking headers: {str(e)}",
                        recommendation="Ensure the URL is accessible"
                    )
                ]
            ) 