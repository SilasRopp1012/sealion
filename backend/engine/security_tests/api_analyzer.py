import httpx
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from core.models import TestResult, TestStatus, Vulnerability, Severity

class ApiAnalyzer:
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
    def __init__(self):
        self.api_pattern = re.compile(r'["\'](/api/[^"\']+|/rest/[^"\']+)["\']')
        self.benign_paths = [
            "avatar", "health", "metrics", "swagger", "version", 
            "tracking", "consent", "flags", "config", "profile", "banner",
            "contact", "sales", "form", "chilipiper", "event" # Added new keywords
        ]

    async def run(self, url: str) -> TestResult:
        vulnerabilities = []
        status = TestStatus.PASS
        
        try:
            async with httpx.AsyncClient(headers={"User-Agent": self.USER_AGENT}, follow_redirects=True) as client:
                response = await client.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                script_tags = soup.find_all('script', src=True)
                js_urls = {urljoin(str(response.url), tag['src']) for tag in script_tags}
                
                js_content = ""
                inline_scripts = soup.find_all('script', src=False)
                for script in inline_scripts:
                    js_content += script.string + "\n" if script.string else ""
                
                found_api_routes = set()
                
                # Scan inline content
                matches = self.api_pattern.findall(js_content)
                for match in matches:
                    found_api_routes.add(match)

                # Scan external JS files
                for js_url in js_urls:
                    try:
                        js_response = await client.get(js_url)
                        matches = self.api_pattern.findall(js_response.text)
                        for match in matches:
                            found_api_routes.add(match)
                    except httpx.RequestError:
                        continue
                
                for route in found_api_routes:
                    api_url = urljoin(str(response.url), route)
                    try:
                        api_response = await client.get(api_url)
                        if 200 <= api_response.status_code < 300:
                            # Avoid flagging benign, informational endpoints
                            if "metrics" in route or "swagger" in route:
                                continue
                            status = TestStatus.FAIL
                            vulnerabilities.append(Vulnerability(
                                test_name="Publicly Accessible API Route",
                                description=f"An unauthenticated API endpoint was found: {api_url}",
                                recommendation="Review the endpoint to ensure it does not expose sensitive data. If it does, implement authentication and authorization controls.",
                                severity=Severity.MEDIUM,
                                evidence={"url": api_url, "status_code": api_response.status_code}
                            ))
                    except httpx.RequestError:
                        continue

        except Exception as e:
            return TestResult(
                status=TestStatus.ERROR,
                vulnerabilities=[Vulnerability(
                    test_name="API Analyzer Error",
                    description=f"An error occurred while scanning for API routes: {str(e)}",
                    recommendation="Check connectivity and ensure the target URL is accessible.",
                    severity=Severity.INFO,
                    evidence=str(e)
                )]
            )
        
        return TestResult(status=status, vulnerabilities=vulnerabilities) 