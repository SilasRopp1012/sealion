import httpx
import re
import json
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from core.models import TestResult, TestStatus, Vulnerability, Severity

class DatabaseScanner:
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
    def __init__(self):
        self.firebase_pattern = re.compile(r'firebase\.initializeApp\(\s*(\{.+?\})\s*\)', re.DOTALL)
        self.supabase_pattern = re.compile(r'createClient\(\s*["\'](https://[a-zA-Z0-9-]+\.supabase\.co)["\']\s*,\s*["\']([a-zA-Z0-9-._]+)["\']\s*\)', re.DOTALL)
        self.supabase_common_tables = ["users", "profiles", "posts", "products", "orders", "customers", "accounts", "todos"]

    async def run(self, url: str) -> TestResult:
        vulnerabilities = []
        status = TestStatus.PASS

        try:
            async with httpx.AsyncClient(headers={"User-Agent": self.USER_AGENT}, timeout=10.0, follow_redirects=True) as client:
                response = await client.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                script_tags = soup.find_all('script', src=True)
                js_urls = {urljoin(str(response.url), tag['src']) for tag in script_tags}
                
                js_content = ""
                inline_scripts = soup.find_all('script', src=False)
                for script in inline_scripts:
                    js_content += script.string + "\n" if script.string else ""

                for js_url in js_urls:
                    try:
                        js_response = await client.get(js_url)
                        js_content += js_response.text + "\n"
                    except httpx.RequestError:
                        continue

                firebase_configs = await self._extract_firebase_config(js_content)
                supabase_configs = await self._extract_supabase_config(js_content)

                found_vuln = False
                if firebase_configs:
                    for config in firebase_configs:
                        firebase_vulns = await self._probe_firebase(client, config)
                        if firebase_vulns:
                            vulnerabilities.extend(firebase_vulns)
                            found_vuln = True
                
                if supabase_configs:
                    for config in supabase_configs:
                        supabase_vulns = await self._probe_supabase(client, config)
                        if supabase_vulns:
                            vulnerabilities.extend(supabase_vulns)
                            found_vuln = True
                
                if found_vuln:
                    status = TestStatus.FAIL

        except Exception as e:
            return TestResult(status=TestStatus.ERROR, vulnerabilities=[Vulnerability(test_name="Database Scanner", description=f"An error occurred: {str(e)}", recommendation="Check connectivity.", severity=Severity.INFO, evidence=str(e))])
        
        return TestResult(status=status, vulnerabilities=vulnerabilities)

    def _cleanup_json_string(self, s: str) -> str:
        s = s.strip()
        s = re.sub(r',\s*([}\]])', r'\1', s)
        lines = s.split('\n')
        cleaned_lines = []
        for line in lines:
            if '//' in line:
                line = line.split('//')[0]
            cleaned_lines.append(line)
        s = '\n'.join(cleaned_lines)
        # Attempt to wrap unquoted keys with double quotes
        s = re.sub(r'([{,]\s*)(\w+)(\s*:)', r'\1"\2"\3', s)
        return s

    async def _extract_firebase_config(self, js_content: str) -> list[dict]:
        configs = []
        matches = self.firebase_pattern.findall(js_content)
        for match in matches:
            try:
                json_string = self._cleanup_json_string(match.strip())
                config = json.loads(json_string)
                if config.get("apiKey") and (config.get("projectId") or config.get("databaseURL")):
                    if "projectId" not in config and "databaseURL" in config:
                        # Extract project ID from databaseURL if it exists
                        match_pid = re.search(r'https://(.*?)\.firebaseio\.com', config["databaseURL"])
                        if match_pid:
                            config["projectId"] = match_pid.group(1)
                    if config.get("projectId"):
                        configs.append(config)
            except json.JSONDecodeError:
                continue
        return configs

    async def _extract_supabase_config(self, js_content: str) -> list[dict]:
        configs = []
        matches = self.supabase_pattern.findall(js_content)
        for match in matches:
            if len(match) == 2 and 'public-anon-key' in match[1]:
                configs.append({"url": match[0], "anon_key": match[1]})
        return configs

    async def _probe_firebase(self, client: httpx.AsyncClient, config: dict) -> list[Vulnerability]:
        vulnerabilities = []
        project_id = config.get("projectId")
        storage_bucket = config.get("storageBucket")

        if not project_id:
            return []

        db_url = f"https://{project_id}.firebaseio.com/.json"
        try:
            response = await client.get(db_url, params={'auth': 'null'}, timeout=5)
            if response.status_code == 200 and response.text != "null" and response.text:
                vulnerabilities.append(Vulnerability(test_name="Firebase Realtime DB Exposed", description=f"The Firebase Realtime Database at {db_url} is publicly readable.", recommendation="Implement database rules to restrict unauthorized access.", severity=Severity.CRITICAL, evidence={"url": db_url, "response_preview": response.text[:200]}))
        except httpx.RequestError:
            pass

        firestore_url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/"
        try:
            response = await client.get(firestore_url, timeout=5)
            if response.status_code == 200 and "documents" in response.text:
                 vulnerabilities.append(Vulnerability(test_name="Firebase Firestore Exposed", description=f"Firestore for project '{project_id}' is publicly accessible.", recommendation="Review and enforce Firestore security rules.", severity=Severity.CRITICAL, evidence={"url": firestore_url, "response_preview": response.text[:200]}))
        except httpx.RequestError:
            pass

        if storage_bucket:
            storage_url = f"https://firebasestorage.googleapis.com/v0/b/{storage_bucket}/o"
            try:
                response = await client.get(storage_url, timeout=5)
                if response.status_code == 200 and "items" in response.json():
                    items = response.json().get("items", [])
                    filenames = [item.get("name") for item in items[:5]]
                    vulnerabilities.append(Vulnerability(test_name="Firebase Storage Bucket Exposed", description=f"Storage bucket '{storage_bucket}' is publicly listable.", recommendation="Adjust Storage security rules to prevent public listing.", severity=Severity.HIGH, evidence={"url": storage_url, "exposed_files_preview": filenames}))
            except (httpx.RequestError, json.JSONDecodeError):
                pass

        return vulnerabilities

    async def _probe_supabase(self, client: httpx.AsyncClient, config: dict) -> list[Vulnerability]:
        vulnerabilities = []
        base_url = config.get("url")
        anon_key = config.get("anon_key")
        headers = {
            "apikey": anon_key,
            "Authorization": f"Bearer {anon_key}"
        }
        
        # 1. Probe Supabase REST API (PostgREST)
        open_tables = []
        for table in self.supabase_common_tables:
            try:
                rest_url = f"{base_url}/rest/v1/{table}?select=*"
                response = await client.get(rest_url, headers=headers, params={'limit': 1}, timeout=5)
                if response.status_code == 200:
                    # Check if it returns a list (even an empty one), which indicates the table exists and is readable
                    if isinstance(response.json(), list):
                        open_tables.append(table)
            except (httpx.RequestError, json.JSONDecodeError):
                continue
        
        if open_tables:
            vulnerabilities.append(Vulnerability(
                test_name="Supabase Table Exposed via REST",
                description=f"One or more Supabase tables are publicly readable without Row Level Security (RLS).",
                recommendation="Enable Row Level Security on all public-facing tables and define policies to restrict access.",
                severity=Severity.CRITICAL,
                evidence={"url": base_url, "exposed_tables": open_tables}
            ))

        # 2. Probe Supabase GraphQL API
        graphql_url = f"{base_url}/graphql/v1"
        # A simple introspection query to check if the endpoint is responsive and doesn't require auth
        graphql_query = {"query": "{ __schema { types { name } } }"}
        try:
            response = await client.post(graphql_url, headers=headers, json=graphql_query, timeout=5)
            if response.status_code == 200 and "data" in response.json():
                # Check if the response actually contains schema information
                if response.json().get("data", {}).get("__schema"):
                    vulnerabilities.append(Vulnerability(
                        test_name="Supabase GraphQL API Exposed",
                        description="The Supabase GraphQL endpoint is enabled and accessible with the public anon key.",
                        recommendation="If GraphQL is not needed, disable it. If it is, ensure all tables have appropriate RLS policies, as GraphQL respects them.",
                        severity=Severity.HIGH,
                        evidence={"url": graphql_url, "message": "GraphQL introspection query was successful."}
                    ))
        except (httpx.RequestError, json.JSONDecodeError):
            pass

        return vulnerabilities 