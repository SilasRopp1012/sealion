from typing import Dict, List
import httpx
import re
import math
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from core.models import TestResult, TestStatus, Vulnerability, Severity

# Only flag secrets that are actually dangerous
CRITICAL_SECRETS = {
    "AWS Live Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Live Secret Key": r"[0-9a-zA-Z+/]{40}",
    "GitHub Personal Token": r"ghp_[0-9a-zA-Z]{36}",
    "Stripe Live Secret": r"sk_live_[0-9a-zA-Z]{24}",
    "Slack Bot Token": r"xoxb-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}",
    "Discord Bot Token": r"[MN][a-zA-Z0-9]{23}\\.[\\w-]{6}\\.[\\w-]{27}",
    "Private Key": r"-----BEGIN PRIVATE KEY-----",
    "Database Connection": r"(mongodb|postgresql|mysql)://[^:]+:[^@]+@",
}

# Ignore these completely
IGNORE_PATTERNS = [
    r"dpl_[A-Za-z0-9]{24,}",  # Vercel deployment keys
    r"sk_test_[A-Za-z0-9]{24,}",  # Stripe test keys
    r"pk_test_[A-Za-z0-9]{24,}",  # Stripe test publishable
    r"ghs_[0-9a-zA-Z]{36}",  # GitHub app tokens (usually public)
    r"xoxp-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}",  # Slack user tokens
    r"example",
    r"demo",
    r"test",
    r"placeholder"
]

class SecretScanner:
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"

    def __init__(self):
        try:
            with open("engine/security_tests/secrets_patterns.json", "r") as f:
                patterns_data = json.load(f)
                # Flatten the nested dictionary of patterns
                self.patterns = {}
                for category_patterns in patterns_data.values():
                    if isinstance(category_patterns, dict):
                        self.patterns.update(category_patterns)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading secret patterns: {e}")
            self.patterns = {}
        
        try:
            with open("engine/security_tests/ignore_patterns.json", "r") as f:
                self.ignore_patterns = json.load(f).get("patterns", [])
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading ignore patterns: {e}")
            self.ignore_patterns = []

        try:
            with open("engine/security_tests/context_ignore.json", "r") as f:
                self.context_ignore_keywords = json.load(f).get("keywords", [])
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading context ignore list: {e}")
            self.context_ignore_keywords = []

        self.config_paths = [
            "/.env", "/config.js", "/env.js", "/firebaseConfig.json",
            "/.env.local", "/.env.development", "/.env.production"
        ]

    def _clean_line(self, line: str) -> str:
        line = re.sub(r'//.*$', '', line)
        line = re.sub(r'/\*.*?\*/', '', line)
        line = line.strip()
        try:
            line = bytes(line, 'utf-8').decode('unicode_escape')
        except:
            pass
        return line

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log2(p) for p in prob if p > 0])
        return entropy

    def _has_high_entropy(self, text: str, threshold: float = 4.5) -> bool:
        """Check if string has high entropy and meets complexity requirements"""
        MAX_SECRET_LENGTH = 256 
        
        if len(text) < 20 or len(text) > MAX_SECRET_LENGTH:
            return False
            
        # Must have mixed character classes
        has_upper = bool(re.search(r'[A-Z]', text))
        has_lower = bool(re.search(r'[a-z]', text))
        has_digit = bool(re.search(r'[0-9]', text))
        if not (has_upper and has_lower and has_digit):
            return False

        # NEW: Reject strings with long non-random sequences (like in test data)
        # Rejects 10+ consecutive letters or 8+ consecutive digits
        if re.search(r'[a-zA-Z]{10,}|[0-9]{8,}', text):
            return False

        entropy = self._calculate_entropy(text)
        return entropy > threshold

    async def scan_content(self, content: str, url: str) -> List[Dict]:
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Contextual check: if the line contains ignored keywords, skip it entirely
            if any(keyword.lower() in line.lower() for keyword in self.context_ignore_keywords):
                continue

            clean_line = self._clean_line(line)
            if not clean_line or len(clean_line) < 20:
                continue

            found_pattern_on_line = False
            for pattern_name, regex in self.patterns.items():
                try:
                    matches = re.finditer(regex, clean_line)
                    for match in matches:
                        secret_value = match.group(0)

                        # Check if the matched secret is on our ignore list
                        is_ignored = False
                        for ignore_regex in self.ignore_patterns:
                            if re.fullmatch(ignore_regex, secret_value):
                                is_ignored = True
                                break
                        if is_ignored:
                            continue

                        # --- NEW: Added Complexity Check for AWS Keys ---
                        if pattern_name == "AWS Secret Key":
                            has_upper = bool(re.search(r'[A-Z]', secret_value))
                            has_lower = bool(re.search(r'[a-z]', secret_value))
                            has_digit = bool(re.search(r'[0-9]', secret_value))
                            has_special = bool(re.search(r'[/+]', secret_value))
                            
                            # A real key is complex. If it doesn't have at least 3 of these
                            # character types, it's almost certainly a false positive.
                            if sum([has_upper, has_lower, has_digit, has_special]) < 3:
                                continue # Skip this match

                        findings.append({
                            'type': pattern_name, 'line': i,
                            'value': secret_value[:4] + '*' * (len(secret_value) - 8) + secret_value[-4:],
                            'url': url, 'confidence': 'high',
                            'evidence': {
                                'matched_pattern': pattern_name,
                                'context': clean_line[:80]
                            }
                        })
                        found_pattern_on_line = True
                except re.error:
                    continue

            # If no specific pattern was found, tokenize the line and check each token for high entropy
            if not found_pattern_on_line:
                # Contextual check for high entropy strings as well
                if any(keyword.lower() in clean_line.lower() for keyword in self.context_ignore_keywords):
                    continue
                tokens = re.findall(r'[\w\-\.]{20,256}', clean_line)
                for token in tokens:
                    # Check if the token is on our ignore list
                    is_ignored = False
                    for ignore_regex in self.ignore_patterns:
                        if re.fullmatch(ignore_regex, token):
                            is_ignored = True
                            break
                    if is_ignored:
                        continue
                    
                    if self._has_high_entropy(token):
                        # Final check to avoid flagging things that are clearly not secrets
                        if 'color-scheme' in clean_line or 'fontFamily' in clean_line:
                            continue
                        
                        context_text = '\n'.join(lines[max(0, i-1):i+2])
                        if re.search(r'(?i)(api[_-]?key|token|secret|password|auth)', context_text):
                            findings.append({
                                'type': 'High Entropy String', 'line': i,
                                'value': token[:4] + '*' * (len(token) - 8) + token[-4:],
                                'url': url, 'confidence': 'medium',
                                'evidence': {
                                    'entropy': self._calculate_entropy(token),
                                    'context': line[:80]
                                }
                            })
        return findings

    async def run(self, url: str) -> TestResult:
        try:
            all_findings = []
            files_scanned = {'js_files': 0, 'inline_scripts': 0, 'config_files': 0}
            
            async with httpx.AsyncClient(headers={"User-Agent": self.USER_AGENT}, follow_redirects=True) as client:
                response = await client.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for i, script in enumerate(soup.find_all('script')):
                    if script.string:
                        files_scanned['inline_scripts'] += 1
                        findings = await self.scan_content(script.string, f"{url}#inline-script-{i+1}")
                        all_findings.extend(findings)

                js_files = set()
                for script in soup.find_all('script', src=True):
                    src = script.get('src')
                    if src:
                        if not src.startswith(('http://', 'https://')):
                            src = urljoin(str(response.url), src)
                        if '.js' in src and '.map' not in src:
                            js_files.add(src)

                for js_file in js_files:
                    try:
                        files_scanned['js_files'] += 1
                        js_response = await client.get(js_file)
                        findings = await self.scan_content(js_response.text, js_file)
                        all_findings.extend(findings)
                    except Exception as e:
                        print(f"Error scanning JS file {js_file}: {str(e)}")

                base_url = str(response.url)
                for config_path in self.config_paths:
                    try:
                        config_url = urljoin(base_url, config_path)
                        config_response = await client.get(config_url)
                        if config_response.status_code == 200:
                            files_scanned['config_files'] += 1
                            findings = await self.scan_content(config_response.text, config_url)
                            for finding in findings:
                                finding['confidence'] = 'high'
                                finding['type'] = f"Exposed Config File: {finding['type']}"
                            all_findings.extend(findings)
                    except Exception:
                        continue  # Expected 404s for most config files

                unique_vulns = {}
                for finding in all_findings:
                    key = (finding['url'], finding['line'], finding.get('value'))
                    if key not in unique_vulns:
                        unique_vulns[key] = Vulnerability(
                            test_name=finding['type'],
                            severity=Severity.HIGH if finding.get('confidence') == 'high' else Severity.MEDIUM,
                            description=f"Leaked secret found in {finding['url']}",
                            evidence=finding,
                            recommendation="Remove this secret and rotate it immediately. Store secrets in environment variables or a secure secret management system."
                        )
                
                vulnerabilities = list(unique_vulns.values())

                return TestResult(
                    status=TestStatus.FAIL if vulnerabilities else TestStatus.PASS,
                    details={
                        "files_scanned": files_scanned,
                        "total_findings": len(vulnerabilities),
                        "high_confidence_findings": len([v for v in vulnerabilities if v.severity == "high"])
                    },
                    vulnerabilities=vulnerabilities
                )

        except Exception as e:
            return TestResult(
                status=TestStatus.ERROR,
                details={"error": str(e)},
                vulnerabilities=[
                    Vulnerability(
                        test_name="Secret Scan Error",
                        severity=Severity.INFO, description="Error during secret scanning",
                        evidence={"error": str(e)}, recommendation="Ensure the URL is accessible"
                    )
                ]
            ) 