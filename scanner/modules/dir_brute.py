import requests
from urllib.parse import urljoin
from scanner.models import Finding
from typing import List

# Small built-in wordlist as requested
WORDLIST = [
    "admin",
    "login",
    "dashboard",
    "config.json",
    ".git/config",
    "robots.txt",
    "api",
    "backup.zip",
    "test"
]

def run(url: str, session: requests.Session) -> List[Finding]:
    findings = []
    
    for word in WORDLIST:
        test_url = urljoin(url, word) if url.endswith('/') else f"{url}/{word}"
        try:
            # We don't want to follow redirects for directory brute forcing to accurately catch 200s or 403s
            response = session.get(test_url, timeout=3, allow_redirects=False)
            
            if response.status_code == 200:
                severity = "Medium" if "config" in word or "git" in word or "backup" in word else "Info"
                vuln_type = "Exposed File/Directory" if severity != "Info" else "Directory Discovered"
                
                findings.append(Finding(
                    severity=severity,
                    vuln_type=vuln_type,
                    path=test_url,
                    description=f"Found accessible path '{test_url}' with status 200 OK.",
                    remediation="Restrict access to sensitive directories and files using appropriate server configurations." if severity != "Info" else "Routine discovery, no action needed unless sensitive."
                ))
            elif response.status_code == 403:
                 # It exists but we are forbidden
                 findings.append(Finding(
                    severity="Info",
                    vuln_type="Forbidden Directory Discovered",
                    path=test_url,
                    description=f"Directory '{test_url}' exists but access is forbidden (403).",
                    remediation="Ensure no sensitive information is leaked."
                ))

        except requests.exceptions.RequestException:
            continue
            
    return findings
