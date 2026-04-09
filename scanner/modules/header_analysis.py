import requests
from scanner.models import Finding
from typing import List

def run(url: str, session: requests.Session) -> List[Finding]:
    findings = []
    try:
        response = session.get(url, timeout=5)
        headers = response.headers
        
        # Check standard security headers
        if 'Content-Security-Policy' not in headers:
            findings.append(Finding(
                severity="Medium",
                vuln_type="Missing Security Header",
                path=url,
                description="Content-Security-Policy (CSP) header is missing, leaving the application vulnerable to cross-site scripting (XSS).",
                remediation="Implement a strong CSP policy to restrict the sources from which content can be loaded."
            ))
            
        if 'Strict-Transport-Security' not in headers and url.startswith('https'):
            findings.append(Finding(
                severity="Medium",
                vuln_type="Missing Security Header",
                path=url,
                description="Strict-Transport-Security (HSTS) header is missing. Users could be vulnerable to Man-In-The-Middle attacks.",
                remediation="Ensure that the HSTS header is sent with a long max-age directive."
            ))
            
        if 'X-Frame-Options' not in headers:
            findings.append(Finding(
                severity="Low",
                vuln_type="Missing Security Header",
                path=url,
                description="X-Frame-Options header is missing. The site may be vulnerable to Clickjacking.",
                remediation="Set the X-Frame-Options header to DENY or SAMEORIGIN."
            ))
            
        if 'X-Content-Type-Options' not in headers:
            findings.append(Finding(
                severity="Low",
                vuln_type="Missing Security Header",
                path=url,
                description="X-Content-Type-Options header is missing. Browsers may perform MIME sniffing.",
                remediation="Set the X-Content-Type-Options header to nosniff."
            ))
            
    except requests.exceptions.RequestException:
        pass # Handle or log error
        
    return findings
