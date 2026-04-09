import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from scanner.models import Finding
from typing import List

def run(url: str, session: requests.Session) -> List[Finding]:
    findings = []
    
    # Common SQLi error patterns
    error_patterns = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "pg::syntaxerror:"
    ]
    
    payloads = ["'", "''", "`", "')", "\";", "%%"]
    
    try:
        response = session.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            form_url = urljoin(url, action) if action else url
            
            inputs = form.find_all('input')
            
            for payload in payloads:
                data = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name:
                        data[name] = payload
                
                if method == 'post':
                    test_resp = session.post(form_url, data=data, timeout=5)
                else:
                    test_resp = session.get(form_url, params=data, timeout=5)
                
                resp_text = test_resp.text.lower()
                
                if any(error in resp_text for error in error_patterns):
                    findings.append(Finding(
                        severity="Critical",
                        vuln_type="SQL Injection",
                        path=form_url,
                        description="Potential SQL Injection detected based on database error response.",
                        remediation="Use parameterized queries or prepared statements. Do not concatenate user input into SQL strings."
                    ))
                    break # Stop testing this form if vulnerable
                    
    except requests.exceptions.RequestException:
        pass
        
    return findings
