import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from scanner.models import Finding
from typing import List

def run(url: str, session: requests.Session) -> List[Finding]:
    findings = []
    try:
        # A very basic crawler to find inputs
        response = session.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        forms = soup.find_all('form')
        
        test_payload = "<script>alert('XSS')</script>"
        
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            
            form_url = urljoin(url, action) if action else url
            
            inputs = form.find_all('input')
            data = {}
            for input_tag in inputs:
                name = input_tag.get('name')
                if name:
                    data[name] = test_payload
                    
            if method == 'post':
                test_resp = session.post(form_url, data=data, timeout=5)
            else:
                test_resp = session.get(form_url, params=data, timeout=5)
                
            if test_payload in test_resp.text:
                findings.append(Finding(
                    severity="High",
                    vuln_type="Cross-Site Scripting (XSS)",
                    path=form_url,
                    description=f"Reflected XSS payload found on form submission to {form_url}.",
                    remediation="Sanitize user input before rendering it in the DOM and use Context-Aware Encoding."
                ))
                break # Just record one per page for simplicity
                
    except requests.exceptions.RequestException:
        pass
        
    return findings
