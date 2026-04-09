import requests
from urllib.parse import urlparse
from scanner.models import Finding
from typing import List

def run(url: str, session: requests.Session) -> List[Finding]:
    findings = []
    try:
        domain = urlparse(url).netloc
        if not domain:
            return findings
            
        # Strip port if present
        if ':' in domain:
            domain = domain.split(':')[0]
            
        # Optional: stripping www. to get base domain for broader search
        if domain.startswith('www.'):
            domain = domain[4:]
            
        # Use crt.sh API for fast passive subdomain enumeration
        crt_url = f"https://crt.sh/?q=%25.{domain}&output=json"
        
        response = session.get(crt_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            for entry in data:
                name_value = entry.get('name_value', '')
                # Handle multiple domains in one cert
                for sub in name_value.split('\n'):
                    if sub.endswith(domain) and sub != domain and not sub.startswith('*'):
                         subdomains.add(sub)
                         
            if subdomains:
                findings.append(Finding(
                    severity="Info",
                    vuln_type="Subdomain Enumeration",
                    path=domain,
                    description=f"Discovered {len(subdomains)} subdomains via Certificate Transparency logs (crt.sh).",
                    remediation="Ensure all exposed subdomains are intended to be public and appropriately secured."
                ))
                # For a real tool, we might actually scan these subdomains, but we'll just log them.
                
    except Exception as e:
        # Catch JSONDecodeError, RequestException
        print(f"Subdomain enumeration error: {e}")
        pass
        
    return findings
