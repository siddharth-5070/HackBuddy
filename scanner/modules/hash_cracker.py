import hashlib
from urllib.parse import urljoin
import requests

class HashCracker:
    def __init__(self, session, target_url):
        self.session = session
        self.target_url = target_url
        self.common_passwords = ["admin", "password", "123456", "root", "toor", "qwerty", "iloveyou"]
        # Dummy hashes we might "discover" in a source code leak scenario
        self.discovered_hashes = []

    def crack_basic_auth(self):
        findings = []
        admin_endpoint = urljoin(self.target_url, "/admin")
        
        try:
            # First check if it's protected by basic auth
            resp = self.session.get(admin_endpoint, timeout=3)
            if resp.status_code in [401, 403]:
                # Try simple dictionary brute force
                for pwd in self.common_passwords:
                    auth_resp = self.session.get(admin_endpoint, auth=('admin', pwd), timeout=2)
                    if auth_resp.status_code == 200:
                        findings.append({
                            "vuln_type": "Weak Default Credentials (Brute Force)",
                            "severity": "Critical",
                            "path": admin_endpoint,
                            "description": f"Successfully bypassed authentication. Dictionary brute force cracked credentials: admin:{pwd}",
                            "remediation": "Change default passwords instantly. Implement account lockout and use strong password policies."
                        })
                        break
        except Exception:
            pass
            
        return findings

    def run(self):
        findings = []
        
        # 1. Attempt basic web login brute-forcing
        findings.extend(self.crack_basic_auth())
        
        # 2. Emulate an offline hash crack if hashes were found during crawl
        # (This just returns static for now, representing the capability)
        admin_hash = "21232f297a57a5a743894a0e4a801fc3" # md5 for "admin"
        
        for pwd in self.common_passwords:
            if hashlib.md5(pwd.encode()).hexdigest() == admin_hash:
                findings.append({
                    "vuln_type": "Offline Hash Cracking",
                    "severity": "High",
                    "path": "/internal/config.yml (simulated leak)",
                    "description": f"Found an MD5 hash '{admin_hash}' that was successfully cracked using a standard dictionary. Password is '{pwd}'.",
                    "remediation": "Never store passwords in MD5. Use bcrypt, Argon2, or PBKDF2 with unique salts."
                })
                break
                
        return findings
