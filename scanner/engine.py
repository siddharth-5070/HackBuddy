import requests
import time
from scanner.models import ScanResult, Finding
from scanner.modules import header_analysis, xss, sqli, dir_brute, subdomain
from scanner.reporting import generate_pdf_report
from scanner.vpn_manager import VPNManager

class ScannerEngine:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        # Add a custom user agent
        self.session.headers.update({"User-Agent": "HackBuddy-Sentinel/1.0"})
        self.result = ScanResult(target_url=target_url, status="idle", progress=0, findings=[])

    def run_scan(self):
        self.result.status = "running"
        self.result.progress = 2
        
        # Initialize VPN routing to mask the scanner IP
        print("[+] Initializing VPN / Proxy Anonymization...")
        vpn = VPNManager()
        vpn.apply_to_session(self.session)
        self.result.progress = 5
        
        try:
            # Module 1: Subdomain Enumeration
            print(f"[+] Running Subdomain Enumeration Module on {self.target_url}...")
            subs = subdomain.run(self.target_url, self.session)
            self.result.findings.extend(subs)
            self.result.progress = 20
            
            # Module 2: Header Analysis
            print(f"[+] Running Header Analysis Module on {self.target_url}...")
            headers = header_analysis.run(self.target_url, self.session)
            self.result.findings.extend(headers)
            self.result.progress = 40
            
            # Module 3: XSS Detection
            print(f"[+] Running XSS Module on {self.target_url}...")
            xss_findings = xss.run(self.target_url, self.session)
            self.result.findings.extend(xss_findings)
            self.result.progress = 60
            
            # Module 4: SQLi Detection
            print(f"[+] Running SQLi Module on {self.target_url}...")
            sqli_findings = sqli.run(self.target_url, self.session)
            self.result.findings.extend(sqli_findings)
            self.result.progress = 80
            
            # Module 5: Directory Brute Forcing
            print(f"[+] Running Directory Brute Forcing Module on {self.target_url}...")
            dirs = dir_brute.run(self.target_url, self.session)
            self.result.findings.extend(dirs)
            self.result.progress = 75

            # Advance Module: Port Scanner (Nmap alternative)
            print(f"[+] Running Port Scanner Module on {self.target_url}...")
            from scanner.modules.port_scanner import PortScanner
            port_results = PortScanner(self.target_url).run()
            self.result.findings.extend([Finding(**f) for f in port_results])
            self.result.progress = 85

            # Advance Module: API Fuzzer (Burp alternative)
            print(f"[+] Running Advanced Fuzzer on {self.target_url}...")
            from scanner.modules.fuzzer import APIFuzzer
            fuzz_results = APIFuzzer(self.session, self.target_url).run()
            self.result.findings.extend([Finding(**f) for f in fuzz_results])
            self.result.progress = 90

            # Advance Module: Hash Cracker (Password Cracking tool)
            print(f"[+] Running Hash/Password Cracker on {self.target_url}...")
            from scanner.modules.hash_cracker import HashCracker
            hash_results = HashCracker(self.session, self.target_url).run()
            self.result.findings.extend([Finding(**f) for f in hash_results])
            self.result.progress = 95
            
            print("[+] Scan completed. Generating PDF.")
            generate_pdf_report(self.result, "scan_report.pdf")
            
        except Exception as e:
            print(f"Error during scan: {e}")
            self.result.status = "error"
            return
            
        self.result.progress = 100
        self.result.status = "completed"

    def get_status(self) -> dict:
        return self.result.to_dict()
