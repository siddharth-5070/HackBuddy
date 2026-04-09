import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

class PortScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.hostname = self._extract_hostname(target_url)
        # Top common ports for a rapid scan
        self.ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080, 8443]

    def _extract_hostname(self, url):
        parsed = urlparse(url)
        return parsed.hostname or url

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((self.hostname, port))
            sock.close()
            return port if result == 0 else None
        except Exception:
            return None

    def run(self):
        findings = []
        if not self.hostname:
            return findings

        open_ports = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(self.scan_port, self.ports_to_scan)
            open_ports = [p for p in results if p is not None]

        if open_ports:
            open_ports_str = ", ".join(map(str, open_ports))
            findings.append({
                "vuln_type": "Open Ports Discovered",
                "severity": "Info",
                "path": f"{self.hostname}",
                "description": f"The following ports are open and exposed to the internet: {open_ports_str}.",
                "remediation": "Ensure only necessary external ports (e.g., 80, 443) are accessible. Use firewalls to restrict access to management ports like SSH (22), RDP (3389), or databases (3306)."
            })
            
            # Highlight dangerously exposed ports
            dangerous_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 3306: "MySQL", 3389: "RDP"}
            for p in open_ports:
                if p in dangerous_ports:
                    findings.append({
                        "vuln_type": f"Exposed Management/Data Service ({dangerous_ports[p]})",
                        "severity": "High",
                        "path": f"{self.hostname}:{p}",
                        "description": f"The service {dangerous_ports[p]} is exposed on port {p}. This increases the attack surface for brute-force and exploits.",
                        "remediation": "Restrict access to trusted IP addresses only or enforce VPN usage."
                    })

        return findings
