from dataclasses import dataclass, asdict
from typing import List, Optional

@dataclass
class Finding:
    severity: str # "Critical", "High", "Medium", "Low", "Info"
    vuln_type: str
    path: str
    description: str
    remediation: str

    def to_dict(self):
        return asdict(self)

@dataclass
class ScanResult:
    target_url: str
    status: str # "idle", "running", "completed", "error"
    progress: int
    findings: List[Finding]

    def to_dict(self):
        return {
            "url": self.target_url,
            "status": self.status,
            "progress": self.progress,
            "findings": [f.to_dict() for f in self.findings]
        }
