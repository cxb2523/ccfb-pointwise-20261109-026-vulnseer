from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    """Shared finding structure for all detectors, aligned with vulnseer's report style."""
    rule_id: str
    severity: str
    status: str
    host: str
    evidence: str
    description: str
    bypass_type: Optional[str] = None
