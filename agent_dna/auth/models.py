from dataclasses import dataclass
from typing import List

@dataclass
class Identity:
    subject: str
    tenant_id: str
    organization_id: str
    project_id: str
    role: str
    scopes: List[str]
