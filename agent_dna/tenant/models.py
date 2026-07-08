from dataclasses import dataclass

@dataclass(slots=True)
class TenantContext:
    tenant_id: str
    organization_id: str
    project_id: str
