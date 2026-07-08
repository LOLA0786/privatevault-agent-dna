from fastapi import Depends

from agent_dna.auth.middleware import get_current_identity
from .models import TenantContext

async def get_tenant_context(identity=Depends(get_current_identity)):

    return TenantContext(
        tenant_id=identity.tenant_id,
        organization_id=identity.organization_id,
        project_id=identity.project_id,
    )
