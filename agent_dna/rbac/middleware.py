from fastapi import Depends, HTTPException

from agent_dna.auth.middleware import get_current_identity
from .roles import ROLES

def require_permission(permission: str):

    async def checker(identity=Depends(get_current_identity)):

        permissions = ROLES.get(identity.role, set())

        if permission not in permissions:
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied: {permission}",
            )

        return identity

    return checker
