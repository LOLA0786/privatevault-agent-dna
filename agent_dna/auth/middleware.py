from fastapi import Header, HTTPException

from .apikey import verify_api_key
from .jwt import verify_token
from .models import Identity

async def get_current_identity(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
):

    if x_api_key:

        data = verify_api_key(x_api_key)

        if not data:
            raise HTTPException(401, "Invalid API Key")

        return Identity(
            subject=data["subject"],
            tenant_id=data["tenant_id"],
            organization_id=data["organization_id"],
            project_id=data["project_id"],
            role=data["role"],
            scopes=["*"],
        )

    if authorization:

        if not authorization.startswith("Bearer "):
            raise HTTPException(401, "Invalid Authorization Header")

        token = authorization.split(" ", 1)[1]

        try:
            payload = verify_token(token)
        except Exception:
            raise HTTPException(401, "Invalid JWT")

        return Identity(
            subject=payload["subject"],
            tenant_id=payload["tenant_id"],
            organization_id=payload["organization_id"],
            project_id=payload["project_id"],
            role=payload["role"],
            scopes=payload.get("scopes", []),
        )

    raise HTTPException(401, "Authentication Required")
