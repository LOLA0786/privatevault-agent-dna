import os

JWT_SECRET = os.getenv("PV_JWT_SECRET", "CHANGE_ME_IN_PRODUCTION")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("PV_JWT_EXPIRE", "1440"))

API_KEYS = {
    os.getenv("PV_API_KEY", "pv-local-key"): {
        "tenant_id": "default",
        "organization_id": "default",
        "project_id": "default",
        "role": "owner",
        "subject": "local-user"
    }
}
