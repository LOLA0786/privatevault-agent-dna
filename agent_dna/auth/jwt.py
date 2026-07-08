from datetime import datetime, timedelta, timezone
import jwt

from .config import JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRE_MINUTES

def create_access_token(identity: dict):
    payload = identity.copy()

    payload["exp"] = datetime.now(timezone.utc) + timedelta(
        minutes=JWT_EXPIRE_MINUTES
    )

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str):

    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=[JWT_ALGORITHM],
    )
