import secrets

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import settings

bearer = HTTPBearer(auto_error=False)


async def require_api_key(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> None:
    if not settings.api_keys:
        return

    valid = False
    if credentials is not None:
        token_bytes = credentials.credentials.encode("utf-8")
        for key in settings.api_keys:
            valid |= secrets.compare_digest(token_bytes, key.encode("utf-8"))

    if not valid:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "invalid_api_key",
                "message": "Missing or invalid API key",
                "type": "authentication_error",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )
