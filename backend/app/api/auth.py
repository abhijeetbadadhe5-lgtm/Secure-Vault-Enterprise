
import jwt

from fastapi import Depends
from fastapi.security import (
    HTTPBearer,
    HTTPAuthorizationCredentials
)

from backend.app.security.tokens import (
    create_access_token,
    decode_access_token,
    get_token_secret
)

from backend.app.database.user_repository import get_user_by_id


from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.app.database.user_repository import authenticate_user


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1)


@router.post("/login")
def login(request: LoginRequest):

    user = authenticate_user(
        request.username,
        request.password
    )

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return {
        "message": "LOGIN SUCCESSFUL",
        "user_id": user["id"],
        "username": user["username"]
    }


# Reads "Authorization: Bearer <token>"
bearer_scheme = HTTPBearer(auto_error=False)


@router.post("/token")
def issue_token(request: LoginRequest):
    """Verify credentials and issue a short-lived token."""

    # Do not issue tokens without a configured signing key.
    try:
        get_token_secret()
    except RuntimeError:
        raise HTTPException(
            status_code=503,
            detail="Token service is not configured"
        )

    user = authenticate_user(
        request.username,
        request.password
    )

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    access_token = create_access_token(user["id"])

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 900
    }


@router.get("/me")
def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    )
):
    """Return the identity from a valid Bearer token."""

    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )

    try:
        user_id = decode_access_token(
            credentials.credentials
        )

    except RuntimeError:
        raise HTTPException(
            status_code=503,
            detail="Token service is not configured"
        )

    except (jwt.InvalidTokenError, ValueError, OverflowError):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user = get_user_by_id(user_id)

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="User account not found",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return {
        "message": "PROTECTED ROUTE ACCESS GRANTED",
        "user_id": user["id"],
        "username": user["username"]
    }
