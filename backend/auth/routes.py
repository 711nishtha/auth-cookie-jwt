from collections import defaultdict
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from jose import JWTError
from sqlalchemy.orm import Session

from auth.hashing import hash_password, needs_rehash, verify_password
from auth.models import RefreshToken, User
from auth.security import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    hash_refresh_token,
    refresh_token_expiry,
)
from db.database import get_db
from schemas.user import TokenResponse, UserOut, UserRegister, UserLogin

router = APIRouter(prefix="/auth", tags=["auth"])

# ---------------------------------------------------------------------------
# Naive in-process rate limiter — replace with Redis sliding window in prod.
# Tracks failed login attempts per IP. Not distributed; won't survive restarts.
# ---------------------------------------------------------------------------
_login_attempts: dict[str, list[datetime]] = defaultdict(list)
_MAX_ATTEMPTS = 5
_WINDOW_SECONDS = 900  # 15 minutes


def _check_rate_limit(ip: str) -> None:
    now = datetime.now(timezone.utc)
    # Purge attempts outside the window
    _login_attempts[ip] = [
        t for t in _login_attempts[ip]
        if (now - t).total_seconds() < _WINDOW_SECONDS
    ]
    if len(_login_attempts[ip]) >= _MAX_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": str(_WINDOW_SECONDS)},
        )


def _record_failed_attempt(ip: str) -> None:
    _login_attempts[ip].append(datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Cookie helpers — all auth cookies share these security properties
# ---------------------------------------------------------------------------
_COOKIE_KWARGS = {
    "httponly": True,    # JS cannot read — blocks XSS token theft
    "secure": False,     # Set to True in production with HTTPS
    "samesite": "lax",   # Blocks cross-site POST (CSRF). Lax not Strict: Strict
                         # breaks OAuth redirects (top-level GET from IdP).
}


def _set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    response.set_cookie(
        "access_token",
        access_token,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",          # Send to all endpoints (required for /auth/me etc.)
        **_COOKIE_KWARGS,
    )
    response.set_cookie(
        "refresh_token",
        refresh_token,
        max_age=7 * 24 * 3600,
        path="/auth",      # Send only to /auth/* endpoints (refresh, logout)
        **_COOKIE_KWARGS,
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/auth")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserRegister, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == payload.email).first():
        # Return 400 not 409 — don't confirm whether an email is registered
        # (user enumeration via status code). Timing is similar either way
        # because hash_password is always called below... except here we raise early.
        # Tradeoff accepted: full timing parity would require dummy hashing.
        raise HTTPException(status_code=400, detail="Registration failed")

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------
@router.post("/login")
def login(
    payload: UserLogin,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    user = db.query(User).filter(User.email == payload.email).first()

    # Always run verify_password even if user not found — prevents timing-based
    # user enumeration. Argon2 verify takes ~100ms regardless of outcome.
    dummy_hash = "$argon2id$v=19$m=65536,t=3,p=2$dummysaltdummysalt$dummyhashvalue"
    password_ok = verify_password(payload.password, user.hashed_password if user else dummy_hash)

    if not user or not password_ok or not user.is_active:
        _record_failed_attempt(client_ip)
        # Single generic error — don't reveal whether email exists or password was wrong
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Opportunistic rehash: if argon2 parameters were upgraded, rehash on successful login
    if user and needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(payload.password)
        db.commit()

    raw_refresh, refresh_hash = create_refresh_token()
    db_token = RefreshToken(
        user_id=user.id,
        token_hash=refresh_hash,
        expires_at=refresh_token_expiry(),
    )
    db.add(db_token)
    db.commit()

    access_token = create_access_token(user.id, user.email)
    _set_auth_cookies(response, access_token, raw_refresh)

    # Return minimal info — tokens are in cookies, not the body
    return {"message": "Logged in", "user_id": user.id}


# ---------------------------------------------------------------------------
# Refresh — rotate refresh token on every use
# ---------------------------------------------------------------------------
@router.post("/refresh")
def refresh(
    response: Response,
    db: Session = Depends(get_db),
    refresh_token: Annotated[str | None, Cookie()] = None,
):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")

    token_hash = hash_refresh_token(refresh_token)
    db_token = db.query(RefreshToken).filter(
        RefreshToken.token_hash == token_hash
    ).first()

    if not db_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # Reuse detection: if this token was already rotated (revoked=True), someone is
    # replaying an old token. Revoke ALL tokens for this user immediately.
    if db_token.revoked:
        db.query(RefreshToken).filter(RefreshToken.user_id == db_token.user_id).update(
            {"revoked": True}
        )
        db.commit()
        _clear_auth_cookies(response)
        return JSONResponse(
            status_code=401,
            content={"detail": "Token reuse detected. All sessions revoked."}
        )

    now = datetime.now(timezone.utc)
    if db_token.expires_at.replace(tzinfo=timezone.utc) < now:
        db_token.revoked = True
        db.commit()
        _clear_auth_cookies(response)
        return JSONResponse(
            status_code=401,
            content={"detail": "Refresh token expired"}
        )

    user = db.query(User).filter(User.id == db_token.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User inactive")

    # Rotate: revoke old token, issue new one
    db_token.revoked = True

    raw_new, new_hash = create_refresh_token()
    new_db_token = RefreshToken(
        user_id=user.id,
        token_hash=new_hash,
        expires_at=refresh_token_expiry(),
        replaced_by_id=None,  # would link to new token id post-commit in full impl
    )
    db.add(new_db_token)
    db.commit()

    new_access = create_access_token(user.id, user.email)
    _set_auth_cookies(response, new_access, raw_new)

    return {"message": "Tokens refreshed"}


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------
@router.post("/logout")
def logout(
    response: Response,
    db: Session = Depends(get_db),
    refresh_token: Annotated[str | None, Cookie()] = None,
):
    if refresh_token:
        token_hash = hash_refresh_token(refresh_token)
        db_token = db.query(RefreshToken).filter(
            RefreshToken.token_hash == token_hash
        ).first()
        if db_token:
            db_token.revoked = True
            db.commit()

    _clear_auth_cookies(response)
    return {"message": "Logged out"}


# ---------------------------------------------------------------------------
# Current user dependency — reused by protected routes
# ---------------------------------------------------------------------------
def get_current_user(
    db: Session = Depends(get_db),
    access_token: Annotated[str | None, Cookie()] = None,
) -> User:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not access_token:
        raise credentials_error
    try:
        payload = decode_access_token(access_token)
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise credentials_error

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise credentials_error
    return user


# ---------------------------------------------------------------------------
# Protected route — demonstrates token validation
# ---------------------------------------------------------------------------
@router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    """Read-your-own-profile. Scope check would live here in a fuller system."""
    return current_user
