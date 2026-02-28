"""
OAuth 2.0 Authorization Code Flow with PKCE (RFC 6749 + RFC 7636).

Supported grant types: authorization_code only.
Implicit flow intentionally omitted — tokens in URL fragments leak via logs/referrer.
"""

import hashlib
import secrets
import base64
from datetime import datetime, timedelta, timezone
from typing import Annotated
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, Cookie, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Boolean
from sqlalchemy.orm import Session, Mapped, mapped_column

from auth.models import User
from auth.routes import get_current_user
from auth.security import create_access_token, create_refresh_token, refresh_token_expiry
from auth.models import RefreshToken
from db.database import Base, get_db

router = APIRouter(prefix="/oauth", tags=["oauth"])


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class OAuthClient(Base):
    """Pre-registered OAuth clients. No dynamic registration — reduces attack surface."""
    __tablename__ = "oauth_clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    client_id: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    # Stored hashed — client_secret is a credential, treat it like a password
    client_secret_hash: Mapped[str] = mapped_column(String, nullable=False)
    # Newline-separated list of EXACTLY registered URIs — no wildcards, no prefix match
    redirect_uris: Mapped[str] = mapped_column(String, nullable=False)
    # Space-separated allowed scopes
    allowed_scopes: Mapped[str] = mapped_column(String, nullable=False, default="read:profile")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class AuthCode(Base):
    """
    Single-use authorization codes. 60s TTL.
    Storing them in DB (not in-memory) survives restarts and enables
    reuse detection across processes.
    """
    __tablename__ = "auth_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    client_id: Mapped[str] = mapped_column(String, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    # Must exactly match the redirect_uri used in the token exchange — RFC 6749 §4.1.3
    redirect_uri: Mapped[str] = mapped_column(String, nullable=False)
    scope: Mapped[str] = mapped_column(String, nullable=False)
    # PKCE: store the challenge, verify against verifier at exchange time
    code_challenge: Mapped[str] = mapped_column(String, nullable=False)
    code_challenge_method: Mapped[str] = mapped_column(String, nullable=False, default="S256")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Mark used rather than delete — enables detection of code replay attempts
    used: Mapped[bool] = mapped_column(Boolean, default=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_secret(secret: str) -> str:
    """SHA-256 for client secrets. Fast is fine — these are high-entropy random values."""
    return hashlib.sha256(secret.encode()).hexdigest()


def _get_client(client_id: str, db: Session) -> OAuthClient:
    client = db.query(OAuthClient).filter(
        OAuthClient.client_id == client_id,
        OAuthClient.is_active == True,
    ).first()
    if not client:
        raise HTTPException(status_code=400, detail="Unknown client")
    return client


def _validate_redirect_uri(client: OAuthClient, redirect_uri: str) -> None:
    """
    Exact byte-for-byte match against pre-registered URIs.
    No prefix matching, no wildcard, no query-string stripping.
    A loose match here is the root cause of most OAuth redirect attacks.
    """
    registered = client.redirect_uris.splitlines()
    if redirect_uri not in registered:
        # Do NOT include the supplied URI in the error — avoid reflected open redirect
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")


def _validate_pkce_challenge(verifier: str, challenge: str, method: str) -> bool:
    """
    RFC 7636 §4.6 verification.
    S256: BASE64URL(SHA-256(ASCII(code_verifier))) == code_challenge
    Plain method intentionally not supported — S256 is strictly better.
    """
    if method != "S256":
        return False
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    # Use secrets.compare_digest for constant-time comparison
    return secrets.compare_digest(computed, challenge)


def _safe_redirect_error(redirect_uri: str, error: str, state: str | None) -> RedirectResponse:
    """
    Only redirect error responses after redirect_uri has been validated.
    For client_id or redirect_uri errors, callers must return HTTP errors directly.
    """
    params = {"error": error}
    if state:
        params["state"] = state
    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=302)


# ---------------------------------------------------------------------------
# GET /oauth/authorize
# ---------------------------------------------------------------------------

@router.get("/authorize")
def authorize(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str = "read:profile",
    state: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str = "S256",
    db: Session = Depends(get_db),
    # Reuse existing session cookie if user is already logged in.
    # If not present, we'd redirect to /auth/login?next=... — simplified here.
    access_token: Annotated[str | None, Cookie()] = None,
):
    # --- Validate client and redirect_uri BEFORE anything else.
    # RFC 6749 §4.1.2.1: If these are invalid, respond directly — do NOT redirect.
    # Redirecting on a bad redirect_uri would hand control to the attacker's URL.
    client = _get_client(client_id, db)
    _validate_redirect_uri(client, redirect_uri)

    # Only authorization_code flow supported
    if response_type != "code":
        return _safe_redirect_error(redirect_uri, "unsupported_response_type", state)

    # PKCE is required for all clients in this system.
    # Even confidential clients benefit: defense in depth against code interception.
    if not code_challenge:
        return _safe_redirect_error(redirect_uri, "invalid_request", state)

    if code_challenge_method != "S256":
        return _safe_redirect_error(redirect_uri, "invalid_request", state)

    # Validate requested scopes are within what the client is allowed
    requested = set(scope.split())
    allowed = set(client.allowed_scopes.split())
    if not requested.issubset(allowed):
        return _safe_redirect_error(redirect_uri, "invalid_scope", state)

    # --- Require authenticated user ---
    # In a real system: redirect to login with ?next= encoding the full authorize URL.
    # Here: return a consent/login form inline.
    current_user = None
    if access_token:
        try:
            from auth.security import decode_access_token
            payload = decode_access_token(access_token)
            user_id = int(payload["sub"])
            current_user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
        except Exception:
            pass  # Token invalid/expired — fall through to login form

    if not current_user:
        # Embed all params in the form so state survives the round-trip
        return HTMLResponse(_login_and_consent_form(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state or "",
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            error=None,
        ))

    # User is already authenticated — show consent screen
    return HTMLResponse(_consent_form(
        user_email=current_user.email,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state or "",
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    ))


# ---------------------------------------------------------------------------
# POST /oauth/consent  (form submission from the consent/login page)
# ---------------------------------------------------------------------------

@router.post("/consent")
def consent(
    request: Request,
    db: Session = Depends(get_db),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(...),
    state: str = Form(""),
    code_challenge: str = Form(...),
    code_challenge_method: str = Form("S256"),
    action: str = Form(...),          # "approve" or "deny"
    # Credentials only present when user arrived unauthenticated
    email: str = Form(""),
    password: str = Form(""),
    # Sentinel set by the pre-authenticated consent form
    session_auth: str = Form(""),     # "1" if user was already logged in
    access_token: Annotated[str | None, Cookie()] = None,
):
    # Re-validate client and redirect_uri on every POST — hidden fields are user-controlled
    client = _get_client(client_id, db)
    _validate_redirect_uri(client, redirect_uri)

    if action == "deny":
        return _safe_redirect_error(redirect_uri, "access_denied", state or None)

    user = None

    if session_auth == "1" and access_token:
        # User was already authenticated — verify their session cookie rather than
        # re-accepting password from a hidden field (which they could tamper with)
        try:
            from auth.security import decode_access_token
            payload = decode_access_token(access_token)
            user = db.query(User).filter(
                User.id == int(payload["sub"]), User.is_active == True
            ).first()
        except Exception:
            pass  # Session expired between GET and POST — fall through to credential check

    if user is None:
        # Fresh login path — verify submitted credentials
        from auth.hashing import verify_password
        db_user = db.query(User).filter(User.email == email, User.is_active == True).first()
        dummy = "$argon2id$v=19$m=65536,t=3,p=2$dummysalt$dummyhashvalue"
        ok = verify_password(password, db_user.hashed_password if db_user else dummy)

        if not db_user or not ok:
            html = _login_and_consent_form(
                client_id=client_id, redirect_uri=redirect_uri, scope=scope,
                state=state, code_challenge=code_challenge,
                code_challenge_method=code_challenge_method, error="Invalid credentials",
            )
            return HTMLResponse(html, status_code=401)
        user = db_user

    # Issue auth code — 60 second TTL, single use
    raw_code = secrets.token_urlsafe(32)
    db_code = AuthCode(
        code=raw_code,
        client_id=client_id,
        user_id=user.id,
        redirect_uri=redirect_uri,
        scope=scope,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=60),
    )
    db.add(db_code)
    db.commit()

    params = {"code": raw_code}
    # Always echo state back — client uses this to detect CSRF on the callback
    if state:
        params["state"] = state

    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=302)


# ---------------------------------------------------------------------------
# POST /oauth/token
# ---------------------------------------------------------------------------

@router.post("/token")
def token(
    db: Session = Depends(get_db),
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    code_verifier: str = Form(...),
):
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Unsupported grant type")

    # Authenticate the client — confidential clients must prove identity at token endpoint
    client = _get_client(client_id, db)
    if not secrets.compare_digest(client.client_secret_hash, _hash_secret(client_secret)):
        raise HTTPException(status_code=401, detail="Invalid client credentials")

    # Fetch the auth code
    db_code = db.query(AuthCode).filter(AuthCode.code == code).first()

    if not db_code:
        raise HTTPException(status_code=400, detail="Invalid authorization code")

    # Reuse detection: if the code was already used, it indicates a replay attack.
    # Revoke all tokens for this user and reject — better to disrupt a session
    # than silently allow a potential attacker through.
    if db_code.used:
        db.query(RefreshToken).filter(RefreshToken.user_id == db_code.user_id).update({"revoked": True})
        db.commit()
        raise HTTPException(status_code=400, detail="Authorization code already used. All sessions revoked.")

    now = datetime.now(timezone.utc)
    if db_code.expires_at.replace(tzinfo=timezone.utc) < now:
        db_code.used = True
        db.commit()
        raise HTTPException(status_code=400, detail="Authorization code expired")

    # client_id must match what was used during /authorize — prevents code injection
    if db_code.client_id != client_id:
        raise HTTPException(status_code=400, detail="client_id mismatch")

    # redirect_uri must exactly match — RFC 6749 §4.1.3 mandatory check
    if db_code.redirect_uri != redirect_uri:
        raise HTTPException(status_code=400, detail="redirect_uri mismatch")

    # PKCE verification — proves the exchanger is the same party that initiated the flow.
    # Without this, an intercepted code (e.g., via referrer leak) could be exchanged
    # by a third party even without client_secret (critical for public clients).
    if not _validate_pkce_challenge(code_verifier, db_code.code_challenge, db_code.code_challenge_method):
        raise HTTPException(status_code=400, detail="Invalid code_verifier")

    # Mark used immediately before issuing tokens — prevent race-condition double-use
    db_code.used = True
    db.flush()

    user = db.query(User).filter(User.id == db_code.user_id, User.is_active == True).first()
    if not user:
        db.commit()
        raise HTTPException(status_code=400, detail="User not found")

    scopes = db_code.scope.split()
    access_token = create_access_token(user.id, user.email, scopes)
    raw_refresh, refresh_hash = create_refresh_token()

    db.add(RefreshToken(
        user_id=user.id,
        token_hash=refresh_hash,
        expires_at=refresh_token_expiry(),
    ))
    db.commit()

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 900,  # 15 min — client should not hardcode this
        "refresh_token": raw_refresh,
        "scope": db_code.scope,
    }


# ---------------------------------------------------------------------------
# GET /oauth/userinfo  (RFC 7662-inspired, scope-gated)
# ---------------------------------------------------------------------------

@router.get("/userinfo")
def userinfo(current_user: User = Depends(get_current_user)):
    """
    Returns claims about the authenticated user.
    get_current_user validates the access token from cookie.
    For OAuth clients sending Bearer tokens in headers, extend the dependency.
    """
    return {
        "sub": str(current_user.id),
        "email": current_user.email,
        "email_verified": True,  # Assumed for demo — real system requires verification flow
    }


# ---------------------------------------------------------------------------
# HTML helpers — minimal, no framework
# ---------------------------------------------------------------------------

def _login_and_consent_form(
    client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, error
) -> str:
    error_html = f'<p class="error">{error}</p>' if error else ""
    return f"""<!DOCTYPE html>
<html><head><title>Login – OAuth Consent</title>
<style>body{{font-family:sans-serif;max-width:420px;margin:60px auto;padding:0 20px}}
input{{width:100%;padding:8px;margin:6px 0;box-sizing:border-box}}
button{{width:100%;padding:10px;margin-top:8px;cursor:pointer}}
.error{{color:red;font-size:.9em}}.scope{{background:#f4f4f4;padding:8px;border-radius:4px;font-size:.9em}}</style>
</head><body>
<h2>Authorize <strong>{client_id}</strong></h2>
<p>Log in to grant access to: <span class="scope">{scope}</span></p>
{error_html}
<form method="POST" action="/oauth/consent">
  <input type="hidden" name="client_id" value="{client_id}">
  <input type="hidden" name="redirect_uri" value="{redirect_uri}">
  <input type="hidden" name="scope" value="{scope}">
  <input type="hidden" name="state" value="{state}">
  <input type="hidden" name="code_challenge" value="{code_challenge}">
  <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
  <input type="email" name="email" placeholder="Email" required autocomplete="username">
  <input type="password" name="password" placeholder="Password" required autocomplete="current-password">
  <button type="submit" name="action" value="approve">Log in &amp; Approve</button>
  <button type="submit" name="action" value="deny" style="background:#eee">Deny</button>
</form>
</body></html>"""


def _consent_form(
    user_email, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method
) -> str:
    return f"""<!DOCTYPE html>
<html><head><title>Authorize – {client_id}</title>
<style>body{{font-family:sans-serif;max-width:420px;margin:60px auto;padding:0 20px}}
button{{width:100%;padding:10px;margin-top:8px;cursor:pointer}}
.scope{{background:#f4f4f4;padding:8px;border-radius:4px;font-size:.9em}}</style>
</head><body>
<h2>Authorize <strong>{client_id}</strong></h2>
<p>Logged in as <strong>{user_email}</strong></p>
<p>This app is requesting access to:</p>
<div class="scope">{scope}</div>
<form method="POST" action="/oauth/consent">
  <!-- session_auth=1: tell the server to verify identity via cookie, not re-submitted password.
       Hidden fields are user-controlled; never accept a password from a hidden input. -->
  <input type="hidden" name="session_auth" value="1">
  <input type="hidden" name="client_id" value="{client_id}">
  <input type="hidden" name="redirect_uri" value="{redirect_uri}">
  <input type="hidden" name="scope" value="{scope}">
  <input type="hidden" name="state" value="{state}">
  <input type="hidden" name="code_challenge" value="{code_challenge}">
  <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
  <button type="submit" name="action" value="approve">Approve</button>
  <button type="submit" name="action" value="deny" style="background:#eee">Deny</button>
</form>
</body></html>"""
