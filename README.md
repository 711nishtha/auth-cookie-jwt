# Auth System

A minimal, security-conscious authentication and OAuth 2.0 implementation built from first principles.

This project intentionally avoids third-party auth providers to understand core identity and security mechanics.

---

## Purpose

Demonstrate working knowledge of:
- Identity vs authentication vs authorization
- Session/cookie mechanics vs JWT tradeoffs
- Refresh token rotation and reuse detection
- OAuth 2.0 Authorization Code Flow with PKCE
- Trust boundary design between components
- Common attack surfaces and concrete mitigations

This is **not production-ready**. It is intentionally minimal and designed to be readable.

---

## Architecture

```
Browser (untrusted)
  │
  ├─► Auth Server  :8000          FastAPI. Owns identity: issues, rotates, revokes tokens.
  │     /auth/*    — login, logout, refresh, register
  │     /oauth/*   — authorization code flow, token exchange, userinfo
  │
  ├─► Resource API :8000/api      Stateless. Validates JWTs. No DB access.
  │
  └─► Frontend     :3000          Express. Thin proxy. Holds client_secret server-side.

Database (SQLite/demo, Postgres-compatible schema)
  — Users, hashed passwords, refresh tokens (hashed), auth codes (short-lived)
  — Only the Auth Server process has DB credentials
```

**Trust boundary**: the Resource API trusts only the JWT signature and claims — it never
calls back to the Auth Server per request. The browser is never trusted with raw token values.

---

## Token Strategy

| Token | Type | TTL | Storage | Notes |
|---|---|---|---|---|
| Access | RS256 JWT | 15 min | HttpOnly cookie (`/api` path) | Stateless validation; no revocation |
| Refresh | Opaque random | 7 days | HttpOnly cookie (`/auth/refresh` path) | Stored hashed in DB; rotated on use |
| Auth code | Opaque random | 60 sec | DB only | Single-use; reuse triggers session wipeout |

**Signing**: RS256 (asymmetric). The Resource API verifies tokens using only the public key —
the private key never leaves the Auth Server process.

**Rotation**: Every refresh call invalidates the old token and issues a new one. If a
rotated-out token is presented again, all sessions for that user are immediately revoked
(reuse = likely theft).

**Why not LocalStorage**: HttpOnly cookies are completely inaccessible to JavaScript.
A successful XSS attack cannot read or exfiltrate the token value. LocalStorage has no
equivalent protection.

---

## OAuth 2.0 Flow

Authorization Code Flow with PKCE (RFC 6749 + RFC 7636).

```
1. Client generates state (CSRF token) + code_verifier + code_challenge (S256)
2. Browser → GET /oauth/authorize?client_id=...&code_challenge=...&state=...
3. Auth Server validates client_id and redirect_uri (exact match, no wildcards)
4. User authenticates + approves consent
5. Auth Server issues auth code (60s TTL), redirects to redirect_uri?code=...&state=...
6. Client validates state matches what it stored (CSRF check)
7. Client → POST /oauth/token with code + code_verifier + client_secret
8. Auth Server validates: code not used, not expired, client matches,
   redirect_uri matches, PKCE verifier hashes to stored challenge
9. Auth Server issues access + refresh tokens
```

Implicit flow (`response_type=token`) is not implemented. Tokens in URL fragments
appear in browser history, server logs, and referrer headers.

---

## Security Decisions

**Passwords**: argon2id with 64MB memory cost and 3 iterations — above OWASP minimums,
resistant to GPU parallelism. Constant-time verification. Dummy hash checked on unknown
email to prevent timing-based user enumeration.

**Cookies**: `HttpOnly` (no JS access) + `Secure` (HTTPS only) + `SameSite=Lax`
(blocks cross-site POST, preserves OAuth redirect compatibility). Scoped by `path` —
the refresh token is never sent to the Resource API.

**redirect_uri**: Byte-for-byte exact match against a pre-registered list.
On client_id or redirect_uri errors, the server returns a direct HTTP error — it does
not redirect, which would hand control to an untrusted URI.

**Auth code reuse**: Codes are marked `used` rather than deleted. Presenting a used code
is treated as evidence of interception — all sessions for the user are revoked immediately.

**PKCE on all clients**: Required even for confidential clients. Defense in depth — an
intercepted code is useless without the `code_verifier`.

**Rate limiting**: In-process sliding window on `/auth/login` — 5 attempts per IP per
15 minutes. Adequate for demo; see production notes below.

---

## Known Limitations

- **Access token revocation**: Revoked/deactivated users retain access until the 15-min
  token expires. A `jti` blocklist in Redis would close this window.
- **Rate limiter**: In-process only. Ineffective across multiple server instances.
  A crashed process resets all counters.
- **Ephemeral signing keys**: RS256 keys are generated at startup. All issued tokens
  are invalidated on restart. Production requires persistent key management with rotation.
- **No email verification**: User registration accepts any email without confirmation.
- **SQLite**: Not safe for concurrent writes at scale. Schema is Postgres-compatible.
- **Consent bypass**: Pre-approved first-party consent is simulated, not policy-enforced.
- **No scope enforcement on Resource API**: Scopes are embedded in the JWT but not
  checked against route-level requirements (the hook is present, not wired up).

---

## What Would Change in Production

| Area | Demo | Production |
|---|---|---|
| Key management | Ephemeral RSA at startup | KMS (AWS/GCP), persisted PEM, versioned `kid` |
| Database | SQLite | Postgres with connection pooling |
| Migrations | `create_all()` | Alembic |
| Rate limiting | In-process dict | Redis sliding window, also at WAF/proxy layer |
| Token revocation | TTL only | `jti` blocklist in Redis for access tokens |
| Secrets | Hardcoded defaults | Environment variables, secret manager |
| HTTPS | Assumed | TLS termination at load balancer; `Strict-Transport-Security` header |
| Logging | None | Structured logs; scrub tokens, passwords, PII before emission |
| Client secrets | Stored as SHA-256 | bcrypt/argon2 — client secrets are user-chosen strings |
| Email verification | None | Token-based confirmation flow before account activation |
| Account recovery | None | Time-limited signed recovery tokens, separate from auth flow |

---

## Running

```bash
# Install
pip install -r requirements.txt

# Start Auth Server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# API docs (development only — disable in prod)
open http://localhost:8000/docs
```

---

## Project Structure

```
auth/
  models.py     — SQLAlchemy models: User, RefreshToken
  hashing.py    — argon2id password hashing
  security.py   — JWT creation/validation, refresh token generation
  routes.py     — /auth/* endpoints: register, login, refresh, logout, /me
  oauth.py      — /oauth/* endpoints: authorize, consent, token, userinfo

db/
  database.py   — SQLAlchemy engine, session, Base

schemas/
  user.py       — Pydantic request/response models

docs/
  architecture.md   — Component diagram, trust boundaries, data flows
  auth_design.md    — Session vs JWT, token strategy, cookie decisions
  oauth_flow.md     — Authorization Code Flow, PKCE, critical validation points
  threat_model.md   — Attack surface: mitigations and residual risk

main.py           — FastAPI app, middleware, router registration
requirements.txt
```

---

## Installation & Running

### Backend (Auth Server)

```bash
cd auth-system

# Create virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
# → Auth Server running at http://localhost:8000
# → API docs at http://localhost:8000/docs
```

### Frontend

```bash
cd auth-system/frontend

# Install dependencies (Node.js 18+ required for --watch)
npm install

# Development
npm run dev
# → Frontend running at http://localhost:3000

# Production
node server.js
```

### Environment Variables (Frontend)

| Variable | Default | Notes |
|---|---|---|
| `SESSION_SECRET` | Random on startup | Set a stable secret in prod — random restarts all sessions |
| `OAUTH_CLIENT_ID` | `frontend` | Must match a registered client in the DB |
| `OAUTH_CLIENT_SECRET` | `demo-secret-change-in-prod` | **Change this** |
| `NODE_ENV` | — | Set to `production` to enable Secure cookie flag |

### Register the Demo OAuth Client

The OAuth client must be pre-registered in the DB before the flow will work.
Add a startup fixture or use the `/docs` Swagger UI to `POST /auth/register` a user,
then insert a row directly into `oauth_clients` via SQLite:

```bash
sqlite3 auth.db "
INSERT INTO oauth_clients
  (client_id, client_secret_hash, redirect_uris, allowed_scopes, is_active)
VALUES (
  'frontend',
  '$(python3 -c \"import hashlib; print(hashlib.sha256(b'demo-secret-change-in-prod').hexdigest())\")' ,
  'http://localhost:3000/oauth-callback',
  'read:profile',
  1
);"
```

### Quick Test Sequence

```
1. Open http://localhost:3000
2. Register a new account
3. Log in with password → redirected to /dashboard
4. Log out
5. Click "Login via OAuth" → Auth Server consent page → back to /dashboard
```
