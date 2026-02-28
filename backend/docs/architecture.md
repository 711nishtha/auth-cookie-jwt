# Architecture Overview

## Components

```
[ Browser ]
    │  HTTPS only. Stores tokens in HttpOnly cookies — not accessible to JS.
    │
    ├──► [ Auth Server ]  :8000/auth
    │        Owns identity: registration, login, token issuance, refresh, revoke.
    │        Issues short-lived access tokens and long-lived refresh tokens.
    │        Has direct DB access. No token validation delegated elsewhere.
    │
    ├──► [ Resource API ]  :8000/api
    │        Stateless. Validates access tokens on every request.
    │        Never issues tokens. Never touches user passwords.
    │        Reads public key to verify JWT signatures.
    │
    └──► [ Frontend Server ]  :3000
             Express. Serves HTML. Proxies auth requests. No auth logic of its own.
             Acts as a confidential OAuth client (holds client_secret server-side).

[ Database ]  (SQLite for demo, Postgres-ready schema)
    Stores: users (hashed passwords), refresh tokens (hashed), auth codes (short-lived).
    Auth Server is the only component with DB credentials.
    Resource API has no DB access — enforced by design, not just policy.
```

## Trust Boundaries

```
UNTRUSTED                          TRUSTED
─────────────────────────────────────────────────────
Browser / User Agent               Auth Server process
Network (assume TLS, not implicit) Resource API process
Frontend JS context                Database (local, not exposed)
OAuth Client redirect URIs
```

- The browser is never trusted with raw tokens or secrets.
- The frontend server (Express) is a trusted confidential client — it holds `client_secret`
  and exchanges auth codes on behalf of the user.
- The Resource API trusts only the JWT signature + claims. It does not call back to Auth Server
  on every request (no introspection by default). Tradeoff: revoked access tokens remain
  valid until expiry. Mitigated by keeping access token TTL short (15 min).

## Login Data Flow

```
1. User submits credentials → Frontend Server
2. Frontend Server POSTs to Auth Server /auth/token (password grant, internal)
3. Auth Server verifies password hash (argon2)
4. Auth Server issues:
     - access_token  (JWT, 15 min, signed RS256)
     - refresh_token (opaque random, 7 days, stored hashed in DB)
5. Both tokens set as HttpOnly Secure SameSite=Lax cookies by Auth Server
6. Browser holds cookies — JS cannot read them
7. Subsequent API requests send cookies automatically; API validates JWT
```

## Token Validation Flow (Resource API)

```
1. Extract access_token from cookie (not Authorization header — cookie is harder to steal via XSS)
2. Verify JWT signature using Auth Server's public key (RS256)
3. Check exp, iat, iss, aud claims
4. Extract user_id and scope from payload
5. Authorize against required scope for the route
6. If expired → 401; client uses refresh flow
```

## OAuth 2.0 Authorization Code Flow (external clients)

```
1. Client redirects user to /oauth/authorize with client_id, redirect_uri, state, code_challenge
2. Auth Server authenticates user, shows consent
3. Auth Server issues short-lived auth code (60s TTL), redirects to client
4. Client POSTs code + code_verifier to /oauth/token
5. Auth Server validates code, verifier, issues access + refresh tokens
6. Tokens returned in response body to confidential server-side client
   (not set as cookies here — client manages storage on their server)
```

## Why Logical Separation Matters

- **Auth Server isolation**: A compromised Resource API cannot read the user DB or
  forge tokens. Private signing key never leaves the Auth Server process.
- **No shared DB credentials**: If the API were compromised, the attacker cannot
  directly enumerate users or harvest password hashes.
- **Frontend as thin proxy**: No secrets in browser JS. `client_secret` stays on the
  Express server. Frontend is treated as an untrusted surface.
- **Stateless API validation**: Horizontal scaling without shared session state.
  Cost: access token revocation requires short TTL as compensation.
