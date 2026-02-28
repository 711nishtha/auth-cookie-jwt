# OAuth 2.0 Flow

## Roles (RFC 6749 mapping)

| RFC Role | This System |
|---|---|
| Resource Owner | End user (human with credentials) |
| Client | Frontend Express server (confidential client) |
| Authorization Server | Auth Server `/oauth/*` endpoints |
| Resource Server | Resource API `/api/*` endpoints |

The frontend server is a **confidential client** — it runs server-side and can
securely hold a `client_secret`. This is distinct from a public client (SPA, mobile app)
which cannot hold secrets and must rely solely on PKCE.

## Authorization Code Flow — Step by Step

```
1. CLIENT INITIATES
   User clicks "Login". Express server generates:
     - state: cryptographically random 32 bytes (CSRF protection)
     - code_verifier: random 32 bytes (PKCE)
     - code_challenge: BASE64URL(SHA-256(code_verifier))
   Stores (state, code_verifier) in server-side session (not in browser).
   Redirects browser to:
     GET /oauth/authorize
       ?client_id=frontend
       &redirect_uri=http://localhost:3000/callback
       &response_type=code
       &scope=read:profile
       &state=<random>
       &code_challenge=<hash>
       &code_challenge_method=S256

2. AUTH SERVER VALIDATES REQUEST
   - client_id exists and is registered
   - redirect_uri exactly matches pre-registered URI (no prefix match, no wildcard)
   - response_type=code
   - scope is within allowed scopes for this client
   - Rejects anything invalid with an error (does NOT redirect on client_id/redirect_uri errors
     to avoid open redirect — error shown directly)

3. USER AUTHENTICATES
   Auth Server presents login form (or reuses existing session).
   User enters credentials. Auth Server verifies against DB.

4. USER CONSENTS (if required)
   Consent screen shows requested scope.
   For first-party clients, consent may be pre-approved.

5. AUTH CODE ISSUED
   Auth Server generates auth code:
     - Cryptographically random, 32 bytes
     - Stored in DB with: client_id, user_id, redirect_uri, scope, code_challenge, exp (60s)
   Redirects browser to:
     GET http://localhost:3000/callback
       ?code=<auth_code>
       &state=<echoed_state>

6. CLIENT VALIDATES STATE
   Express server checks: received state == stored state (from step 1 session).
   Mismatch → reject. This prevents CSRF against the callback.

7. CLIENT EXCHANGES CODE FOR TOKENS
   Express server POSTs directly to Auth Server (server-to-server, not via browser):
     POST /oauth/token
       client_id=frontend
       client_secret=<secret>          ← confidential client authentication
       grant_type=authorization_code
       code=<auth_code>
       redirect_uri=http://localhost:3000/callback
       code_verifier=<original_verifier>

8. AUTH SERVER VALIDATES EXCHANGE
   - Retrieve code from DB; verify not expired, not already used
   - Verify client_id + client_secret
   - Verify redirect_uri matches what was used in step 1
   - Verify PKCE: SHA-256(code_verifier) == stored code_challenge
   - Delete code from DB immediately (single-use)
   - Issue access_token (JWT) + refresh_token (opaque)

9. TOKENS DELIVERED
   Tokens returned in JSON response body to the Express server.
   Express server sets them as HttpOnly cookies on the browser response.
   Browser never sees the raw token values in JS context.
```

## Why Implicit Flow Is Avoided

Implicit flow (`response_type=token`) was deprecated in OAuth 2.1 for good reason:
- Access token returned in URL fragment → logged in browser history, server logs, referrer headers
- No client authentication step
- No mechanism to bind token to the specific client that requested it
- PKCE provides the same benefit (public client protection) without token exposure

This system does not implement implicit flow. Any request for `response_type=token` returns 400.

## Critical Validation Points

**redirect_uri — exact match required**
Pre-register URIs in DB. Compare byte-for-byte. Never do prefix matching.
A loose match allows `https://evil.com/callback?foo=https://localhost:3000` to steal codes.
On `client_id` or `redirect_uri` errors, show error directly — do NOT redirect,
as the redirect_uri itself may be malicious.

**state parameter — CSRF on callback**
State binds the authorization request to the callback. Without it, an attacker can
initiate an auth flow and trick a victim's browser into completing it (CSRF).
State must be: unguessable, stored server-side, validated before code exchange.

**auth code — single use, short TTL**
60-second expiry. Deleted from DB on first use. If a code is presented twice,
revoke all tokens issued from that code family (reuse = potential interception).

**PKCE — code injection protection**
Even if an attacker intercepts the auth code (e.g., via malicious redirect), they cannot
exchange it without the `code_verifier` which never leaves the legitimate client.
Required for all clients in this system, including confidential ones (defense in depth).
