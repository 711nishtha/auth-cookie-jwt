# Auth Design

## Session vs JWT Decision

**Chosen: JWT access tokens + opaque refresh tokens**

| Concern | Session Cookie | JWT |
|---|---|---|
| Revocation | Instant (delete session) | Delayed (wait for expiry) |
| Scalability | Requires shared store | Stateless, scales freely |
| DB hit per request | Yes | No |
| Token size | Small (session ID) | Larger (~300–500 bytes) |

Decision: JWT access tokens for stateless API validation. Short 15-min TTL compensates
for inability to instantly revoke. Refresh tokens are opaque and stored (hashed) in DB,
enabling real revocation of long-lived sessions.

This is the dominant industry pattern for a reason — it trades perfect revocation for
horizontal scalability. A pure session approach would require sticky sessions or a
Redis cluster. Neither is appropriate for a minimal demo.

## Access + Refresh Token Strategy

**Access Token**
- JWT, RS256 signed (asymmetric — API only needs public key)
- Payload: `sub` (user_id), `iss`, `aud`, `exp`, `iat`, `scope`
- TTL: 15 minutes
- Delivered as HttpOnly cookie: `access_token`
- Never logged. Never returned in response body to browser.

**Refresh Token**
- Cryptographically random (32 bytes, url-safe base64) — opaque, not a JWT
- Stored as `SHA-256(token)` in DB with user_id, issued_at, expires_at, revoked flag
- TTL: 7 days
- Delivered as HttpOnly cookie: `refresh_token`
- One active refresh token per session. Rotation on use (old token revoked, new issued).

**Why asymmetric signing (RS256)?**
Resource API can verify tokens using only the public key. Private key never leaves
the Auth Server. If the API is compromised, the attacker cannot forge tokens.

## Token Expiry Approach

- Access: hard expiry at 15 min. No silent extension.
- Refresh: 7-day sliding window. On each use, old token is revoked and a new one issued.
- Auth codes (OAuth): 60 seconds, single-use, deleted on first use.
- On any suspicious reuse of a revoked refresh token, the entire token family is revoked
  (refresh token rotation with reuse detection).

## Token Revocation Approach

- **Access tokens**: Cannot be revoked before expiry. Acceptable at 15-min TTL.
  For immediate revocation needs (e.g., account compromise), reduce TTL further
  or add a short-lived blocklist (Redis, not implemented here).
- **Refresh tokens**: Stored in DB. Revoked by setting `revoked = true`.
  Logout revokes the current refresh token. Password change revokes all user's tokens.
- **Reuse detection**: If a refresh token that was already rotated is presented again,
  it indicates potential theft. All tokens for that user are immediately revoked.

## Cookie Strategy

```
Set-Cookie: access_token=<jwt>; HttpOnly; Secure; SameSite=Lax; Path=/api; Max-Age=900
Set-Cookie: refresh_token=<opaque>; HttpOnly; Secure; SameSite=Lax; Path=/auth/refresh; Max-Age=604800
```

**HttpOnly**: Prevents JS access. XSS cannot read the token even with full script execution.

**Secure**: Cookie only sent over HTTPS. Enforced at cookie level, not just policy.

**SameSite=Lax**: Blocks cross-site POST requests (CSRF mitigation). Top-level GET navigations
still send the cookie (needed for OAuth redirect). `Strict` would break OAuth redirect flows.

**Scoped paths**: `access_token` is only sent to `/api/*`. `refresh_token` only to `/auth/refresh`.
This minimizes cookie exposure surface — the refresh token is never sent to the resource API.

## Why Not LocalStorage

LocalStorage is readable by any JS on the page. A single XSS vulnerability — in your code,
a dependency, an injected ad, a browser extension — exposes the token with zero additional effort.

HttpOnly cookies are not accessible to JS at all. XSS can still trigger requests
(the cookie is sent automatically), but cannot exfiltrate the token value itself.
The attacker loses the ability to use the token outside the victim's browser/session.

The residual risk (XSS-driven requests) is mitigated by CSRF protection (SameSite + CSRF tokens).
LocalStorage offers no equivalent defense layer.

## Rate Limiting

Not fully implemented, but the shape it would take:
- `/auth/login`: 5 attempts per IP per 15 min, then 429 + exponential backoff hint.
- `/auth/refresh`: 10 requests per token per minute.
- `/oauth/token`: 20 requests per client_id per minute.

Implementation: sliding window counter in Redis, or a simple in-memory dict for the demo.
The key insight is that rate limiting on auth endpoints is a first-line defense against
credential stuffing and token brute-force — it must be at the network/proxy layer too,
not just application-level.
