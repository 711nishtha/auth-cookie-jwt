# Threat Model

## 1. Token Leakage

**Description**
Access or refresh token exposed to an unauthorized party — via logs, error responses,
network interception, or compromised storage.

**Mitigations**
- Tokens stored in HttpOnly cookies, never in JS-accessible storage or URL parameters.
- HTTPS enforced; Secure cookie flag prevents transmission over HTTP.
- Tokens never appear in server logs (log sanitization required in prod).
- Access token TTL is 15 min — leaked token has limited utility window.
- Refresh token stored hashed (SHA-256) in DB; raw value never persisted.

**Residual Risk**
A network-level attacker who can break TLS (compromised CA, MITM on corporate proxy)
could still intercept cookies. Certificate pinning is out of scope for a web demo.

---

## 2. CSRF (Cross-Site Request Forgery)

**Description**
Attacker crafts a malicious page that causes the victim's browser to make an
authenticated request to the API (e.g., transfer funds, change email).
Cookies are sent automatically — the attacker doesn't need the token value.

**Mitigations**
- `SameSite=Lax` on all auth cookies — blocks cross-site POST requests entirely.
- For state-changing endpoints, a `Double Submit Cookie` CSRF token pattern is used
  as defense in depth (token in cookie + mirrored in request header; JS reads
  a non-HttpOnly CSRF cookie and sends it as a header — works because reading a
  cookie from a different origin is blocked by SOP).
- OAuth `state` parameter prevents CSRF on the authorization callback.

**Residual Risk**
`SameSite=Lax` allows top-level GET navigations to send cookies. Any state-changing
action exposed via GET (a design error) would be vulnerable. All mutations must be POST/PUT/DELETE.

---

## 3. XSS Token Theft

**Description**
Attacker injects malicious JavaScript into the page and attempts to steal auth tokens
to use from a different machine or persist beyond the session.

**Mitigations**
- Tokens in HttpOnly cookies are completely inaccessible to JavaScript — `document.cookie`
  does not return them. XSS cannot read the token value.
- Content-Security-Policy header restricts script sources (inline scripts blocked).
- Input sanitization on all user-controlled output (no raw HTML injection).

**Residual Risk**
XSS can still make authenticated requests from within the victim's browser (the cookie
is sent automatically). This is a weaker attack (session-bound, no exfiltration) but
still a risk. Robust CSP and no `unsafe-inline` is the key remaining control.

---

## 4. Replay Attacks

**Description**
A previously captured valid token or auth code is reused to gain unauthorized access.

**Mitigations**
- Auth codes: single-use (deleted on first exchange), 60-second TTL.
- Auth code reuse detected by checking DB — if already deleted, reject and revoke
  all tokens from that session (indicates interception).
- Refresh tokens: rotated on every use. Old token invalidated immediately.
- Refresh token reuse (presenting a rotated-out token) triggers full session revocation.
- JWT access tokens carry `iat` + `exp`; replaying an expired token fails signature
  verification (exp claim checked).
- `jti` (JWT ID) blocklist is not implemented but would be needed for hard revocation.

**Residual Risk**
A captured access token is valid until expiry (15 min). No per-request nonce binding.
For higher-security contexts, reduce TTL further or implement `jti` blocklist.

---

## 5. Refresh Token Abuse

**Description**
Attacker obtains a refresh token and uses it to generate access tokens indefinitely,
surviving password changes and logout.

**Mitigations**
- Refresh tokens stored hashed; raw value is never in DB — compromise of DB doesn't
  immediately yield usable tokens (attacker must brute-force preimage of SHA-256).
- Token rotation: each refresh invalidates the old token. Legitimate user and attacker
  cannot both hold a valid token after the first use following theft.
- Reuse detection: if the rotated-out token is presented, all tokens for the user
  are revoked immediately (automatic session wipeout).
- Password change revokes all refresh tokens for the user unconditionally.
- Logout revokes the current refresh token.

**Residual Risk**
Between theft and first legitimate use post-theft, the attacker has a valid refresh token.
The rotation + reuse detection window depends on user activity. Silent theft with no
subsequent legitimate use would not be automatically detected until token expiry (7 days).

---

## 6. Open Redirect

**Description**
The OAuth `redirect_uri` parameter is manipulated to redirect the user (and the auth code)
to an attacker-controlled URL.

**Mitigations**
- `redirect_uri` validated against a pre-registered exact-match whitelist. No wildcard,
  no prefix match, no path traversal.
- On `client_id` or `redirect_uri` validation failure, the Auth Server does NOT redirect —
  it returns a direct error page. Redirecting to an untrusted URI to report an error
  about that URI would be self-defeating.
- Query params in registered URIs are compared including param values.

**Residual Risk**
If the client application itself has an open redirect vulnerability (e.g., a `?next=`
parameter that redirects arbitrarily), an attacker could chain: valid `redirect_uri` →
client's open redirect → attacker's site. This is a client-side responsibility outside
the Auth Server's control. Clients must sanitize redirect parameters.
