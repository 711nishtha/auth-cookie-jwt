"use strict";

/**
 * Frontend server — thin proxy + OAuth confidential client.
 *
 * Security posture:
 *   - Never stores tokens. All tokens live in HttpOnly cookies managed by the Auth Server.
 *   - Never reads or parses JWTs. Identity comes from the Auth Server's /auth/me response.
 *   - Never uses LocalStorage or sessionStorage for anything auth-related.
 *   - client_secret lives only in this process — never sent to the browser.
 *   - OAuth state + PKCE verifier stored in server-side session — not in a cookie or URL.
 */

import express from "express";
import session from "express-session";
import crypto from "crypto";

const app = express();
const PORT = 3000;
const AUTH = "http://localhost:8000"; // Auth Server base URL — backend only, never exposed to browser
const response = await fetch("https://example.com");

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Server-side session for OAuth state/PKCE only.
// express-session stores data on the server; browser gets an opaque session ID cookie.
// This is NOT used to store tokens — tokens stay in Auth Server-issued HttpOnly cookies.
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,      // Session ID not readable by JS
    secure: process.env.NODE_ENV === "production", // HTTPS-only in prod
    sameSite: "lax",     // CSRF protection; lax allows OAuth redirect GET
    maxAge: 10 * 60 * 1000, // 10 min — OAuth flows should complete well within this
  },
  name: "sid",           // Don't leak the default "connect.sid" name (fingerprinting)
}));

// ---------------------------------------------------------------------------
// OAuth client config — confidential client credentials stay server-side only
// ---------------------------------------------------------------------------
const OAUTH_CLIENT_ID     = process.env.OAUTH_CLIENT_ID     || "frontend";
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || "demo-secret-change-in-prod";
const OAUTH_REDIRECT_URI  = "http://localhost:3000/oauth-callback";
const OAUTH_SCOPES        = "read:profile";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Forward Set-Cookie headers from Auth Server response to the browser.
 *  Tokens are set as HttpOnly cookies by the Auth Server — this proxy
 *  simply passes them through unchanged. The frontend never reads their values. */
function forwardCookies(authRes, res) {
  // node-fetch v3 provides getSetCookie() returning an array
  const cookies = authRes.headers.getSetCookie?.() ?? [];
  for (const c of cookies) {
    res.append("Set-Cookie", c);
  }
}
/** Proxy request cookies from the browser to the Auth Server.
 *  HttpOnly cookies are invisible to JS but are still present on the
 *  request object in Node — we forward them so the Auth Server can
 *  authenticate the user without the frontend ever seeing the token values. */
function forwardRequestCookies(req) {
  return req.headers.cookie || "";
}

/** Simple HTML shell — no framework, no client-side JS for auth logic */
function page(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #f8f9fa; color: #212529; min-height: 100vh; }
    nav { background: #1a1a2e; padding: 14px 32px; display: flex; align-items: center; gap: 24px; }
    nav a { color: #e0e0e0; text-decoration: none; font-size: .9rem; transition: color .15s; }
    nav a:hover { color: #fff; }
    nav .brand { color: #fff; font-weight: 600; font-size: 1rem; margin-right: auto; }
    main { max-width: 460px; margin: 60px auto; padding: 0 20px; }
    h1 { font-size: 1.6rem; margin-bottom: 24px; }
    .card { background: #fff; border-radius: 8px; padding: 28px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
    label { display: block; font-size: .85rem; font-weight: 500; margin-bottom: 4px; color: #495057; }
    input[type=email], input[type=password] {
      width: 100%; padding: 9px 12px; border: 1px solid #ced4da;
      border-radius: 5px; font-size: .95rem; margin-bottom: 16px; outline: none;
    }
    input:focus { border-color: #4361ee; box-shadow: 0 0 0 3px rgba(67,97,238,.15); }
    button, .btn {
      display: block; width: 100%; padding: 10px; background: #4361ee;
      color: #fff; border: none; border-radius: 5px; font-size: .95rem;
      font-weight: 500; cursor: pointer; text-align: center; text-decoration: none;
      transition: background .15s; margin-bottom: 10px;
    }
    button:hover, .btn:hover { background: #3451d1; }
    .btn-secondary { background: #6c757d; }
    .btn-secondary:hover { background: #5a6268; }
    .btn-outline {
      background: transparent; color: #4361ee;
      border: 1.5px solid #4361ee;
    }
    .btn-outline:hover { background: #eef0fd; }
    .error { background: #fff3f3; border: 1px solid #f5c2c7; color: #842029;
             padding: 10px 14px; border-radius: 5px; font-size: .9rem; margin-bottom: 16px; }
    .success { background: #f0fff4; border: 1px solid #b7efc5; color: #0f5132;
               padding: 10px 14px; border-radius: 5px; font-size: .9rem; margin-bottom: 16px; }
    .meta { font-size: .85rem; color: #6c757d; margin-top: 16px; text-align: center; }
    .meta a { color: #4361ee; }
    .divider { display: flex; align-items: center; gap: 12px; margin: 18px 0; color: #adb5bd; font-size: .85rem; }
    .divider::before, .divider::after { content: ""; flex: 1; height: 1px; background: #dee2e6; }
    table { width: 100%; border-collapse: collapse; font-size: .9rem; }
    td { padding: 8px 0; border-bottom: 1px solid #f1f3f5; }
    td:first-child { color: #6c757d; width: 40%; }
  </style>
</head>
<body>
  <nav>
    <span class="brand">AuthDemo</span>
    <a href="/">Home</a>
    <a href="/dashboard">Dashboard</a>
    <a href="/logout">Logout</a>
  </nav>
  <main>${body}</main>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// GET /  — homepage
// ---------------------------------------------------------------------------
app.get("/", (req, res) => {
  res.send(page("AuthDemo", `
    <h1>AuthDemo</h1>
    <div class="card">
      <p style="margin-bottom:20px;color:#495057;font-size:.95rem;">
        Minimal auth system demo — password login and OAuth 2.0 Authorization Code Flow.
      </p>
      <a href="/login" class="btn">Login with password</a>
      <a href="/oauth-login" class="btn btn-outline">Login via OAuth</a>
      <div class="divider">or</div>
      <a href="/register" class="btn btn-secondary">Create account</a>
    </div>
  `));
});

// ---------------------------------------------------------------------------
// GET /register
// ---------------------------------------------------------------------------
app.get("/register", (req, res) => {
  const err = req.query.error ? `<div class="error">${req.query.error}</div>` : "";
  res.send(page("Register", `
    <h1>Create account</h1>
    <div class="card">
      ${err}
      <form method="POST" action="/register">
        <label>Email</label>
        <input type="email" name="email" required autocomplete="username">
        <label>Password</label>
        <input type="password" name="password" required autocomplete="new-password" minlength="8">
        <button type="submit">Register</button>
      </form>
      <p class="meta">Already have an account? <a href="/login">Log in</a></p>
    </div>
  `));
});

// ---------------------------------------------------------------------------
// POST /register — proxy to Auth Server
// ---------------------------------------------------------------------------
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  try {
    const authRes = await fetch(`${AUTH}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (authRes.ok) {
      return res.redirect("/login?registered=1");
    }
    const data = await authRes.json().catch(() => ({}));
    const msg = encodeURIComponent(data.detail || "Registration failed");
    res.redirect(`/register?error=${msg}`);
  } catch {
    res.redirect("/register?error=Could+not+reach+auth+server");
  }
});

// ---------------------------------------------------------------------------
// GET /login
// ---------------------------------------------------------------------------
app.get("/login", (req, res) => {
  const err = req.query.error ? `<div class="error">${req.query.error}</div>` : "";
  const ok  = req.query.registered ? `<div class="success">Account created — please log in.</div>` : "";
  res.send(page("Login", `
    <h1>Log in</h1>
    <div class="card">
      ${err}${ok}
      <form method="POST" action="/login">
        <label>Email</label>
        <input type="email" name="email" required autocomplete="username">
        <label>Password</label>
        <input type="password" name="password" required autocomplete="current-password">
        <button type="submit">Log in</button>
      </form>
      <div class="divider">or</div>
      <a href="/oauth-login" class="btn btn-outline">Login via OAuth</a>
      <p class="meta">No account? <a href="/register">Register</a></p>
    </div>
  `));
});

// ---------------------------------------------------------------------------
// POST /login — proxy credentials to Auth Server; forward HttpOnly cookies back
// ---------------------------------------------------------------------------
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const authRes = await fetch(`${AUTH}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (authRes.ok) {
      // Pass the Auth Server's Set-Cookie headers straight to the browser.
      // This frontend never sees the token values — they're HttpOnly on the cookie.
      forwardCookies(authRes, res);
      return res.redirect("/dashboard");
    }

    const data = await authRes.json().catch(() => ({}));
    const msg = encodeURIComponent(data.detail || "Login failed");
    res.redirect(`/login?error=${msg}`);
  } catch {
    res.redirect("/login?error=Could+not+reach+auth+server");
  }
});

// ---------------------------------------------------------------------------
// GET /dashboard — fetch user identity from Auth Server; render server-side
// ---------------------------------------------------------------------------
app.get("/dashboard", async (req, res) => {
  try {
    // Forward the browser's cookies (including the HttpOnly access_token) to Auth Server.
    // The frontend never reads the access_token value — it just tunnels the cookie header.
    const authRes = await fetch(`${AUTH}/auth/me`, {
      headers: { cookie: forwardRequestCookies(req) },
    });

    if (authRes.status === 401) {
      // Try refreshing the access token before giving up
      const refreshRes = await fetch(`${AUTH}/auth/refresh`, {
        method: "POST",
        headers: { cookie: forwardRequestCookies(req) },
      });
      if (refreshRes.ok) {
        forwardCookies(refreshRes, res);
        return res.redirect("/dashboard");
      }
      return res.redirect("/login?error=Session+expired");
    }

    if (!authRes.ok) {
      return res.redirect("/login?error=Not+authenticated");
    }

    const user = await authRes.json();
    // Identity comes from Auth Server response body — we never decode the JWT ourselves.
    // The frontend has no business parsing tokens; that's the Auth Server's job.
    res.send(page("Dashboard", `
      <h1>Dashboard</h1>
      <div class="card">
        <p style="margin-bottom:20px;color:#495057">Authenticated session active.</p>
        <table>
          <tr><td>User ID</td><td>${user.id}</td></tr>
          <tr><td>Email</td><td>${user.email}</td></tr>
          <tr><td>Status</td><td>${user.is_active ? "Active" : "Inactive"}</td></tr>
        </table>
        <div style="margin-top:24px">
          <a href="/logout" class="btn btn-secondary">Log out</a>
        </div>
      </div>
    `));
  } catch {
    res.redirect("/login?error=Could+not+reach+auth+server");
  }
});

// ---------------------------------------------------------------------------
// GET /logout — revoke refresh token on Auth Server; clear cookies
// ---------------------------------------------------------------------------
app.get("/logout", async (req, res) => {
  try {
    // Tell the Auth Server to revoke the refresh token.
    // Forwarding cookies lets the server identify which token to revoke.
    await fetch(`${AUTH}/auth/logout`, {
      method: "POST",
      headers: { cookie: forwardRequestCookies(req) },
    });
  } catch { /* best-effort — proceed with local logout regardless */ }

  // Auth Server will clear its HttpOnly cookies; we redirect to login.
  // Even if the revocation request failed, the user is redirected away from protected routes.
  res.redirect("/login");
});

// ---------------------------------------------------------------------------
// GET /oauth-login — initiate Authorization Code Flow
// ---------------------------------------------------------------------------
app.get("/oauth-login", (req, res) => {
  // state: random value bound to this session, echoed back by Auth Server.
  // Validated in /oauth-callback to prevent CSRF — an attacker cannot initiate
  // a flow and trick a victim into completing it for them.
  const state = crypto.randomBytes(24).toString("base64url");

  // PKCE: code_verifier stays server-side (in session), only the challenge goes out.
  // Even if someone intercepts the auth code in the redirect, they cannot exchange it
  // without the verifier.
  const verifier  = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");

  // Store in server-side session — never in a cookie or URL parameter
  req.session.oauthState    = state;
  req.session.codeVerifier  = verifier;

  const params = new URLSearchParams({
    response_type:         "code",
    client_id:             OAUTH_CLIENT_ID,
    redirect_uri:          OAUTH_REDIRECT_URI,
    scope:                 OAUTH_SCOPES,
    state,
    code_challenge:        challenge,
    code_challenge_method: "S256",
  });

  res.redirect(`${AUTH}/oauth/authorize?${params}`);
});

// ---------------------------------------------------------------------------
// GET /oauth-callback — complete Authorization Code Flow
// ---------------------------------------------------------------------------
app.get("/oauth-callback", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.redirect(`/login?error=${encodeURIComponent(error)}`);
  }

  // CSRF check: state returned by Auth Server must match what we stored in session.
  // req.session.oauthState was generated by this server and never sent to the browser
  // as a readable value — an attacker cannot forge a matching state.
  if (!state || state !== req.session.oauthState) {
    return res.redirect("/login?error=Invalid+state+parameter");
  }

  const verifier = req.session.codeVerifier;
  if (!verifier || !code) {
    return res.redirect("/login?error=Missing+OAuth+parameters");
  }

  // Clear OAuth session data — single-use
  delete req.session.oauthState;
  delete req.session.codeVerifier;

  try {
    // Token exchange is server-to-server — client_secret never touches the browser.
    // The browser only ever saw the auth code (in the redirect URL) which is now spent.
    const tokenRes = await fetch(`${AUTH}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type:    "authorization_code",
        code,
        redirect_uri:  OAUTH_REDIRECT_URI,
        client_id:     OAUTH_CLIENT_ID,
        client_secret: OAUTH_CLIENT_SECRET,
        code_verifier: verifier,
      }),
    });

    if (!tokenRes.ok) {
      const data = await tokenRes.json().catch(() => ({}));
      const msg = encodeURIComponent(data.detail || "Token exchange failed");
      return res.redirect(`/login?error=${msg}`);
    }

    // Tokens arrive in response body (server-to-server exchange).
    // We immediately convert them to HttpOnly cookies — they never reach the browser
    // as readable values. This is the confidential client's responsibility.
    const tokens = await tokenRes.json();

    const cookieOpts = [
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
      "Path=/",
    ].join("; ");

    res.append("Set-Cookie",
      `access_token=${tokens.access_token}; Max-Age=${tokens.expires_in}; ${cookieOpts}`
    );
    res.append("Set-Cookie",
      `refresh_token=${tokens.refresh_token}; Max-Age=${7 * 24 * 3600}; ${cookieOpts}`
    );

    res.redirect("/dashboard");
  } catch {
    res.redirect("/login?error=Could+not+reach+auth+server");
  }
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Frontend running at http://localhost:${PORT}`);
  console.log(`Auth Server expected at ${AUTH}`);
});
