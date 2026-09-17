"""
OAUTH category — deliberately weak OAuth 2.0 / 2.1 authorization server + the
MCP protected-resource metadata that points at it. A scanner detects most of
these by reading the two .well-known metadata documents; the rest by exercising
the authorize/token/register endpoints. No real accounts or secrets exist.

Findings intended to trip (21):
  Weak OAuth Metadata, PKCE Not Enforced, PKCE Downgrade, Missing Client Auth,
  Implicit Flow, Password Grant, Open Redirect, Open Registration,
  Scope Escalation, Missing State, Insecure Cookie, No Revocation, Weak Token,
  alg=none Accepted, Unbound Token, Code Reuse, Token in Query String,
  Cacheable Token, No Refresh Rotation, Excessive Token Lifetime,
  Audience Not Validated.
"""
from __future__ import annotations

import base64
import json
import os

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

# When true, /oauth/authorize performs a RAW 302 to any redirect_uri (live open
# redirect) — only safe on an isolated/closed lab. Default false on a public host:
# the finding stays detectable (unvalidated redirect_uri reflected + advertised in
# metadata) but the endpoint does not forward victims to arbitrary external sites.
ALLOW_OPEN_REDIRECT = os.getenv("ALLOW_OPEN_REDIRECT", "false").lower() == "true"

from ..mcp_core import MCPServer, Tool

# The OAuth endpoint is also a (minimal) MCP server so the MCP scan reaches it.
srv = MCPServer(
    "oauth-lab",
    instructions="Protected MCP resource. See /.well-known/oauth-protected-resource.",
)
srv.add_tool(Tool(
    "whoami",
    "Return the authenticated principal (auth is not actually enforced).",
    {"type": "object", "properties": {}},
    lambda a: {"text": "principal=anonymous (bearer token accepted from header OR ?access_token= query)"},
))

# A fixed authorization code that is intentionally reusable.
_REUSABLE_CODE = "auth_code_static_123"
# A refresh token that never rotates.
_STATIC_REFRESH = "refresh_static_neverrotates"


def _issuer(request: Request) -> str:
    # honor forwarded host without validation (helps DNS-rebind style testing too)
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}"


def as_metadata(request: Request) -> dict:
    iss = _issuer(request)
    return {
        "issuer": iss,
        "authorization_endpoint": f"{iss}/oauth/authorize",
        "token_endpoint": f"{iss}/oauth/token",
        "registration_endpoint": f"{iss}/oauth/register",   # Open Registration
        "jwks_uri": f"{iss}/oauth/jwks",
        # NOTE: no "revocation_endpoint" -> No Revocation
        "response_types_supported": ["code", "token", "id_token token"],  # Implicit Flow
        "grant_types_supported": [
            "authorization_code", "implicit", "password", "refresh_token",  # Password Grant
        ],
        # "plain" present -> PKCE Not Enforced / PKCE Downgrade
        "code_challenge_methods_supported": ["plain", "S256"],
        # "none" present -> Missing Client Auth
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        # "none" present -> alg=none Accepted
        "id_token_signing_alg_values_supported": ["none", "HS256"],
        "scopes_supported": ["read", "write", "admin"],
        "bearer_methods_supported": ["header", "query"],  # Token in Query String
        # deliberately omits many recommended fields -> Weak OAuth Metadata
    }


def protected_resource_metadata(request: Request) -> dict:
    iss = _issuer(request)
    return {
        "resource": f"{iss}/mcp/oauth",
        "authorization_servers": [iss],
        "bearer_methods_supported": ["header", "query"],   # Token in Query String
        "scopes_supported": ["read", "write", "admin"],
        # No audience/resource-binding requirement -> Audience Not Validated
    }


# ----------------------------------------------------------------------------
# HTTP handlers (wired into the app in main.py)
# ----------------------------------------------------------------------------
async def wellknown_as(request: Request) -> Response:
    return JSONResponse(as_metadata(request))


async def wellknown_prm(request: Request) -> Response:
    return JSONResponse(protected_resource_metadata(request))


def _is_external(redirect_uri: str) -> bool:
    return redirect_uri.startswith(("http://", "https://", "//"))


async def authorize(request: Request) -> Response:
    q = request.query_params
    redirect_uri = q.get("redirect_uri", "/")
    state = q.get("state")           # missing state is tolerated -> Missing State
    response_type = q.get("response_type", "code")

    # Open Redirect: redirect_uri is not validated against any allow-list.
    if response_type in ("token", "id_token token"):
        # Implicit Flow + Token in Query String: token handed back in the URL.
        frag = f"access_token=weak_token_1&token_type=bearer&expires_in=315360000"
        if state:
            frag += f"&state={state}"
        target = f"{redirect_uri}#{frag}"
    else:
        sep = "&" if "?" in redirect_uri else "?"
        target = f"{redirect_uri}{sep}code={_REUSABLE_CODE}"
        if state:
            target += f"&state={state}"

    # Insecure Cookie: no Secure, no HttpOnly, no SameSite.
    cookie = "session=fixed-session-abc; Path=/"

    # Live 302 to anything only in closed-lab mode, or for same-origin targets.
    if ALLOW_OPEN_REDIRECT or not _is_external(redirect_uri):
        resp = RedirectResponse(target, status_code=302)
        resp.headers["Set-Cookie"] = cookie
        return resp

    # Public-safe: DO NOT forward victims to an arbitrary external site. The
    # finding remains detectable — the unvalidated redirect_uri is reflected
    # verbatim (no allow-list check) and echoed in a header a scanner can key on.
    body = (
        "<!doctype html><meta charset=utf-8>"
        "<title>Authorize (intentionally-vulnerable lab)</title>"
        "<h1>Open redirect (public-safe interstitial)</h1>"
        "<p>This authorization server performs NO validation of redirect_uri.</p>"
        f"<p>Unvalidated target reflected verbatim: <code>{target}</code></p>"
        "<p>Auto-forwarding to external hosts is disabled on this public deployment. "
        "Set ALLOW_OPEN_REDIRECT=true for a raw 302 in a closed lab.</p>"
    )
    resp = HTMLResponse(body, status_code=200)
    resp.headers["X-Unvalidated-Redirect"] = target  # reflection for scanners
    resp.headers["Set-Cookie"] = cookie
    return resp


def _alg_none_jwt(claims: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{body}."  # empty signature -> alg=none Accepted


async def token(request: Request) -> Response:
    form = {}
    try:
        form = dict(await request.form())
    except Exception:
        pass
    if not form:
        try:
            form = await request.json()
        except Exception:
            form = {}
    grant_type = form.get("grant_type", "authorization_code")
    requested_scope = form.get("scope", "read")

    # Missing Client Auth: no client_secret / auth required at all.
    # Code Reuse: the code is static and never invalidated.
    # PKCE Not Enforced: code_verifier is never checked.

    # Scope Escalation: always grant admin regardless of requested scope.
    granted_scope = "read write admin"

    # Unbound Token / alg=none: token carries no aud/cnf binding, alg=none JWT.
    access_token = _alg_none_jwt({"sub": "user", "scope": granted_scope})
    if grant_type == "password":
        # Password Grant accepted with any username/password.
        access_token = _alg_none_jwt({"sub": form.get("username", "user"), "scope": granted_scope})

    body = {
        "access_token": access_token,
        "token_type": "bearer",
        # Excessive Token Lifetime: 10 years.
        "expires_in": 315360000,
        # No Refresh Rotation: same refresh token every time.
        "refresh_token": _STATIC_REFRESH,
        "scope": granted_scope,
    }
    resp = JSONResponse(body)
    # Cacheable Token: intentionally NOT setting Cache-Control: no-store / Pragma: no-cache.
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp


async def register(request: Request) -> Response:
    # Open Registration: unauthenticated dynamic client registration.
    try:
        meta = await request.json()
    except Exception:
        meta = {}
    return JSONResponse({
        "client_id": "public-client-anyone",
        "client_secret": "no-secret-needed",
        "token_endpoint_auth_method": "none",
        "redirect_uris": meta.get("redirect_uris", ["https://anything.example/cb"]),
        "grant_types": ["authorization_code", "implicit", "password"],
    }, status_code=201)


async def jwks(request: Request) -> Response:
    # Advertise HS256 + acceptance of unsigned tokens.
    return JSONResponse({"keys": [{"kty": "oct", "alg": "HS256", "k": "c2VjcmV0", "kid": "1"}]})
