"""
mcp-server-scan — a DELIBERATELY VULNERABLE MCP test target.

Purpose: validate that an MCP security scanner (e.g. Qualys TotalAI) detects a
broad catalog of MCP findings. Each vulnerability CATEGORY is a separate MCP
endpoint so you can scan and confirm findings group by group.

  Endpoint (point TotalAI here)     Category
  --------------------------------  ------------------------------------------
  /mcp/discovery                    endpoint/tool discovery, hidden/duplicate
                                    tools, prompt & roots disclosure, dep-confusion
  /mcp/injection                    SSRF, command/SQL/NoSQL/XXE/LDAP/SSTI/arg
                                    injection, unicode, ANSI, resource traversal
  /mcp/tool-poisoning               tool poisoning, rug-pull, shadowing, RADE,
                                    spoofing, sampling, elicitation, beacon, ...
  /mcp/disclosure                   info/credential/secret disclosure, browser
                                    file access, cross-session leak, json/schema
  /mcp/oauth                        21 OAuth findings (+ .well-known metadata)

SAFETY: all dangerous tool bodies are mocked. Do NOT deploy on a public host.
"""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from .servers import discovery, injection, tool_poisoning, disclosure, oauth

MCP_ENDPOINTS = {
    "/mcp/discovery": discovery.srv,
    "/mcp/injection": injection.srv,
    "/mcp/tool-poisoning": tool_poisoning.srv,
    "/mcp/disclosure": disclosure.srv,
    "/mcp/oauth": oauth.srv,
}


def _make_mcp_route(server):
    async def handler(request):
        return await server.handle_http(request)
    return handler


async def index(request):
    base = str(request.base_url).rstrip("/")
    return JSONResponse({
        "name": "mcp-server-scan",
        "warning": ("INTENTIONALLY VULNERABLE MCP test target for security-scanner "
                    "validation (e.g. Qualys TotalAI). All dangerous behavior is "
                    "mocked. Do not enter real data. Not affiliated with any vendor "
                    "named in spoofed metadata."),
        "usage": "Point your MCP scanner at one of the mcp_endpoints below.",
        "mcp_endpoints": [f"{base}{p}" for p in MCP_ENDPOINTS],
        "oauth_metadata": [
            f"{base}/.well-known/oauth-authorization-server",
            f"{base}/.well-known/oauth-protected-resource",
        ],
    })


async def robots(request):
    # Keep this off search engines.
    return PlainTextResponse("User-agent: *\nDisallow: /\n")


async def health(request):
    return PlainTextResponse("ok")


routes = [
    Route("/", index, methods=["GET"]),
    Route("/health", health, methods=["GET"]),
    Route("/robots.txt", robots, methods=["GET"]),
    # OAuth metadata (served at root AND path-suffixed per RFC 8414 / RFC 9728).
    Route("/.well-known/oauth-authorization-server", oauth.wellknown_as, methods=["GET"]),
    Route("/.well-known/oauth-authorization-server/mcp/oauth", oauth.wellknown_as, methods=["GET"]),
    Route("/.well-known/oauth-protected-resource", oauth.wellknown_prm, methods=["GET"]),
    Route("/.well-known/oauth-protected-resource/mcp/oauth", oauth.wellknown_prm, methods=["GET"]),
    Route("/.well-known/openid-configuration", oauth.wellknown_as, methods=["GET"]),
    # OAuth flow endpoints (intentionally weak). No revocation endpoint on purpose.
    Route("/oauth/authorize", oauth.authorize, methods=["GET", "POST"]),
    Route("/oauth/token", oauth.token, methods=["POST"]),
    Route("/oauth/register", oauth.register, methods=["POST"]),
    Route("/oauth/jwks", oauth.jwks, methods=["GET"]),
]

# Register each MCP endpoint for the methods a streamable-HTTP server needs.
for path, server in MCP_ENDPOINTS.items():
    routes.append(Route(path, _make_mcp_route(server), methods=["GET", "POST", "DELETE"]))

app = Starlette(debug=True, routes=routes)  # debug=True -> verbose errors (info disclosure)
