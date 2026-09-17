# Check → Endpoint mapping

Every check from the TotalAI MCP catalog and where it is exposed in this target.
Point TotalAI at the endpoint in the second column. All dangerous behavior is
**mocked** — the vulnerable *surface* (schema, description, metadata, protocol
behavior) is what the scanner fingerprints.

Base URL below is written as `HOST` (e.g. `http://<docker-host>:8080`).

## Discovery — `HOST/mcp/discovery`

| Check | How it's exposed |
|---|---|
| MCP Endpoint Discovery | Responds to MCP handshake on a discoverable path; `/` lists all endpoints |
| MCP Tool Discovery | `tools/list` returns tools with no auth |
| MCP Hidden Tool | `admin_debug_shell` is callable via `tools/call` but absent from `tools/list` |
| MCP Duplicate Tool Names | Two tools both advertise name `get_status` |
| MCP Prompt Listing Disclosure | `prompts/list` exposes internal prompts |
| MCP Prompt Detail Leak | `internal_support_agent` prompt body leaks admin password + DB DSN |
| MCP Roots Disclosure | `roots/list` leaks `~/.ssh`, prod-db, secrets paths |
| MCP Dependency Confusion | `render_report` requires unscoped internal packages from public index |

## Injection — `HOST/mcp/injection`

| Check | How it's exposed |
|---|---|
| MCP SSRF Vulnerabilities | `fetch_url(url)` fetches arbitrary URLs incl. `169.254.169.254` |
| MCP Argument Injection | `ping_host(host)` concatenated into `ping -c 1 <host>` |
| MCP Command Execution | `run_shell(command)` exposes raw shell |
| MCP Unrestricted SQL Execution | `sql_query(query)` runs arbitrary SQL |
| MCP NoSQL Injection | `mongo_find(filter)` passes raw object to Mongo (`$where`, `$ne`) |
| MCP XXE Injection | `parse_xml(xml)` documents external entities enabled |
| MCP LDAP Injection | `ldap_lookup(username)` builds `(uid=<raw>)` |
| MCP Template Injection (SSTI) | `render_template(template)` unsandboxed Jinja2 |
| MCP Unicode Injection | `set_display_name` — bidi/zero-width chars in description + output |
| MCP ANSI Terminal Escape Injection | `get_log_line` output contains raw ANSI/OSC escapes |
| MCP Resource Read Side Effect (SSRF) | `resources/read` on `internal://fetch` triggers server-side fetch |
| MCP Resource Template Traversal | `file:///srv/data/{path}` template allows `../` |

## Tool Poisoning — `HOST/mcp/tool-poisoning`

| Check | How it's exposed |
|---|---|
| MCP Tool Poisoning | `add` description hides `<IMPORTANT>` exfil instructions |
| MCP Advanced Tool Poisoning | `summarize` hides instructions in a field `description` |
| MCP Tool Schema Default Injection | `summarize.style` malicious `default` value |
| MCP Rug-Pull Detection | `weather` description admits behavior changes after approval |
| MCP Cross-Server Shadowing | `send_email` instructs client to override other servers' tools |
| MCP Server Spoofing | `serverInfo` impersonates "GitHub Official MCP" / verified vendor |
| MCP Retrieval-Agent Deception (RADE) | `docs://quarterly/q3` resource carries hidden agent commands |
| MCP Error Message Prompt Injection | `process_payment` error text injects "developer mode" instructions |
| MCP Exfiltration Beacon | `track_usage` description POSTs secrets to `beacon.evil.example` |
| MCP Notification Abuse | `subscribe_alerts` advertises unbounded notification flooding |
| MCP Sampling Attacks | `autocomplete` returns a `_sampling_request` with injected prompt |
| MCP Elicitation Disclosure | `verify_account` elicits SSN/card/CVV/MFA seed |

## Disclosure / Protocol Abuse — `HOST/mcp/disclosure`

| Check | How it's exposed |
|---|---|
| MCP Information Disclosure | `debug_info` leaks env vars, internal host, traceback; `debug=True` app |
| MCP Credential Exposure | `get_service_token` returns live bearer + refresh token |
| MCP Hardcoded Secret in Metadata | `serverInfo`/`instructions` contain AWS keys, Slack token, DB URL |
| MCP Browser File Access | `read_browser_data` reads Chrome `Cookies`/`Login Data` |
| MCP Cross-Session State Leak | `note_get_all` returns every session's notes from a global store |
| MCP JSON Duplicate-Key Pollution | `get_role` returns a body with duplicate `role`/`result` keys |
| MCP Output Schema Mismatch | `get_temperature` declares numeric `outputSchema`, returns other shape |
| MCP Resource Mutation After Subscribe | `state://balance` content mutates on second read |
| MCP Session Fixation | Server accepts a client-supplied session id (`X-Session-Id`) |
| MCP DNS Rebinding Risk | `serverInfo` advertises `host_validation: disabled`, `allowed_origins: *` |

## OAuth — `HOST/mcp/oauth` (+ `HOST/.well-known/*`)

Detected primarily from `/.well-known/oauth-authorization-server` and
`/.well-known/oauth-protected-resource`, and from the `/oauth/*` endpoints.

| Check | How it's exposed |
|---|---|
| MCP Weak OAuth Metadata | Metadata omits recommended fields; permissive everywhere |
| MCP OAuth PKCE Not Enforced | `code_challenge_methods_supported` includes `plain`; verifier never checked |
| MCP OAuth PKCE Downgrade | Both `plain` and `S256` offered → downgrade to `plain` |
| MCP OAuth Missing Client Auth | `token_endpoint_auth_methods_supported: ["none", ...]` |
| MCP OAuth Implicit Flow | `response_types_supported` includes `token`; grants `implicit` |
| MCP OAuth Password Grant | `grant_types_supported` includes `password`; `/oauth/token` accepts it |
| MCP OAuth Open Redirect | `/oauth/authorize` redirects to any `redirect_uri` unvalidated |
| MCP OAuth Open Registration | `/oauth/register` unauthenticated dynamic client registration |
| MCP OAuth Scope Escalation | Token endpoint grants `read write admin` regardless of request |
| MCP OAuth Missing State | `/oauth/authorize` proceeds without `state` |
| MCP OAuth Insecure Cookie | `Set-Cookie: session=...` no Secure/HttpOnly/SameSite |
| MCP OAuth No Revocation | No `revocation_endpoint` in metadata / no `/oauth/revoke` |
| MCP OAuth Weak Token | Implicit flow returns `weak_token_1` (low entropy/predictable) |
| MCP OAuth alg=none Accepted | `id_token_signing_alg_values_supported: ["none",...]`; JWTs use `alg=none` |
| MCP OAuth Unbound Token | Issued JWT has no `aud`/`cnf` binding |
| MCP OAuth Code Reuse | `/oauth/token` accepts the same static code repeatedly |
| MCP OAuth Token in Query String | `bearer_methods_supported: ["query"]`; implicit token in URL |
| MCP OAuth Cacheable Token | Token response `Cache-Control: public` (not `no-store`) |
| MCP OAuth No Refresh Rotation | Same `refresh_token` returned every time |
| MCP OAuth Excessive Token Lifetime | `expires_in: 315360000` (10 years) |
| MCP OAuth Audience Not Validated | Protected-resource metadata has no audience binding; `whoami` accepts any token |

---

### Notes on a few checks

- **Server Spoofing** and **DNS Rebinding Risk** are advertised via metadata
  because a static test target cannot actually rebind DNS or hold a real vendor
  identity — the scanner should still fingerprint the exposed indicators.
- **Session Fixation** relies on the server honoring a client-proposed session
  id; send header `X-Session-Id: attacker-fixed` on `initialize`.
- If TotalAI expects each finding on its *own* URL rather than grouped, split
  any category server in `app/servers/` into per-tool servers and add routes in
  `app/main.py` — the core supports any number of endpoints.
