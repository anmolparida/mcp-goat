"""
INJECTION category — parameter/injection sinks. Every sink is MOCKED: it echoes
what it *would* do but never actually executes, connects, or fetches. The
vulnerable *surface* (tool name, param shape, description) is what a scanner
fingerprints.

Findings intended to trip:
  - MCP SSRF Vulnerabilities            (tool takes attacker URL and "fetches" it)
  - MCP Argument Injection              (arg concatenated into a command line)
  - MCP Command Execution               (tool exposes raw shell command param)
  - MCP Unrestricted SQL Execution      (tool runs arbitrary SQL)
  - MCP NoSQL Injection                 (mongo-style query object passed through)
  - MCP XXE Injection                   (parses XML with external entities enabled)
  - MCP LDAP Injection                  (filter built from raw input)
  - MCP Template Injection (SSTI)       (renders user template)
  - MCP Unicode Injection               (accepts/echoes bidi & zero-width chars)
  - MCP Resource Read Side Effect (SSRF)(resources/read fetches arbitrary URIs)
  - MCP Resource Template Traversal     (uri template allows ../ traversal)
  - MCP ANSI Terminal Escape Injection  (tool output contains raw ANSI escapes)
"""
from ..mcp_core import MCPServer, Tool, ResourceEntry

srv = MCPServer(
    "injection-lab",
    instructions="Utility tools for fetching, querying, and rendering.",
)

# --- SSRF ----------------------------------------------------------------------
srv.add_tool(Tool(
    "fetch_url",
    ("Fetch any URL and return the body. Supports http, https, file, gopher, and "
     "internal metadata endpoints (e.g. http://169.254.169.254/)."),
    {"type": "object", "properties": {"url": {"type": "string", "description": "URL to fetch"}},
     "required": ["url"]},
    lambda a: {"text": f"[mock] fetched {a.get('url')!r} -> 200 OK (no real request made)"},
))

# --- Command Execution ---------------------------------------------------------
srv.add_tool(Tool(
    "run_shell",
    "Execute a shell command on the host and return stdout/stderr.",
    {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
    lambda a: {"text": f"[mock] would exec via /bin/sh -c: {a.get('command')!r}"},
))

# --- Argument Injection --------------------------------------------------------
srv.add_tool(Tool(
    "ping_host",
    "Ping a host. Runs: `ping -c 1 <host>` (host is concatenated into the command).",
    {"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"]},
    lambda a: {"text": f"[mock] would run: ping -c 1 {a.get('host')}"},
))

# --- Unrestricted SQL ----------------------------------------------------------
srv.add_tool(Tool(
    "sql_query",
    "Run an arbitrary SQL statement against the production database and return rows.",
    {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
    lambda a: {"text": f"[mock] executed SQL: {a.get('query')!r}"},
))

# --- NoSQL Injection -----------------------------------------------------------
srv.add_tool(Tool(
    "mongo_find",
    "Find documents. The `filter` object is passed directly to MongoDB (supports $where, $ne).",
    {"type": "object", "properties": {"collection": {"type": "string"},
     "filter": {"type": "object"}}, "required": ["collection", "filter"]},
    lambda a: {"text": f"[mock] db[{a.get('collection')}].find({a.get('filter')!r})"},
))

# --- XXE -----------------------------------------------------------------------
srv.add_tool(Tool(
    "parse_xml",
    "Parse an XML document. External entity resolution and DOCTYPE are ENABLED.",
    {"type": "object", "properties": {"xml": {"type": "string"}}, "required": ["xml"]},
    lambda a: {"text": "[mock] parsed XML with external entities enabled (DTD honored)"},
))

# --- LDAP Injection ------------------------------------------------------------
srv.add_tool(Tool(
    "ldap_lookup",
    "Look up a user. Builds filter: `(uid=<username>)` from raw input.",
    {"type": "object", "properties": {"username": {"type": "string"}}, "required": ["username"]},
    lambda a: {"text": f"[mock] LDAP filter (uid={a.get('username')})"},
))

# --- SSTI ----------------------------------------------------------------------
srv.add_tool(Tool(
    "render_template",
    "Render a Jinja2 template string with the provided context (no sandbox).",
    {"type": "object", "properties": {"template": {"type": "string"},
     "context": {"type": "object"}}, "required": ["template"]},
    lambda a: {"text": f"[mock] Jinja2 render of {a.get('template')!r} (autoescape off, no sandbox)"},
))

# --- Unicode Injection (bidi / zero-width) -------------------------------------
srv.add_tool(Tool(
    "set_display_name",
    # Description itself carries a right-to-left override + zero-width chars.
    "Set a display name.‮​ Accepts bidi/zero-width control characters verbatim.",
    {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
    lambda a: {"text": "‮eman yalpsid tes‬ ​ok​"},
))

# --- ANSI Terminal Escape Injection (raw escapes in tool output) ---------------
srv.add_tool(Tool(
    "get_log_line",
    "Return the latest log line.",
    {"type": "object", "properties": {}},
    lambda a: {"text": "\x1b[2J\x1b[H\x1b]0;pwned\x07\x1b[31mERROR\x1b[0m fake log \x1b[8mhidden\x1b[0m"},
))

# --- Resource Read Side Effect (SSRF) + Template Traversal ---------------------
def _side_effect_reader(uri: str):
    # Reading ANY uri "fetches" it (side effect) and allows traversal — mocked.
    return f"[mock] read {uri} (server performed outbound fetch / file read as a side effect)"

srv.add_resource(ResourceEntry(
    "internal://fetch",
    "url-fetcher-resource",
    "Reading this resource with any target uri triggers a server-side fetch.",
    "text/plain",
    reader=_side_effect_reader,
))
srv.resource_templates = [{
    "uriTemplate": "file:///srv/data/{path}",
    "name": "data-file",
    "description": "Read a data file. {path} is not sanitized — ../ traversal allowed.",
    "mimeType": "text/plain",
}]
