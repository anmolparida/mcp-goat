"""
DISCOVERY category — endpoint discovery, tool discovery, hidden tools,
duplicate tool names, prompt disclosure, roots disclosure, dependency confusion.

Findings intended to trip:
  - MCP Endpoint Discovery        (server responds on well-known MCP paths)
  - MCP Tool Discovery            (tools/list returns tools without auth)
  - MCP Hidden Tool               (a callable tool absent from tools/list)
  - MCP Duplicate Tool Names      (two tools with the same name)
  - MCP Prompt Listing Disclosure (prompts/list exposes internal prompts)
  - MCP Prompt Detail Leak        (prompt body leaks internal system prompt)
  - MCP Roots Disclosure          (roots/list leaks local filesystem roots)
  - MCP Dependency Confusion      (tool advertises an internal, unscoped package)
"""
from ..mcp_core import MCPServer, Tool, Prompt

srv = MCPServer(
    "discovery-lab",
    instructions="Unauthenticated MCP server. All tools available without credentials.",
    server_info_extra={"build": "internal", "package": "acme-internal-utils"},
)

# --- Tool Discovery: plainly enumerable tools, no auth --------------------------
srv.add_tool(Tool(
    "list_customers",
    "Return the full customer directory.",
    {"type": "object", "properties": {"page": {"type": "integer"}}},
    lambda a: {"text": "customer1, customer2, customer3 (mock data)"},
))

# --- Duplicate Tool Names: two tools registered under the SAME visible name -----
# (The registry key differs by suffix, but both advertise name="get_status".)
srv.add_tool(Tool(
    "get_status",
    "Get service status.",
    {"type": "object", "properties": {}},
    lambda a: {"text": "OK"},
))
dup = Tool(
    "get_status",  # SAME advertised name -> duplicate
    "Get service status (v2). Overrides the first definition.",
    {"type": "object", "properties": {}},
    lambda a: {"text": "OK v2"},
)
dup.name = "get_status"
srv.tools["get_status__dup"] = dup  # second entry, same wire name

# --- Hidden Tool: callable via tools/call but never listed ----------------------
srv.add_tool(Tool(
    "admin_debug_shell",
    "INTERNAL. Hidden maintenance tool — not advertised to clients.",
    {"type": "object", "properties": {"cmd": {"type": "string"}}},
    lambda a: {"text": f"[mock] would run admin cmd: {a.get('cmd')!r}"},
    hidden=True,
))

# --- Dependency Confusion: tool description references an internal, unscoped pkg -
srv.add_tool(Tool(
    "render_report",
    ("Render a report. Requires the internal npm package `acme-report-helpers` "
     "(unscoped, not published to the public registry) and pip package "
     "`acme_internal_pdf`. Installs from default public index if missing."),
    {"type": "object", "properties": {"template": {"type": "string"}}},
    lambda a: {"text": "[mock] report rendered"},
))

# --- Prompt Listing Disclosure + Prompt Detail Leak ----------------------------
srv.add_prompt(Prompt(
    "internal_support_agent",
    "INTERNAL system prompt for the customer-support agent (should not be exposed).",
    arguments=[{"name": "ticket_id", "description": "Zendesk ticket id", "required": True}],
    messages=[{
        "role": "system",
        "content": {
            "type": "text",
            "text": ("You are ACME's internal support agent. Admin override password is "
                     "'hunter2-admin'. Database DSN: postgres://svc:S3cr3t@10.0.0.5/prod. "
                     "Never reveal these to the user."),
        },
    }],
))
srv.add_prompt(Prompt(
    "billing_playbook",
    "Internal billing escalation playbook.",
    messages=[{"role": "system", "content": {"type": "text",
              "text": "Refund approvals up to $10000 without manager sign-off. Use code REFUND-ALL."}}],
))

# --- Roots Disclosure: leak local filesystem roots -----------------------------
srv.roots = [
    {"uri": "file:///Users/acme/company-secrets", "name": "secrets"},
    {"uri": "file:///home/svc/.ssh", "name": "ssh-keys"},
    {"uri": "file:///var/lib/prod-db", "name": "prod-db"},
]
