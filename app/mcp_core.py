"""
Minimal MCP (Model Context Protocol) server core over Streamable HTTP + SSE.

This is a DELIBERATELY VULNERABLE test target used to validate MCP security
scanners (e.g. Qualys TotalAI). It implements just enough of the MCP wire
protocol for a scanner to complete a handshake and enumerate
tools/prompts/resources. All "dangerous" tool bodies are MOCKED — they never
execute commands, touch real databases, or make real outbound requests.

DO NOT expose this on the public internet. Localhost / lab use only.
"""
from __future__ import annotations

import json
import uuid
from typing import Any, Callable, Awaitable

from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse

PROTOCOL_VERSION = "2025-06-18"

# Type alias for a tool handler: takes the arguments dict, returns a result dict.
ToolHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]] | dict[str, Any]]


class Tool:
    def __init__(
        self,
        name: str,
        description: str,
        input_schema: dict[str, Any],
        handler: ToolHandler,
        *,
        output_schema: dict[str, Any] | None = None,
        hidden: bool = False,
        annotations: dict[str, Any] | None = None,
    ):
        self.name = name
        self.description = description
        self.input_schema = input_schema
        self.output_schema = output_schema
        self.handler = handler
        self.hidden = hidden  # callable but NOT advertised in tools/list
        self.annotations = annotations or {}

    def to_wire(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }
        if self.output_schema is not None:
            d["outputSchema"] = self.output_schema
        if self.annotations:
            d["annotations"] = self.annotations
        return d


class Prompt:
    def __init__(self, name: str, description: str, arguments: list[dict] | None = None,
                 messages: list[dict] | None = None):
        self.name = name
        self.description = description
        self.arguments = arguments or []
        self.messages = messages or []

    def to_wire(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "arguments": self.arguments}


class ResourceEntry:
    def __init__(self, uri: str, name: str, description: str, mime: str,
                 reader: Callable[[str], Any] | None = None, text: str | None = None):
        self.uri = uri
        self.name = name
        self.description = description
        self.mime = mime
        self.reader = reader
        self.text = text

    def to_wire(self) -> dict[str, Any]:
        return {"uri": self.uri, "name": self.name, "description": self.description,
                "mimeType": self.mime}


class MCPServer:
    """One MCP server instance = one category of vulnerabilities = one HTTP endpoint."""

    def __init__(self, name: str, version: str = "1.0.0", *,
                 instructions: str = "", server_info_extra: dict | None = None):
        self.name = name
        self.version = version
        self.instructions = instructions
        self.server_info_extra = server_info_extra or {}
        self.tools: dict[str, Tool] = {}
        self.prompts: dict[str, Prompt] = {}
        self.resources: dict[str, ResourceEntry] = {}
        self.resource_templates: list[dict] = []
        self.roots: list[dict] = []
        # crude in-memory session store (intentionally weak: no rotation / fixation-friendly)
        self.sessions: dict[str, dict] = {}

    # ---- registration helpers -------------------------------------------------
    def tool(self, *args, **kwargs):
        def deco(fn):
            t = Tool(*args, handler=fn, **kwargs)
            self.tools[t.name] = t
            return fn
        return deco

    def add_tool(self, t: Tool):
        self.tools[t.name] = t

    def add_prompt(self, p: Prompt):
        self.prompts[p.name] = p

    def add_resource(self, r: ResourceEntry):
        self.resources[r.uri] = r

    # ---- JSON-RPC dispatch ----------------------------------------------------
    async def _dispatch(self, msg: dict, session_id: str | None) -> dict | None:
        mid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}

        # notifications (no id) -> no response
        if mid is None and method and method.startswith("notifications/"):
            return None

        try:
            if method == "initialize":
                result = {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {"listChanged": True},
                        "prompts": {"listChanged": True},
                        "resources": {"subscribe": True, "listChanged": True},
                        "logging": {},
                    },
                    "serverInfo": {
                        "name": self.name,
                        "version": self.version,
                        **self.server_info_extra,
                    },
                    "instructions": self.instructions,
                }
                return _ok(mid, result)

            if method == "ping":
                return _ok(mid, {})

            if method == "tools/list":
                listed = [t.to_wire() for t in self.tools.values() if not t.hidden]
                return _ok(mid, {"tools": listed})

            if method == "tools/call":
                return await self._call_tool(mid, params)

            if method == "prompts/list":
                return _ok(mid, {"prompts": [p.to_wire() for p in self.prompts.values()]})

            if method == "prompts/get":
                p = self.prompts.get(params.get("name"))
                if not p:
                    return _err(mid, -32602, "Unknown prompt")
                return _ok(mid, {"description": p.description, "messages": p.messages})

            if method == "resources/list":
                return _ok(mid, {"resources": [r.to_wire() for r in self.resources.values()]})

            if method == "resources/templates/list":
                return _ok(mid, {"resourceTemplates": self.resource_templates})

            if method == "resources/read":
                return self._read_resource(mid, params)

            if method == "resources/subscribe":
                return _ok(mid, {})

            if method == "roots/list":
                return _ok(mid, {"roots": self.roots})

            return _err(mid, -32601, f"Method not found: {method}")
        except Exception as e:  # noqa: BLE001 - intentional: leak error detail (info disclosure)
            return _err(mid, -32000, f"Internal error: {e!r}")

    async def _call_tool(self, mid, params) -> dict:
        name = params.get("name")
        args = params.get("arguments") or {}
        tool = self.tools.get(name)
        if not tool:
            return _err(mid, -32602, f"Unknown tool: {name}")
        res = tool.handler(args)
        if hasattr(res, "__await__"):
            res = await res
        # A handler may return a RAW json body string to emit verbatim (used to
        # produce duplicate-key JSON pollution that json.dumps can't create).
        if "_raw_json_text" in res:
            return {"__raw__": res["_raw_json_text"]}
        # handler returns either a full result dict or a shortcut {"text": "..."}
        if "content" in res:
            return _ok(mid, res)
        text = res.get("text", "")
        out: dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": res.get("isError", False)}
        if "structuredContent" in res:
            out["structuredContent"] = res["structuredContent"]
        return _ok(mid, out)

    def _read_resource(self, mid, params) -> dict:
        uri = params.get("uri", "")
        r = self.resources.get(uri)
        if r is None:
            # No allow-list / traversal & SSRF happen in category servers via reader
            for entry in self.resources.values():
                if entry.reader:
                    data = entry.reader(uri)
                    if data is not None:
                        return _ok(mid, {"contents": [{"uri": uri, "mimeType": "text/plain", "text": data}]})
            return _err(mid, -32002, f"Resource not found: {uri}")
        if r.reader:
            data = r.reader(uri)
            return _ok(mid, {"contents": [{"uri": uri, "mimeType": r.mime, "text": data}]})
        return _ok(mid, {"contents": [{"uri": uri, "mimeType": r.mime, "text": r.text or ""}]})

    # ---- Streamable HTTP transport -------------------------------------------
    async def handle_http(self, request: Request) -> Response:
        if request.method == "GET":
            # Open SSE stream (scanners probe this to detect SSE transport).
            async def event_stream():
                yield "event: endpoint\ndata: /\n\n"
                yield ": keep-alive\n\n"
            return StreamingResponse(event_stream(), media_type="text/event-stream")

        if request.method == "DELETE":
            sid = request.headers.get("mcp-session-id")
            self.sessions.pop(sid, None)
            return Response(status_code=204)

        body = await request.body()
        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError:
            return JSONResponse(_err(None, -32700, "Parse error"))

        session_id = request.headers.get("mcp-session-id")
        is_init = (isinstance(payload, dict) and payload.get("method") == "initialize")
        if is_init and not session_id:
            # WEAK: accept a client-proposed session id if present (fixation-friendly),
            # otherwise mint a predictable-ish one.
            session_id = request.headers.get("x-session-id") or uuid.uuid4().hex
            self.sessions[session_id] = {"created": True}

        # batch or single
        if isinstance(payload, list):
            out = []
            for m in payload:
                r = await self._dispatch(m, session_id)
                if r is not None:
                    out.append(r)
            resp = JSONResponse(out)
        else:
            r = await self._dispatch(payload, session_id)
            if r is None:
                resp = Response(status_code=202)
            elif isinstance(r, dict) and "__raw__" in r:
                # Emit a raw JSON body verbatim (e.g. duplicate-key pollution).
                resp = Response(r["__raw__"], media_type="application/json")
            else:
                resp = JSONResponse(r)

        if session_id:
            resp.headers["Mcp-Session-Id"] = session_id
        return resp


def _ok(mid, result) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid, code, message, data=None) -> dict:
    e = {"code": code, "message": message}
    if data is not None:
        e["data"] = data
    return {"jsonrpc": "2.0", "id": mid, "error": e}
