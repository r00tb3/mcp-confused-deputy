#!/usr/bin/env python3
"""Minimal MCP client used as the demo driver for the broker.

The client speaks JSON-RPC 2.0 over streamable HTTP: it initializes a session,
sends ``notifications/initialized``, lists tools, and calls them. Both plain
JSON and SSE-framed responses are accepted.

This is also importable:

    from agent import MCPClient
    client = MCPClient("http://127.0.0.1:8765")
    client.initialize()
    print(client.list_tools())

Standard library only. Python 3.10+.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any

PROTOCOL_VERSION = "2025-06-18"
DEFAULT_BASE_URL = "http://127.0.0.1:8765"


class TransportError(RuntimeError):
    """The HTTP exchange failed before a JSON-RPC response was available."""


class RPCError(RuntimeError):
    """The server returned a JSON-RPC error object."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(f"JSON-RPC error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data


def parse_sse(body: str) -> dict[str, Any]:
    """Parse one SSE response and return the JSON payload of its message event.

    The broker sends exactly one event per response, but this accepts multiple
    events and returns the first one carrying a JSON-RPC object.
    """

    events: list[dict[str, Any]] = []
    data_lines: list[str] = []
    event_name = "message"
    for line in body.splitlines():
        if line == "":
            if data_lines:
                events.append(
                    {"event": event_name, "data": "\n".join(data_lines)}
                )
            data_lines = []
            event_name = "message"
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if field == "event":
            event_name = value
        elif field == "data":
            data_lines.append(value)
    if data_lines:
        events.append({"event": event_name, "data": "\n".join(data_lines)})

    for event in events:
        if event["event"] == "message":
            try:
                payload = json.loads(event["data"])
            except json.JSONDecodeError as exc:
                raise TransportError(f"invalid SSE JSON: {exc}") from exc
            if isinstance(payload, dict):
                return payload
    raise TransportError("SSE response contained no message event")


class MCPClient:
    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        caller: str = "lab-agent",
        elevation_grant: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.mcp_url = f"{self.base_url}/mcp"
        self.caller = caller
        self.elevation_grant = elevation_grant
        self.timeout = timeout
        self.session_id: str | None = None
        self.server_info: dict[str, Any] | None = None
        self.protocol_version: str | None = None
        self._next_id = 0

    # -------------------------------------------------------------- transport

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "X-Caller": self.caller,
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.protocol_version:
            headers["MCP-Protocol-Version"] = self.protocol_version
        if self.elevation_grant:
            headers["X-Elevation-Grant"] = self.elevation_grant
        if extra:
            headers.update(extra)
        return headers

    def post(
        self,
        payload: dict[str, Any],
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any] | None]:
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.mcp_url,
            data=body,
            headers=self._headers(extra_headers),
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                status = response.status
                content_type = response.headers.get("Content-Type", "")
                raw = response.read().decode("utf-8")
                session = response.headers.get("Mcp-Session-Id")
                if session:
                    self.session_id = session
        except urllib.error.HTTPError as exc:
            status = exc.code
            content_type = exc.headers.get("Content-Type", "")
            raw = exc.read().decode("utf-8", errors="replace")
        except urllib.error.URLError as exc:
            raise TransportError(f"cannot reach {self.mcp_url}: {exc.reason}") from exc

        if not raw.strip():
            return status, None
        if "text/event-stream" in content_type:
            return status, parse_sse(raw)
        try:
            return status, json.loads(raw)
        except json.JSONDecodeError as exc:
            raise TransportError(
                f"non-JSON response ({content_type or 'no content type'}): {raw[:200]}"
            ) from exc

    def request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        self._next_id += 1
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": self._next_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params
        status, response = self.post(payload, extra_headers)
        if response is None:
            raise TransportError(f"empty response to {method} (HTTP {status})")
        if "error" in response:
            error = response["error"]
            raise RPCError(
                int(error.get("code", -32603)),
                str(error.get("message", "unknown error")),
                error.get("data"),
            )
        if "result" not in response:
            raise TransportError(f"response to {method} has no result")
        return response["result"]

    def notify(self, method: str, params: dict[str, Any] | None = None) -> int:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        status, _ = self.post(payload)
        return status

    # ------------------------------------------------------------------- MCP

    def initialize(self) -> dict[str, Any]:
        result = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "lab-agent", "version": "1.0.0"},
            },
        )
        self.server_info = result.get("serverInfo")
        self.protocol_version = result.get("protocolVersion")
        return result

    def initialized(self) -> int:
        return self.notify("notifications/initialized")

    def list_tools(self) -> list[dict[str, Any]]:
        return list(self.request("tools/list").get("tools", []))

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "tools/call",
            {"name": name, "arguments": arguments},
            extra_headers=extra_headers,
        )

    def read_resource(self, path: str) -> str:
        result = self.call_tool("fs.read", {"path": path})
        return result["content"][0]["text"]

    def close(self) -> None:
        # HTTP is stateless here; the broker keeps no per-session state that
        # needs releasing. Kept for symmetry with other MCP clients.
        self.session_id = None


def demo(base_url: str, grant: str | None, smuggled: bool) -> int:
    client = MCPClient(base_url, elevation_grant=grant)
    print(f"[agent] connecting to {client.mcp_url}")
    init = client.initialize()
    print(
        "[agent] initialized:",
        json.dumps(
            {
                "protocolVersion": init.get("protocolVersion"),
                "serverInfo": init.get("serverInfo"),
                "capabilities": init.get("capabilities"),
            }
        ),
    )
    status = client.initialized()
    print(f"[agent] notifications/initialized -> HTTP {status}")

    tools = client.list_tools()
    print(f"[agent] tools/list -> {[tool['name'] for tool in tools]}")
    for tool in tools:
        print(f"         {tool['name']}: {tool['description']}")

    try:
        text = client.read_resource("welcome.md")
        print(f"[agent] fs.read welcome.md -> {len(text)} bytes")
    except (RPCError, TransportError) as exc:
        print(f"[agent] fs.read welcome.md failed: {exc}")

    arguments: dict[str, Any] = {
        "path": "notes/scratch.md",
        "content": "written by lab/agent.py\n",
    }
    if smuggled:
        arguments["escalate"] = True
        arguments["escalation_note"] = "requested by the demo agent"
    try:
        result = client.call_tool("fs.write", arguments)
        print(
            "[agent] fs.write notes/scratch.md ->",
            json.dumps(result, indent=2),
        )
    except RPCError as exc:
        print(f"[agent] fs.write rejected: {exc}")
        print(f"        data: {json.dumps(exc.data)}")

    print("[agent] inspect the causal audit trail at", f"{base_url}/audit")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="MCP demo client.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--grant", default=None, help="X-Elevation-Grant token")
    parser.add_argument(
        "--smuggle",
        action="store_true",
        help="add the undeclared escalate argument to a normal fs.write call",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return demo(args.base_url, args.grant, args.smuggle)
    except (RPCError, TransportError) as exc:
        print(f"[agent] error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
