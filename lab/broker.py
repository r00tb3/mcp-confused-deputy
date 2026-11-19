#!/usr/bin/env python3
"""A small, deliberately vulnerable MCP broker.

The broker speaks MCP over streamable HTTP at POST /mcp. It exposes two
workspace file tools and keeps one privileged action (service.reload) out of
tools/list. In ``vuln`` mode the privileged action can be requested with an
undeclared ``escalate`` argument on a normal file tool call. In ``clean`` mode
the same request is rejected before any tool runs unless the caller presents
``X-Elevation-Grant: <token>``.

Standard library only. Python 3.10+.
"""

from __future__ import annotations

import argparse
import copy
import hmac
import json
import os
import re
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18")
SERVER_NAME = "mcp-confused-deputy-broker"
SERVER_VERSION = "1.0.0"
DEFAULT_GRANT_TOKEN = "lab-elevation-grant"
MAX_BODY_BYTES = 2 * 1024 * 1024

FS_READ_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "description": "Path relative to the workspace root.",
        }
    },
    "required": ["path"],
    # The permissive schema is part of the fixture: undeclared fields survive
    # client-side validation and reach the dispatcher.
    "additionalProperties": True,
}

FS_WRITE_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "description": "Path relative to the workspace root.",
        },
        "content": {
            "type": "string",
            "description": "UTF-8 text to write.",
        },
    },
    "required": ["path", "content"],
    "additionalProperties": True,
}

TOOLS = [
    {
        "name": "fs.read",
        "description": "Read a UTF-8 text file from the shared workspace.",
        "inputSchema": FS_READ_SCHEMA,
    },
    {
        "name": "fs.write",
        "description": "Write a UTF-8 text file inside the shared workspace.",
        "inputSchema": FS_WRITE_SCHEMA,
    },
]

KNOWN_TOOLS = {"fs.read", "fs.write"}
DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


class SandboxError(ValueError):
    """Raised when a requested path is not safely inside the workspace."""


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def rpc_result(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def rpc_error(
    request_id: Any, code: int, message: str, data: Any | None = None
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def tool_ok(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": False}


def tool_error(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": True}


def wants_sse(accept_header: str | None) -> bool:
    """Pick SSE when the client accepts it, otherwise JSON.

    A q-value of zero disables a media type. ``application/json, text/event-stream``
    selects SSE because both have equal weight and the client explicitly listed
    the event stream. ``*/*`` falls back to JSON.
    """

    if not accept_header:
        return False

    sse_q = 0.0
    json_q = 0.0
    for item in accept_header.split(","):
        parts = [p.strip() for p in item.split(";") if p.strip()]
        if not parts:
            continue
        media = parts[0].lower()
        q = 1.0
        for param in parts[1:]:
            if param.lower().startswith("q="):
                try:
                    q = float(param[2:].strip())
                except ValueError:
                    q = 0.0
        if media == "text/event-stream":
            sse_q = max(sse_q, q)
        elif media in ("application/json", "application/*"):
            json_q = max(json_q, q)
        elif media == "*/*" and json_q == 0.0:
            json_q = q

    return sse_q > 0.0 and sse_q >= json_q


class Broker:
    """Mode-specific request handling plus the in-memory audit log."""

    def __init__(
        self,
        mode: str,
        workspace: Path,
        state_dir: Path,
        grant_token: str,
    ) -> None:
        self.mode = mode
        self.workspace = Path(workspace).resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.state_dir = Path(state_dir).resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.grant_token = grant_token

        self._lock = threading.RLock()
        self._audit: list[dict[str, Any]] = []
        self._request_counter = 0
        self._session_counter = 0
        self._service_generation = 0

    # ------------------------------------------------------------------ audit

    def next_request_id(self) -> str:
        with self._lock:
            self._request_counter += 1
            return f"req-{self._request_counter:06d}"

    def record(
        self,
        request_id: str,
        caller: str,
        tool: str,
        params: dict[str, Any],
        side_effects: list[dict[str, Any]],
    ) -> None:
        entry = {
            "req_id": request_id,
            "ts": utc_now(),
            "caller": caller,
            "tool": tool,
            "params": copy.deepcopy(params),
            "side_effects": copy.deepcopy(side_effects),
        }
        with self._lock:
            self._audit.append(entry)

    def audit_snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._audit)

    def health(self) -> dict[str, Any]:
        with self._lock:
            return {
                "ok": True,
                "mode": self.mode,
                "service_generation": self._service_generation,
                "audit_entries": len(self._audit),
            }

    def next_session_id(self) -> str:
        with self._lock:
            self._session_counter += 1
            return f"sess-{self._session_counter:06d}"

    # ------------------------------------------------------------------ paths

    def resolve_path(self, raw_path: str) -> Path:
        if not isinstance(raw_path, str):
            raise SandboxError("path must be a string")
        raw_path = raw_path.strip()
        if not raw_path:
            raise SandboxError("path is empty")
        if "\x00" in raw_path:
            raise SandboxError("path contains a NUL byte")

        normalized = raw_path.replace("\\", "/")
        if DRIVE_PREFIX.match(normalized):
            raise SandboxError(f"path escapes workspace: {raw_path}")
        if Path(normalized).is_absolute():
            raise SandboxError(f"path escapes workspace: {raw_path}")

        candidate = (self.workspace / normalized).resolve()
        try:
            candidate.relative_to(self.workspace)
        except ValueError:
            raise SandboxError(f"path escapes workspace: {raw_path}") from None
        return candidate

    def read_file(self, raw_path: str) -> tuple[str | None, str | None]:
        try:
            path = self.resolve_path(raw_path)
        except SandboxError as exc:
            return None, str(exc)
        if not path.is_file():
            return None, f"not a file: {raw_path}"
        try:
            return path.read_text(encoding="utf-8"), None
        except UnicodeDecodeError:
            return None, f"not valid UTF-8: {raw_path}"
        except OSError as exc:
            return None, f"read failed: {exc}"

    def write_file(self, raw_path: str, content: str) -> tuple[str | None, str | None]:
        try:
            path = self.resolve_path(raw_path)
        except SandboxError as exc:
            return None, str(exc)
        if path == self.workspace:
            return None, "path is the workspace root"
        if path.exists() and path.is_dir():
            return None, f"path is a directory: {raw_path}"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        except OSError as exc:
            return None, f"write failed: {exc}"
        return f"wrote {len(content.encode('utf-8'))} bytes to {raw_path}", None

    # -------------------------------------------------------------- privilege

    def grant_is_valid(self, header_value: str | None) -> bool:
        if header_value is None:
            return False
        try:
            presented = header_value.strip().encode("utf-8")
        except UnicodeEncodeError:
            return False
        return hmac.compare_digest(presented, self.grant_token.encode("utf-8"))

    def reload_service(self, request_id: str, caller: str) -> tuple[bool, str]:
        with self._lock:
            self._service_generation += 1
            generation = self._service_generation
            state = {
                "generation": generation,
                "last_reload": utc_now(),
                "req_id": request_id,
                "caller": caller,
            }
            try:
                state_file = self.state_dir / "service-state.json"
                temporary = state_file.with_suffix(".json.tmp")
                temporary.write_text(
                    json.dumps(state, indent=2) + "\n", encoding="utf-8"
                )
                os.replace(temporary, state_file)
                return (
                    True,
                    f"reloaded service configuration (generation {generation})",
                )
            except OSError as exc:
                return False, f"service reload failed: {exc}"

    # ---------------------------------------------------------------- routing

    def handle(
        self, payload: Any, headers: Any
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Handle one decoded JSON-RPC payload.

        Returns ``(response, new_session_id)``. ``response`` is ``None`` for a
        notification, which the HTTP layer answers with 202 Accepted.
        """

        if not isinstance(payload, dict):
            if isinstance(payload, list):
                return (
                    rpc_error(
                        None,
                        -32600,
                        "Invalid Request",
                        {"detail": "batch requests are not supported"},
                    ),
                    None,
                )
            return rpc_error(None, -32600, "Invalid Request"), None

        request_id = payload.get("id") if "id" in payload else None
        if payload.get("jsonrpc") != "2.0":
            return rpc_error(request_id, -32600, "Invalid Request"), None
        if "id" in payload and not (
            request_id is None
            or isinstance(request_id, str)
            or (isinstance(request_id, (int, float)) and not isinstance(request_id, bool))
        ):
            return rpc_error(None, -32600, "Invalid Request"), None

        method = payload.get("method")
        if not isinstance(method, str):
            return rpc_error(request_id, -32600, "Invalid Request"), None

        is_notification = "id" not in payload
        params = payload.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            if is_notification:
                return None, None
            return rpc_error(request_id, -32602, "Invalid params"), None

        if is_notification:
            # MCP only needs notifications/initialized from this client. Any
            # other notification is accepted silently, per JSON-RPC.
            return None, None

        try:
            if method == "initialize":
                return self.handle_initialize(request_id, params)
            if method in ("notifications/initialized", "notifications/cancelled"):
                return rpc_result(request_id, {}), None
            if method == "ping":
                return rpc_result(request_id, {}), None
            if method == "tools/list":
                return rpc_result(request_id, {"tools": copy.deepcopy(TOOLS)}), None
            if method == "tools/call":
                return self.handle_tools_call(request_id, params, headers), None
            if method == "debug.raise":
                # Small deterministic hook used by the test suite to exercise
                # the -32603 branch. Not part of the advertised MCP surface.
                raise RuntimeError("intentional debug failure")
            return rpc_error(request_id, -32601, "Method not found"), None
        except Exception as exc:  # noqa: BLE001 - JSON-RPC boundary
            return (
                rpc_error(
                    request_id,
                    -32603,
                    "Internal error",
                    {"detail": str(exc)},
                ),
                None,
            )

    def handle_initialize(
        self, request_id: Any, params: dict[str, Any]
    ) -> tuple[dict[str, Any], str]:
        requested = params.get("protocolVersion")
        version = (
            requested
            if requested in SUPPORTED_PROTOCOL_VERSIONS
            else PROTOCOL_VERSION
        )
        result = {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": (
                "Workspace file tools. Paths are relative to the workspace root. "
                "Service reload is an operator action."
            ),
        }
        return rpc_result(request_id, result), self.next_session_id()

    def handle_tools_call(
        self, request_id: Any, params: dict[str, Any], headers: Any
    ) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not name:
            return rpc_error(request_id, -32602, "Invalid params", {"field": "name"})
        if not isinstance(arguments, dict):
            return rpc_error(
                request_id, -32602, "Invalid params", {"field": "arguments"}
            )
        if name not in KNOWN_TOOLS:
            return rpc_error(
                request_id, -32602, "Invalid params", {"field": "name", "value": name}
            )

        if "escalate" in arguments and not isinstance(arguments["escalate"], bool):
            return rpc_error(
                request_id, -32602, "Invalid params", {"field": "escalate"}
            )
        if "escalation_note" in arguments and not isinstance(
            arguments["escalation_note"], str
        ):
            return rpc_error(
                request_id, -32602, "Invalid params", {"field": "escalation_note"}
            )

        if name == "fs.read" and not isinstance(arguments.get("path"), str):
            return rpc_error(request_id, -32602, "Invalid params", {"field": "path"})
        if name == "fs.write":
            if not isinstance(arguments.get("path"), str):
                return rpc_error(
                    request_id, -32602, "Invalid params", {"field": "path"}
                )
            if not isinstance(arguments.get("content"), str):
                return rpc_error(
                    request_id, -32602, "Invalid params", {"field": "content"}
                )

        escalate = arguments.get("escalate") is True
        caller = self.caller_from(headers)
        request_key = self.next_request_id()
        grant_header = headers.get("X-Elevation-Grant")

        # The clean-mode gate runs before any path resolution, file I/O, or
        # service work. A rejected request still gets an audit row, but that row
        # has no side effects because nothing executed.
        if (
            self.mode == "clean"
            and escalate
            and not self.grant_is_valid(grant_header)
        ):
            self.record(request_key, caller, name, arguments, [])
            return rpc_error(
                request_id,
                -32002,
                "Elevation required",
                {
                    "mode": self.mode,
                    "tool": name,
                    "header": "X-Elevation-Grant",
                },
            )

        side_effects: list[dict[str, Any]] = []
        if name == "fs.read":
            text, error = self.read_file(arguments["path"])
            if error is not None:
                self.record(request_key, caller, name, arguments, [])
                return rpc_result(request_id, tool_error(error))
            result = tool_ok(text or "")
        else:
            text, error = self.write_file(
                arguments["path"], arguments["content"]
            )
            if error is not None:
                self.record(request_key, caller, name, arguments, [])
                return rpc_result(request_id, tool_error(error))
            result = tool_ok(text or "")

        if escalate:
            ok, detail = self.reload_service(request_key, caller)
            side_effects.append(
                {"action": "service.reload", "ok": ok, "detail": detail}
            )

        self.record(request_key, caller, name, arguments, side_effects)
        return rpc_result(request_id, result)

    @staticmethod
    def caller_from(headers: Any) -> str:
        caller = headers.get("X-Caller") or "anonymous"
        caller = caller.strip()
        if not caller:
            caller = "anonymous"
        return caller[:80]


class BrokerHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        broker: Broker,
    ) -> None:
        self.broker = broker
        super().__init__(server_address, handler)


class MCPHandler(BaseHTTPRequestHandler):
    server_version = "ConfusedDeputyBroker/1.0"
    protocol_version = "HTTP/1.1"

    @property
    def broker(self) -> Broker:
        return self.server.broker  # type: ignore[attr-defined]

    # ---------------------------------------------------------------- helpers

    def send_body(
        self,
        body: bytes,
        status: int = 200,
        content_type: str = "application/json",
        session_id: str | None = None,
    ) -> None:
        self.send_response(status)
        if body:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        if session_id:
            self.send_header("Mcp-Session-Id", session_id)
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)
        self.close_connection = True

    def send_json(
        self,
        data: Any,
        status: int = 200,
        session_id: str | None = None,
    ) -> None:
        body = json.dumps(data, separators=(",", ":")).encode("utf-8")
        self.send_body(body, status, "application/json", session_id)

    def send_rpc(
        self, response: dict[str, Any], session_id: str | None = None
    ) -> None:
        accept = self.headers.get("Accept")
        if wants_sse(accept):
            encoded = json.dumps(response, separators=(",", ":"))
            body = f"event: message\ndata: {encoded}\n\n".encode("utf-8")
            self.send_body(
                body, 200, "text/event-stream", session_id=session_id
            )
        else:
            self.send_json(response, 200, session_id)

    # ----------------------------------------------------------------- verbs

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if urlparse(self.path).path != "/mcp":
            self.send_json({"error": "not found"}, 404)
            return

        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length or "0")
        except ValueError:
            length = -1
        if length < 0:
            self.send_rpc(rpc_error(None, -32700, "Parse error"))
            return
        if length > MAX_BODY_BYTES:
            self.send_json({"error": "request body too large"}, 413)
            return

        raw = self.rfile.read(length) if length else b""
        try:
            text = raw.decode("utf-8")
            payload = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_rpc(rpc_error(None, -32700, "Parse error"))
            return

        response, session_id = self.broker.handle(payload, self.headers)
        if response is None:
            self.send_body(b"", 202)
        else:
            self.send_rpc(response, session_id)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlparse(self.path).path
        if path == "/audit":
            self.send_json(self.broker.audit_snapshot())
            return
        if path == "/health":
            self.send_json(self.broker.health())
            return
        if path == "/":
            self.send_json(
                {
                    "name": SERVER_NAME,
                    "mode": self.broker.mode,
                    "endpoints": {
                        "mcp": "POST /mcp",
                        "audit": "GET /audit",
                        "health": "GET /health",
                    },
                }
            )
            return
        if path == "/mcp":
            body = json.dumps({"error": "use POST"}).encode("utf-8")
            self.send_response(405)
            self.send_header("Content-Type", "application/json")
            self.send_header("Allow", "POST")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True
            return
        self.send_json({"error": "not found"}, 404)

    def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self.send_body(b"", 204)

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep the lab output readable. The verifier parses the startup line.
        return


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Deliberately vulnerable MCP confused-deputy broker."
    )
    parser.add_argument(
        "--mode",
        choices=("vuln", "clean"),
        default="vuln",
        help="vuln honours smuggled escalation; clean requires an elevation grant",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--port", type=int, default=8765, help="use 0 for an ephemeral port"
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=here / "workspace",
        help="sandbox root for fs.read/fs.write",
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=here / "state",
        help="where the service state file is written",
    )
    parser.add_argument(
        "--grant-token",
        default=DEFAULT_GRANT_TOKEN,
        help="token accepted in X-Elevation-Grant in clean mode",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    broker = Broker(
        mode=args.mode,
        workspace=args.workspace,
        state_dir=args.state_dir,
        grant_token=args.grant_token,
    )
    server = BrokerHTTPServer((args.host, args.port), MCPHandler, broker)
    port = server.server_address[1]
    display_host = (
        "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    )
    print(
        f"broker listening on http://{display_host}:{port} (mode={args.mode})",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
