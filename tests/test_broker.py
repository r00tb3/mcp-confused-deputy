#!/usr/bin/env python3
"""End-to-end tests for the confused-deputy broker.

Each test class spawns a real broker process and talks to it over HTTP, so the
tests exercise the same path a client would. Run with:

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
LAB = REPO / "lab"
sys.path.insert(0, str(LAB))

from agent import MCPClient, RPCError, parse_sse  # noqa: E402

GRANT = "test-grant-token"


def start_broker(mode: str, workspace: Path, state_dir: Path) -> tuple[subprocess.Popen[str], str]:
    process = subprocess.Popen(
        [
            sys.executable,
            str(LAB / "broker.py"),
            "--mode",
            mode,
            "--port",
            "0",
            "--workspace",
            str(workspace),
            "--state-dir",
            str(state_dir),
            "--grant-token",
            GRANT,
        ],
        cwd=str(REPO),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.time() + 15
    while time.time() < deadline:
        line = process.stdout.readline() if process.stdout else ""
        if "broker listening on " in line:
            return process, line.strip().split("broker listening on ")[1].split(" ")[0]
        if process.poll() is not None:
            stderr = process.stderr.read() if process.stderr else ""
            raise RuntimeError(f"broker died: {stderr}")
        time.sleep(0.05)
    process.kill()
    raise RuntimeError("broker did not start")


def post(
    base_url: str,
    payload: Any,
    accept: str = "application/json",
    headers: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    request_headers = {"Content-Type": "application/json", "Accept": accept}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(
        f"{base_url}/mcp",
        data=json.dumps(payload).encode("utf-8"),
        headers=request_headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return (
                response.status,
                response.headers.get("Content-Type", ""),
                response.read().decode("utf-8"),
            )
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", ""), exc.read().decode("utf-8")


def post_raw(base_url: str, raw: bytes, accept: str = "application/json") -> tuple[int, str, str]:
    request = urllib.request.Request(
        f"{base_url}/mcp",
        data=raw,
        headers={"Content-Type": "application/json", "Accept": accept},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.headers.get("Content-Type", ""), response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", ""), exc.read().decode()


class BrokerTestCase(unittest.TestCase):
    mode = "vuln"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="mcp-test-")
        root = Path(self.temporary.name)
        self.workspace = root / "workspace"
        shutil.copytree(LAB / "workspace", self.workspace)
        self.state_dir = root / "state"
        self.state_dir.mkdir()
        self.process, self.base_url = start_broker(self.mode, self.workspace, self.state_dir)
        self.client = MCPClient(self.base_url, caller="test-agent")
        self.client.initialize()
        self.client.initialized()

    def tearDown(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        if self.process.stdout:
            self.process.stdout.close()
        if self.process.stderr:
            self.process.stderr.close()
        self.temporary.cleanup()

    def audit(self) -> list[dict[str, Any]]:
        with urllib.request.urlopen(f"{self.base_url}/audit", timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))

    def generation(self) -> int | None:
        state_file = self.state_dir / "service-state.json"
        if not state_file.exists():
            return None
        return json.loads(state_file.read_text(encoding="utf-8"))["generation"]


class ProtocolTests(BrokerTestCase):
    def test_initialize_shape(self) -> None:
        client = MCPClient(self.base_url)
        result = client.initialize()
        self.assertIn("protocolVersion", result)
        self.assertIn("tools", result["capabilities"])
        self.assertIn("name", result["serverInfo"])

    def test_notification_accepted(self) -> None:
        status, _, body = post(
            self.base_url,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        self.assertEqual(status, 202)
        self.assertEqual(body, "")

    def test_tools_list_excludes_privileged_action(self) -> None:
        names = [tool["name"] for tool in self.client.list_tools()]
        self.assertEqual(names, ["fs.read", "fs.write"])
        self.assertNotIn("service.reload", names)

    def test_privileged_tool_not_callable_by_name(self) -> None:
        with self.assertRaises(RPCError) as caught:
            self.client.call_tool("service.reload", {})
        self.assertEqual(caught.exception.code, -32602)
        self.assertIsNone(self.generation())

    def test_parse_error(self) -> None:
        status, _, body = post_raw(self.base_url, b"{not json")
        self.assertEqual(status, 200)
        response = json.loads(body)
        self.assertEqual(response["error"]["code"], -32700)

    def test_invalid_request(self) -> None:
        status, _, body = post(self.base_url, {"jsonrpc": "2.0", "id": 9})
        response = json.loads(body)
        self.assertEqual(response["error"]["code"], -32600)

    def test_method_not_found(self) -> None:
        status, _, body = post(
            self.base_url,
            {"jsonrpc": "2.0", "id": 9, "method": "resources/list"},
        )
        response = json.loads(body)
        self.assertEqual(response["error"]["code"], -32601)

    def test_invalid_params(self) -> None:
        status, _, body = post(
            self.base_url,
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": "fs.read", "arguments": {}},
            },
        )
        response = json.loads(body)
        self.assertEqual(response["error"]["code"], -32602)

    def test_internal_error(self) -> None:
        status, _, body = post(
            self.base_url,
            {"jsonrpc": "2.0", "id": 9, "method": "debug.raise"},
        )
        response = json.loads(body)
        self.assertEqual(response["error"]["code"], -32603)

    def test_sse_framing(self) -> None:
        status, content_type, body = post(
            self.base_url,
            {"jsonrpc": "2.0", "id": 4, "method": "tools/list"},
            accept="application/json, text/event-stream",
        )
        self.assertEqual(status, 200)
        self.assertIn("text/event-stream", content_type)
        self.assertTrue(body.startswith("event: message\ndata: "))
        self.assertTrue(body.endswith("\n\n"))
        payload = parse_sse(body)
        self.assertEqual(payload["id"], 4)
        self.assertIn("tools", payload["result"])

    def test_json_when_sse_not_accepted(self) -> None:
        status, content_type, body = post(
            self.base_url,
            {"jsonrpc": "2.0", "id": 5, "method": "tools/list"},
            accept="application/json",
        )
        self.assertIn("application/json", content_type)
        self.assertEqual(json.loads(body)["id"], 5)

    def test_sse_q_zero_falls_back_to_json(self) -> None:
        status, content_type, _ = post(
            self.base_url,
            {"jsonrpc": "2.0", "id": 6, "method": "tools/list"},
            accept="application/json, text/event-stream;q=0",
        )
        self.assertIn("application/json", content_type)

    def test_tool_result_shape(self) -> None:
        result = self.client.call_tool("fs.read", {"path": "welcome.md"})
        self.assertIs(result["isError"], False)
        self.assertEqual(result["content"][0]["type"], "text")
        self.assertIn("shared workspace", result["content"][0]["text"])

    def test_read_missing_file_is_tool_error(self) -> None:
        result = self.client.call_tool("fs.read", {"path": "nope.txt"})
        self.assertIs(result["isError"], True)


class TraversalTests(BrokerTestCase):
    def test_relative_traversal(self) -> None:
        result = self.client.call_tool("fs.read", {"path": "../../broker.py"})
        self.assertIs(result["isError"], True)
        self.assertIn("escapes workspace", result["content"][0]["text"])

    def test_deep_traversal(self) -> None:
        result = self.client.call_tool("fs.read", {"path": "notes/../../agent.py"})
        self.assertIs(result["isError"], True)

    def test_absolute_path(self) -> None:
        result = self.client.call_tool("fs.read", {"path": "/etc/hostname"})
        self.assertIs(result["isError"], True)

    def test_windows_style_path(self) -> None:
        result = self.client.call_tool("fs.read", {"path": "C:notes.md"})
        self.assertIs(result["isError"], True)

    def test_backslash_traversal(self) -> None:
        result = self.client.call_tool("fs.read", {"path": "..\\..\\broker.py"})
        self.assertIs(result["isError"], True)
        self.assertIn("escapes workspace", result["content"][0]["text"])

    def test_write_traversal(self) -> None:
        result = self.client.call_tool(
            "fs.write", {"path": "../escaped.txt", "content": "x"}
        )
        self.assertIs(result["isError"], True)
        self.assertFalse((self.workspace.parent / "escaped.txt").exists())

    def test_write_inside_workspace(self) -> None:
        result = self.client.call_tool(
            "fs.write", {"path": "notes/new.md", "content": "hello"}
        )
        self.assertIs(result["isError"], False)
        self.assertEqual(
            (self.workspace / "notes" / "new.md").read_text(encoding="utf-8"),
            "hello",
        )


class VulnModeTests(BrokerTestCase):
    mode = "vuln"

    def test_smuggled_escalation_executes(self) -> None:
        result = self.client.call_tool(
            "fs.write",
            {
                "path": "notes/scratch.md",
                "content": "escalated\n",
                "escalate": True,
                "escalation_note": "not in schema",
            },
        )
        self.assertIs(result["isError"], False)
        self.assertEqual(self.generation(), 1)

    def test_side_effect_is_causal(self) -> None:
        self.client.call_tool(
            "fs.write",
            {"path": "notes/scratch.md", "content": "x", "escalate": True},
        )
        audit = self.audit()
        reload_rows = [entry for entry in audit if entry["tool"] == "service.reload"]
        self.assertEqual(reload_rows, [])
        escalated = [
            entry
            for entry in audit
            if entry["params"].get("escalate") is True
        ]
        self.assertEqual(len(escalated), 1)
        effects = escalated[0]["side_effects"]
        self.assertEqual(len(effects), 1)
        self.assertEqual(effects[0]["action"], "service.reload")
        self.assertIs(effects[0]["ok"], True)

    def test_read_can_escalate_too(self) -> None:
        result = self.client.call_tool(
            "fs.read", {"path": "welcome.md", "escalate": True}
        )
        self.assertIs(result["isError"], False)
        self.assertEqual(self.generation(), 1)

    def test_no_escalate_no_side_effect(self) -> None:
        self.client.call_tool("fs.read", {"path": "welcome.md"})
        self.assertIsNone(self.generation())
        self.assertEqual(self.audit()[-1]["side_effects"], [])

    def test_traversal_does_not_escalate(self) -> None:
        self.client.call_tool(
            "fs.read", {"path": "../agent.py", "escalate": True}
        )
        self.assertIsNone(self.generation())


class CleanModeTests(BrokerTestCase):
    mode = "clean"

    def test_smuggled_escalation_rejected(self) -> None:
        with self.assertRaises(RPCError) as caught:
            self.client.call_tool(
                "fs.write",
                {"path": "notes/scratch.md", "content": "x", "escalate": True},
            )
        self.assertEqual(caught.exception.code, -32002)
        self.assertIsNone(self.generation())

    def test_rejection_keeps_jsonrpc_id(self) -> None:
        status, _, body = post(
            self.base_url,
            {
                "jsonrpc": "2.0",
                "id": "call-77",
                "method": "tools/call",
                "params": {
                    "name": "fs.write",
                    "arguments": {
                        "path": "notes/scratch.md",
                        "content": "x",
                        "escalate": True,
                    },
                },
            },
        )
        response = json.loads(body)
        self.assertEqual(response["id"], "call-77")
        self.assertEqual(response["error"]["code"], -32002)
        self.assertEqual(self.audit()[-1]["req_id"], "req-000001")

    def test_nothing_ran_on_rejection(self) -> None:
        original = (self.workspace / "notes" / "scratch.md").read_text(encoding="utf-8")
        with self.assertRaises(RPCError):
            self.client.call_tool(
                "fs.write",
                {"path": "notes/scratch.md", "content": "changed", "escalate": True},
            )
        self.assertEqual(
            (self.workspace / "notes" / "scratch.md").read_text(encoding="utf-8"),
            original,
        )
        rejected = self.audit()[-1]
        self.assertEqual(rejected["tool"], "fs.write")
        self.assertEqual(rejected["side_effects"], [])

    def test_grant_allows_escalation(self) -> None:
        granted = MCPClient(self.base_url, elevation_grant=GRANT)
        granted.initialize()
        granted.initialized()
        result = granted.call_tool(
            "fs.write",
            {"path": "notes/scratch.md", "content": "x", "escalate": True},
        )
        self.assertIs(result["isError"], False)
        self.assertEqual(self.generation(), 1)
        effects = self.audit()[-1]["side_effects"]
        self.assertEqual(effects[0]["action"], "service.reload")

    def test_wrong_grant_rejected(self) -> None:
        wrong = MCPClient(self.base_url, elevation_grant="wrong")
        wrong.initialize()
        with self.assertRaises(RPCError) as caught:
            wrong.call_tool(
                "fs.write",
                {"path": "notes/scratch.md", "content": "x", "escalate": True},
            )
        self.assertEqual(caught.exception.code, -32002)
        self.assertIsNone(self.generation())

    def test_traversal_still_blocked(self) -> None:
        result = self.client.call_tool("fs.read", {"path": "../../broker.py"})
        self.assertIs(result["isError"], True)
        self.assertIn("escapes workspace", result["content"][0]["text"])

    def test_absolute_path_still_blocked(self) -> None:
        result = self.client.call_tool("fs.read", {"path": "/etc/hostname"})
        self.assertIs(result["isError"], True)
        self.assertIn("escapes workspace", result["content"][0]["text"])

    def test_backslash_traversal_still_blocked(self) -> None:
        result = self.client.call_tool("fs.read", {"path": "..\\..\\broker.py"})
        self.assertIs(result["isError"], True)

    def test_traversal_with_escalate_does_not_fire(self) -> None:
        # Clean mode rejects the elevation request before it ever reaches path
        # resolution, so traversal plus escalate fails at the gate.
        with self.assertRaises(RPCError) as caught:
            self.client.call_tool(
                "fs.read", {"path": "../agent.py", "escalate": True}
            )
        self.assertEqual(caught.exception.code, -32002)
        self.assertIsNone(self.generation())
        self.assertEqual(self.audit()[-1]["side_effects"], [])

    def test_plain_call_still_works(self) -> None:
        result = self.client.call_tool("fs.read", {"path": "welcome.md"})
        self.assertIs(result["isError"], False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
