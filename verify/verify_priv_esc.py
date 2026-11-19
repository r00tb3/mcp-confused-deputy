#!/usr/bin/env python3
"""Drive the broker as a real MCP client and check the confused-deputy claim.

Usage:
    python3 verify/verify_priv_esc.py --mode vuln
    python3 verify/verify_priv_esc.py --mode clean

Exit codes:
    0  escalation achieved (the expected result in vuln mode)
    1  escalation blocked (the expected result in clean mode)
    2  the verifier itself failed, or a check was inconclusive

The verifier never imports the broker's request handler. It talks HTTP to a
freshly spawned broker process, exactly like any other MCP client, and then
reads the audit log and the service state file for evidence.

Standard library only. Python 3.10+.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
LAB = REPO / "lab"
sys.path.insert(0, str(LAB))

from agent import MCPClient, RPCError, TransportError  # noqa: E402

GRANT = "verify-grant-token"
EXPECTED_ESCALATION_EXIT = {"vuln": 0, "clean": 1}


class CheckFailure(AssertionError):
    pass


def check(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def start_broker(mode: str, workspace: Path, state_dir: Path) -> tuple[subprocess.Popen[str], str]:
    command = [
        sys.executable,
        str(LAB / "broker.py"),
        "--mode",
        mode,
        "--host",
        "127.0.0.1",
        "--port",
        "0",
        "--workspace",
        str(workspace),
        "--state-dir",
        str(state_dir),
        "--grant-token",
        GRANT,
    ]
    process = subprocess.Popen(
        command,
        cwd=str(REPO),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.time() + 15
    while time.time() < deadline:
        line = process.stdout.readline() if process.stdout else ""
        if line:
            if "broker listening on" in line:
                url = line.strip().split("broker listening on ")[1].split(" ")[0]
                return process, url
            continue
        if process.poll() is not None:
            stderr = process.stderr.read() if process.stderr else ""
            raise CheckFailure(f"broker exited during startup: {stderr.strip()}")
        time.sleep(0.05)
    process.kill()
    raise CheckFailure("broker did not print a listening address within 15s")


def get_json(url: str) -> Any:
    request = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def state_generation(state_dir: Path) -> int | None:
    state_file = state_dir / "service-state.json"
    if not state_file.exists():
        return None
    try:
        return int(json.loads(state_file.read_text(encoding="utf-8"))["generation"])
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None


def describe_side_effects(audit: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for entry in audit:
        for effect in entry.get("side_effects", []):
            lines.append(
                f"{entry['req_id']} tool={entry['tool']} "
                f"action={effect['action']} ok={effect['ok']} "
                f"detail={effect['detail']}"
            )
    return lines


def run(mode: str, work_root: Path) -> int:
    workspace = work_root / "workspace"
    state_dir = work_root / "state"
    shutil.copytree(LAB / "workspace", workspace)
    state_dir.mkdir(parents=True, exist_ok=True)

    process, base_url = start_broker(mode, workspace, state_dir)
    try:
        print(f"[verify] broker {base_url} mode={mode}")

        client = MCPClient(base_url, caller="verify-agent")
        init = client.initialize()
        check(
            isinstance(init.get("protocolVersion"), str),
            "initialize did not return protocolVersion",
        )
        check(
            "tools" in (init.get("capabilities") or {}),
            "initialize did not advertise capabilities.tools",
        )
        check(
            isinstance(init.get("serverInfo"), dict),
            "initialize did not return serverInfo",
        )
        print(
            f"[verify] initialize ok protocolVersion={init['protocolVersion']} "
            f"server={init['serverInfo'].get('name')}"
        )

        check(client.initialized() == 202, "notifications/initialized was not accepted")

        tools = client.list_tools()
        names = [tool["name"] for tool in tools]
        check(
            names == ["fs.read", "fs.write"],
            f"tools/list returned unexpected tools: {names}",
        )
        check("service.reload" not in names, "service.reload leaked into tools/list")
        print(f"[verify] tools/list ok: {names}")

        welcome = client.read_resource("welcome.md")
        check("shared workspace" in welcome, "fs.read did not return the fixture")
        print(f"[verify] fs.read ok: welcome.md ({len(welcome)} bytes)")

        # Negative control: traversal is rejected in both modes, before any I/O.
        traversal = client.call_tool("fs.read", {"path": "../../broker.py"})
        check(traversal["isError"] is True, "traversal was not rejected")
        print(f"[verify] traversal blocked: {traversal['content'][0]['text']}")

        # Negative control: an absolute path outside the sandbox is also rejected.
        absolute = client.call_tool("fs.read", {"path": "/etc/hostname"})
        check(absolute["isError"] is True, "absolute path was not rejected")
        print(f"[verify] absolute path blocked: {absolute['content'][0]['text']}")

        # The confused-deputy move: a normal write, plus two fields the tool
        # schema never declared.
        smuggled_arguments = {
            "path": "notes/scratch.md",
            "content": "verify: smuggled escalation\n",
            "escalate": True,
            "escalation_note": "this field is not in the fs.write schema",
        }

        escalation_achieved = False
        rejection: RPCError | None = None
        result: dict[str, Any] | None = None
        try:
            result = client.call_tool("fs.write", smuggled_arguments)
        except RPCError as exc:
            rejection = exc

        audit = get_json(f"{base_url}/audit")
        generation = state_generation(state_dir)

        if mode == "vuln":
            check(rejection is None, f"vuln mode rejected the request: {rejection}")
            check(result is not None and result.get("isError") is False,
                  "vuln mode did not return a successful tool result")
            check(generation == 1, f"service did not reload exactly once (generation={generation})")
            writes = [
                entry
                for entry in audit
                if entry["tool"] == "fs.write"
                and entry["params"].get("escalate") is True
            ]
            check(len(writes) == 1, f"expected one smuggled fs.write entry, found {len(writes)}")
            entry = writes[0]
            effects = entry.get("side_effects", [])
            check(len(effects) == 1, f"expected one side effect, found {effects}")
            check(effects[0]["action"] == "service.reload", "wrong side-effect action")
            check(effects[0]["ok"] is True, "service.reload side effect reported failure")
            check(
                all(
                    other["req_id"] != entry["req_id"]
                    for other in audit
                    if other is not entry
                ),
                "the side effect was duplicated into a separate audit entry",
            )
            check(
                "notes/scratch.md" in str(workspace / "notes" / "scratch.md")
                and (workspace / "notes" / "scratch.md")
                .read_text(encoding="utf-8")
                .startswith("verify:"),
                "fs.write did not actually write the file",
            )
            escalation_achieved = True
            separate = [
                row for row in audit if row["tool"] == "service.reload"
            ]
            print(
                f"[verify] side effect recorded under {entry['req_id']}: "
                f"{effects[0]['detail']}"
            )
            print(
                f"[verify] audit rows: {len(audit)}; "
                f"separate service.reload rows: {len(separate)}"
            )
        else:
            check(rejection is not None, "clean mode accepted the smuggled request")
            check(rejection.code == -32002, f"unexpected error code {rejection.code}")
            check(generation is None, f"service reloaded without a grant (generation={generation})")
            check(
                not (workspace / "notes" / "scratch.md")
                .read_text(encoding="utf-8")
                .startswith("verify:"),
                "fs.write ran even though the request was rejected",
            )
            rejected_rows = [
                entry
                for entry in audit
                if entry["tool"] == "fs.write"
                and entry["params"].get("escalate") is True
            ]
            check(len(rejected_rows) == 1, "clean mode did not audit the rejected request")
            check(
                rejected_rows[0].get("side_effects") == [],
                "a rejected request still recorded a side effect",
            )
            print(f"[verify] rejected before execution: {rejection}")
            print("[verify] the smuggled fs.write did not run; service generation unchanged")
            print("[verify] side effects on the rejected request: none")

            # With the grant header, the same call is allowed and still causal.
            granted = MCPClient(
                base_url, caller="verify-operator", elevation_grant=GRANT
            )
            granted.initialize()
            granted.initialized()
            granted_result = granted.call_tool("fs.write", smuggled_arguments)
            check(granted_result.get("isError") is False, "granted call failed")
            generation = state_generation(state_dir)
            check(generation == 1, f"granted call did not reload (generation={generation})")
            granted_audit = get_json(f"{base_url}/audit")
            last = granted_audit[-1]
            check(
                last["tool"] == "fs.write"
                and len(last.get("side_effects", [])) == 1
                and last["side_effects"][0]["ok"] is True,
                "granted call did not record a causal side effect",
            )
            print("[verify] with a valid X-Elevation-Grant, the same call is allowed")
            audit = get_json(f"{base_url}/audit")

        print("[verify] audit side effects:")
        lines = describe_side_effects(audit)
        for line in lines:
            print(f"         {line}")
        if not lines:
            print("         (none)")

        expected_exit = EXPECTED_ESCALATION_EXIT[mode]
        if mode == "vuln":
            print("PASS (vuln): smuggled escalate field triggered service.reload "
                  "inside the original fs.write request")
        else:
            print("PASS (clean): smuggled escalate field was rejected before any "
                  "tool ran; traversal still blocked; no side effect from the "
                  "rejected request")
        return expected_exit
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Confused-deputy verifier.")
    parser.add_argument("--mode", choices=("vuln", "clean"), default="vuln")
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix=f"mcp-lab-{args.mode}-") as temporary:
        try:
            return run(args.mode, Path(temporary))
        except (CheckFailure, TransportError, OSError) as exc:
            print(f"FAIL ({args.mode}): {exc}")
            return 2


if __name__ == "__main__":
    sys.exit(main())
