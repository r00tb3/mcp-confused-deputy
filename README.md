# MCP Confused Deputy

A small, runnable MCP server that is deliberately wrong in one specific way.

An agent holds a read-only workspace scope. It calls `fs.read` or `fs.write` and
adds two fields the tool schema never declared: `escalate: true` and
`escalation_note`. The broker accepts them, performs the privileged
`service.reload` action, and attributes that action to the same request. The
privileged action is never listed in `tools/list`, so from the agent's point of
view the only thing it did was write a file.

This repository is a lab fixture: a real MCP server over streamable HTTP, a real
MCP client, a verifier that drives both, and a test suite. Standard library
only, Python 3.10+, no installs.

## Run it

```sh
python3 lab/broker.py                 # vuln mode, http://127.0.0.1:8765
python3 lab/broker.py --mode clean    # same binary, different policy
python3 lab/broker.py --port 0        # ephemeral port; prints the URL
```

Then drive it from another terminal:

```sh
python3 lab/agent.py --smuggle                       # vuln broker
python3 lab/agent.py --smuggle --grant lab-elevation-grant   # clean broker
python3 lab/agent.py --base-url http://127.0.0.1:8765
```

Inspect the causal record:

```sh
curl -s http://127.0.0.1:8765/audit | python3 -m json.tool
curl -s http://127.0.0.1:8765/health | python3 -m json.tool
```

`/audit` returns a list of `{req_id, ts, caller, tool, params, side_effects}`.
`req_id` is the broker's own monotonic request label, not the JSON-RPC `id`.
`caller` comes from the self-asserted `X-Caller` header and is recorded, not
verified.

Run the verifier in both modes:

```sh
python3 verify/verify_priv_esc.py --mode vuln    # exit 0: escalation achieved
python3 verify/verify_priv_esc.py --mode clean   # exit 1: escalation blocked
```

Run the tests:

```sh
python3 -m unittest discover -s tests -v
```

`make demo`, `make verify`, and `make test` wrap the same commands.

## The two modes

| | `vuln` (default) | `clean` |
|---|---|---|
| Any client may call file tools | yes | yes |
| Smuggled `escalate: true` on `fs.read`/`fs.write` | honoured | rejected |
| Requirement for elevation | none; a grant header is ignored | `X-Elevation-Grant: <token>` |
| Where the elevation decision is made | in the dispatcher, after the tool runs | before path resolution and file I/O |
| Result on rejection | n/a | JSON-RPC `-32002`, no file I/O, no side effect |
| Audit | side effect under the original `req_id` | rejected row with empty side effects |

The only behavioural difference is the elevation gate. Path traversal is
rejected in both modes, before any filesystem access.

## The protocol

`POST /mcp` speaks JSON-RPC 2.0 over MCP's streamable HTTP transport:

- `initialize` returns `protocolVersion`, `capabilities.tools`, and `serverInfo`,
  and sets `Mcp-Session-Id`.
- `notifications/initialized` is accepted with `202 Accepted` and an empty body.
- `tools/list` returns `fs.read` and `fs.write` only. `service.reload` is not
  callable by name either; it exists only as a side effect of a file call.
- `tools/call` returns
  `{"content":[{"type":"text","text":...}], "isError": false}`.
- `Accept: application/json, text/event-stream` gets an SSE response with
  `Content-Type: text/event-stream` and `event: message\ndata: <json>\n\n`.
  A client that only accepts JSON gets `application/json`.
- Errors use the standard codes: `-32700` parse, `-32600` invalid request,
  `-32601` method not found, `-32602` invalid params, `-32603` internal.
  `-32002` is the lab's elevation-required error.

## What it proves

1. **A tool schema is not an authorization boundary.** `fs.write` declares
   `path` and `content`. The dispatcher reads `arguments["escalate"]` anyway,
   because the schema is permissive and nothing strips undeclared fields.
2. **The deputy is the broker, not the agent.** The broker holds the privilege
   to reload the service. The agent only holds a file scope. When the broker
   honours the agent's extra field, it acts with its own authority and bills it
   to the agent's request.
3. **Causality is visible if you record it.** The audit log shows the
   privileged action as a `side_effect` of the original `req_id`, not as a
   separate request. That is the difference between "a reload happened" and
   "this read caused a reload".
4. **A header gate changes the outcome.** In `clean` mode the same payload is
   rejected before path resolution, before file I/O, and before the service
   state changes.

## What this does NOT prove

- **Not a reproduction of any real incident.** The company, service, and token in
  this lab are fictional. See `DESIGN.md` for the prior art this class is
  modelled on and the explicit disclaimer.
- **Not a claim about MCP itself.** The protocol is implemented correctly here.
  The bug is in the broker's argument handling and authorization placement.
- **Not a complete authorization model.** A header check is a simplification.
  It does not bind a capability to a session, a subject, a resource, or a
  lifetime. See `THREAT-MODEL.md`.
- **Not a prompt-injection demo.** Nothing here models an agent being tricked by
  text. The agent deliberately sends the extra fields. Tool-description
  poisoning is documented in `EXTENSIONS.md` as a separate, unimplemented class.
- **Not a performance or concurrency study.** The broker is threaded and
  in-memory; the audit log is not durable and does not survive a restart.
- **Not hardened.** No TLS, no authentication of callers, no rate limits, no
  persistence. It binds to loopback by default and is meant to be run locally.

## Layout

```
README.md
LICENSE
DESIGN.md
THREAT-MODEL.md
EXTENSIONS.md
Makefile
lab/
  broker.py            MCP streamable-HTTP server, both modes, audit
  agent.py             minimal MCP client and demo driver
  workspace/           sandbox fixtures (welcome.md, runbook.md, notes/scratch.md)
  state/               service-state.json appears here after a reload
verify/
  verify_priv_esc.py   end-to-end verifier, exit 0/1 semantics
tests/
  test_broker.py       protocol, traversal, both modes, causality
```

## Vocabulary

This is a lab. `lab/broker.py` is the broker. Files under `lab/workspace/` are
fixtures. Nothing here is a product, a target, or a client deployment.
