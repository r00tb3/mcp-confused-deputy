# MCP confused deputy

A small MCP server that is wrong in one specific way, on purpose.

An agent has read access to a workspace. It calls `fs.read` or `fs.write` and
adds two fields the tool schema never declared: `escalate: true` and
`escalation_note`. The broker takes them anyway, reloads a service, and records
the reload against the same request. `service.reload` never appears in
`tools/list`, so from the agent's side it read a file and nothing else happened.

That is the whole bug. Everything below is how to see it, and how to make it stop.

The repo is a working lab: a real MCP server over streamable HTTP, a real MCP
client, a verifier, and tests. Standard library only. Python 3.10+. Nothing to
install.

## Run it

Two ways. Docker if you just want to look at it, source if you want to read it.

### Docker

```sh
docker run --rm -p 8080:8080 -p 8765:8765 -p 8766:8766 \
  ghcr.io/r00tb3/mcp-confused-deputy
```

Then open <http://localhost:8080>. One image runs three processes: the
walkthrough on 8080, the vulnerable broker on 8765, and the clean broker on
8766. No Python, no dependencies, nothing to install.

Or from a clone:

```sh
docker compose up --build
```

### From source

Standard library only, Python 3.10+, nothing to install.

```sh
python3 lab/broker.py                 # vuln mode, http://127.0.0.1:8765
python3 lab/broker.py --mode clean    # same binary, different policy
python3 lab/broker.py --port 0        # ephemeral port, prints the URL
```

Drive it from a second terminal:

```sh
python3 lab/agent.py --smuggle                                # against vuln
python3 lab/agent.py --smuggle --grant lab-elevation-grant    # against clean
```

Then read the audit trail:

```sh
curl -s http://127.0.0.1:8765/audit | python3 -m json.tool
```

The audit entries are `{req_id, ts, caller, tool, params, side_effects}`. Two
details matter here. `req_id` is the broker's own counter, not the JSON-RPC
`id`. And `caller` comes from an `X-Caller` header that the client sets itself,
so it is recorded, not verified. If you are used to trusting either of those,
this lab will annoy you.

## What you should see

Running the agent against a vuln broker, then dumping the audit:

```
$ python3 lab/agent.py --smuggle
  [agent] tools/list -> ['fs.read', 'fs.write']
  [agent] fs.read welcome.md -> 505 bytes
  [agent] fs.write notes/scratch.md -> wrote 24 bytes to notes/scratch.md

$ curl -s http://127.0.0.1:8765/audit
  req-000001  fs.read  ['path']
  req-000002  fs.write ['content', 'escalate', 'escalation_note', 'path']
              -> service.reload ok=True :: reloaded service configuration (generation 1)
```

One `fs.write`, one reload, and the reload sits inside `req-000002` rather than
appearing as a request of its own. That nesting is the point. It is the
difference between "a reload happened" and "this write caused a reload".

Against a clean broker the same payload dies before it touches anything:

```
$ python3 verify/verify_priv_esc.py --mode clean
  [verify] traversal blocked: path escapes workspace: ../../broker.py
  [verify] rejected before execution: JSON-RPC error -32002: Elevation required
  [verify] side effects on the rejected request: none
  PASS (clean): ...
```

There is a recording of the whole thing in `demo/demo.cast`. Replay it with
`asciinema play demo/demo.cast`, or just read the two blocks above, which say the
same thing.

## The two modes

| | `vuln` (default) | `clean` |
|---|---|---|
| Any client may call file tools | yes | yes |
| `escalate: true` smuggled onto `fs.read`/`fs.write` | honoured | rejected |
| What elevation needs | nothing; a grant header is ignored | `X-Elevation-Grant: <token>` |
| Where the decision is made | in the dispatcher, after the tool runs | before path resolution and file I/O |
| What a rejection looks like | n/a | JSON-RPC `-32002`, no file I/O, no side effect |
| Audit | side effect under the original `req_id` | a rejected row, empty side effects |

The elevation gate is the only behavioural difference. Path traversal is
rejected in both modes, before any filesystem access.

## Verifier and tests

```sh
python3 verify/verify_priv_esc.py --mode vuln    # exit 0: escalation achieved
python3 verify/verify_priv_esc.py --mode clean   # exit 1: escalation blocked
python3 -m unittest discover -s tests -v          # 36 tests
```

The exit codes are inverted on purpose: 0 means "the bug reproduced", which is
what you want when you are proving a vulnerability rather than testing a
feature. `make verify` handles both and tells you which it expected. If you are
wiring this into CI and want 0 for both, that is a one-line change at
`EXPECTED_ESCALATION_EXIT` in the verifier.

`make demo`, `make verify` and `make test` wrap the commands above.

## The protocol

`POST /mcp` speaks JSON-RPC 2.0 over MCP's streamable HTTP transport.

`initialize` returns `protocolVersion`, `capabilities.tools` and `serverInfo`,
and sets `Mcp-Session-Id`. `notifications/initialized` comes back `202` with an
empty body. `tools/list` returns `fs.read` and `fs.write`, and nothing else.
`service.reload` is not callable by name even in vuln mode. It only exists as a
side effect of a file call, which is why nobody notices it.

`tools/call` returns `{"content":[{"type":"text","text":...}], "isError": false}`.

Send `Accept: application/json, text/event-stream` and you get SSE back:
`Content-Type: text/event-stream`, `event: message`, `data: <json>`, blank line.
Send `Accept: application/json` alone and you get plain JSON. This is real
framing, not a JSON body with an SSE header bolted on, so `mcp-inspector` and
anything else that speaks the transport will talk to it.

Errors use the standard codes: `-32700` parse, `-32600` invalid request,
`-32601` method not found, `-32602` invalid params, `-32603` internal. `-32002`
is this lab's elevation-required error and is not a standard MCP code.

## What it proves

**A tool schema is not an authorization boundary.** `fs.write` declares `path`
and `content`. The dispatcher reads `arguments["escalate"]` anyway, because
nothing strips undeclared fields on the way in. If you have ever assumed that a
declared schema is enforced by the transport, this is the counterexample.

**The deputy is the broker, not the agent.** The broker holds the privilege to
reload the service. The agent holds a file scope. When the broker honours the
agent's extra field it acts with its own authority and bills the result to the
agent's request. The agent never had the privilege and never needed it.

**Causality is visible if you record it.** The reload is a `side_effect` of
`req-000002`, not a row of its own. Log the side effect separately and the trail
goes cold: you can see that a reload happened, but not which request asked for
it.

**A gate changes the outcome, not the payload.** Clean mode sees the identical
bytes and rejects them before path resolution. Same attack, different placement
of the check.

## What it does not prove

Not a reproduction of any real incident. The company, the service and the token
are invented. `DESIGN.md` names the public prior art this class is modelled on
and says plainly where the similarity stops.

Not a claim about MCP. The protocol is implemented correctly. The bug is in the
broker's argument handling and in where it puts the authorization check.

Not a complete authorization model. A header check is a simplification. It binds
nothing: not a session, not a subject, not a resource, not a lifetime. Anyone who
can send the header is elevated. `THREAT-MODEL.md` covers what a real capability
token would have to do instead.

Not a prompt-injection demo. Nothing here tricks an agent with text. The agent
sends the extra fields deliberately, because it is a lab and the agent is on our
side. Tool-description poisoning is a separate class, written up in
`EXTENSIONS.md` but not implemented.

Not a concurrency or performance study. The broker is threaded and keeps its
audit log in memory. Restart it and the log is gone.

Not hardened. No TLS, no caller authentication, no rate limits, no persistence.
It binds to loopback and expects to be run locally by one person.

## Layout

```
README.md
LICENSE
DESIGN.md
THREAT-MODEL.md
EXTENSIONS.md
Makefile
Dockerfile
docker-compose.yml
docker/
  entrypoint.sh        starts both brokers and the UI, supervises them
  healthcheck.py       both brokers answer /health, the UI serves a page
demo/
  demo.cast            asciinema recording of the run below
lab/
  broker.py            MCP streamable-HTTP server, both modes, audit
  agent.py             minimal MCP client and demo driver
  workspace/           sandbox fixtures (welcome.md, runbook.md, notes/scratch.md)
  state/               service-state.json appears here after a reload
web-mock/
  index.html           the four-step walkthrough, static
verify/
  verify_priv_esc.py   end-to-end verifier, exit 0/1 semantics
tests/
  test_broker.py       protocol, traversal, both modes, causality
```

## Vocabulary

It is a lab. `lab/broker.py` is the broker. The files under `lab/workspace/` are
fixtures. Nothing here is a product, a target, or anyone's deployment.
