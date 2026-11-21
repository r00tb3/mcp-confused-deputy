# mcp-confused-deputy

A tool broker that reads arguments nobody gave it.

An agent is scoped to a workspace. It can read files and write files, and that is
the whole of its authority: `fs.read`, `fs.write`, two entries in `tools/list`,
nothing else. So it sends a write, and tucked in beside `path` and `content` are
two fields the schema never declared: `escalate: true` and an
`escalation_note`.

The broker reads them anyway. It reloads a service on its own authority, then
files the reload under the agent's request.

The agent never had reload permission. It didn't need it. That is the entire
bug, and it is why this repo exists: a tool schema is documentation, not a fence,
and the party holding the privilege is the broker, not the agent.

Everything below is how to watch it happen and how to stop it.

No dependencies. Python 3.10+, `python3 lab/broker.py`, done. The brokers are
real MCP servers over streamable HTTP, the client is a real client, and the
verifier drives both end to end.

## Watch it happen

Docker if you just want to look at it:

```sh
docker run --rm -p 8080:8080 -p 8765:8765 -p 8766:8766 \
  ghcr.io/r00tb3/mcp-confused-deputy
```

Then <http://localhost:8080> for the walkthrough. That one image runs three
things: the walkthrough on 8080, a vulnerable broker on 8765, and a hardened one
on 8766. Or `docker compose up --build` from a clone.

If you would rather read the code than click at it:

```sh
python3 lab/broker.py                 # vuln, on :8765
python3 lab/broker.py --mode clean    # same binary, different policy
```

and from a second terminal:

```sh
python3 lab/agent.py --smuggle                                # against vuln
python3 lab/agent.py --smuggle --grant lab-elevation-grant    # against clean
```

## The line that matters

```
$ python3 lab/agent.py --smuggle
  [agent] tools/list -> ['fs.read', 'fs.write']
  [agent] fs.read welcome.md -> 505 bytes
  [agent] fs.write notes/scratch.md -> wrote 24 bytes

$ curl -s http://127.0.0.1:8765/audit
  req-000001  fs.read  ['path']
  req-000002  fs.write ['content', 'escalate', 'escalation_note', 'path']
              -> service.reload ok=True :: reloaded service configuration (generation 1)
```

One write. One reload. And the reload sits *inside* `req-000002` rather than
appearing as a request of its own.

That nesting is the whole argument. If you log side effects as their own rows you
get "a reload happened" and no way to say who asked for it. Keep them attached to
the request that caused them and the trail survives contact with a question.

Same payload against the clean broker, where the gate runs earlier:

```
$ python3 verify/verify_priv_esc.py --mode clean
  [verify] traversal blocked: path escapes workspace: ../../broker.py
  [verify] rejected before execution: JSON-RPC error -32002: Elevation required
  [verify] side effects on the rejected request: none
```

Identical bytes. The file is never written and the service generation never
moves.

There is an asciinema recording in `demo/demo.cast` if you want to watch it
rather than read it, but the two blocks above are the same information.

## Two modes, one difference

| | `vuln` (default) | `clean` |
|---|---|---|
| Any client may call file tools | yes | yes |
| `escalate: true` on a file call | honoured | rejected |
| What elevation needs | nothing; a grant header is ignored | `X-Elevation-Grant: <token>` |
| Where the decision is made | in the dispatcher, after the tool runs | before path resolution and file I/O |
| What a rejection looks like | n/a | `-32002`, no file I/O, no side effect |
| Audit | side effect under the original `req_id` | rejected row, empty side effects |

Path traversal is rejected in both modes, before anything touches the disk. The
elevation gate is the only behavioural difference, which is the point. The
attack is unchanged, only the placement of the check moves.

## The awkward parts

The company, the service and the grant token are invented. `DESIGN.md` names the
public prior art this class is modelled on and is explicit about where the
similarity stops, because "inspired by a real incident" is a claim people
overreach on.

MCP itself is fine here. The protocol is implemented properly. The bug lives in
the broker's argument handling and in where it puts the authorization check.

The header gate is a stopgap and I would not defend it. It binds nothing: not a
session, not a subject, not a resource, not a lifetime. Anyone who can send the
header is elevated. `THREAT-MODEL.md` works through what a real capability token
would have to do instead.

Nothing here tricks an agent with text. The agent sends the extra fields
deliberately, because it is a lab and the agent is on our side. Tool-description
poisoning, where the *description* of a benign tool carries the injection, is a
different class, written up in `EXTENSIONS.md` but not implemented.

The broker is threaded and keeps its audit log in memory, so a restart loses the
trail. No TLS, no caller auth, no rate limits. It binds to loopback and expects
one person to run it locally. It is a lab, not a service.

## Verifying

```sh
python3 verify/verify_priv_esc.py --mode vuln    # exit 0: escalation achieved
python3 verify/verify_priv_esc.py --mode clean   # exit 1: escalation blocked
python3 -m unittest discover -s tests -v          # 36 tests
```

The exit codes are inverted deliberately. Zero means "the bug reproduced", which
is what you want when you are proving a vulnerability rather than testing a
feature. `make verify` runs both and tells you which it expected. If you are
wiring this into CI and would rather have zero for both, change
`EXPECTED_ESCALATION_EXIT` in the verifier.

`make demo`, `make verify` and `make test` wrap the commands above.

## Protocol notes

`POST /mcp`, JSON-RPC 2.0, streamable HTTP.

`initialize` returns `protocolVersion`, `capabilities.tools` and `serverInfo`,
and sets `Mcp-Session-Id`. `notifications/initialized` gets a `202` and an empty
body. `tools/list` returns `fs.read` and `fs.write` and nothing else, and
`service.reload` is not callable by name even in vuln mode, which is precisely
why nobody notices it.

Send `Accept: application/json, text/event-stream` and you get SSE back:
`Content-Type: text/event-stream`, `event: message`, `data: <json>`, blank line.
Send `Accept: application/json` alone and you get plain JSON. Real framing, not
a JSON body wearing an SSE header, so `mcp-inspector` and anything else that
speaks the transport will talk to it.

Standard error codes throughout: `-32700` parse, `-32600` invalid request,
`-32601` method not found, `-32602` invalid params, `-32603` internal. `-32002`
is this lab's elevation-required error and is not part of MCP.

## What's where

```
lab/broker.py        the MCP server, both modes, the audit log
lab/agent.py         a minimal MCP client and the demo driver
lab/workspace/       the sandbox the tools are allowed to touch
verify/              end-to-end verifier, exit 0/1 semantics
tests/               36 tests: protocol, traversal, both modes, causality
web-mock/            the four-step walkthrough, static HTML
docker/              entrypoint and healthcheck for the three-process image
DESIGN.md            the incident this models, and the prior art
THREAT-MODEL.md      what the header gate does and does not buy you
EXTENSIONS.md        tool-description poisoning, documented but not built
```

The names are literal. `lab/broker.py` is the broker, the files under
`lab/workspace/` are fixtures, and nothing here is a product or anybody's
deployment.
