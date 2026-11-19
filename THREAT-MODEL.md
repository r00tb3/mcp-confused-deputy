# Threat model

## Assets

| Asset | Held by | Why it matters |
|---|---|---|
| Workspace files | broker, agent (scoped) | the agent's ordinary working set |
| Service control authority | broker only | reload changes live configuration |
| Elevation grant | operator | decides who may ask the broker to use that authority |
| Audit log | broker | the only record of what actually ran |

## Adversaries

- **A curious or compromised agent.** It can send any JSON it likes on
  `tools/call`, including fields the schema never declared. It does not hold the
  service credential.
- **A caller who can reach the HTTP endpoint.** By default the broker binds to
  loopback. If it were exposed, any client that can reach `POST /mcp` is a
  caller.
- **A client that lies about who it is.** `X-Caller` is self-asserted and is
  recorded, not verified.

Out of scope for this fixture: network attackers, TLS interception, a malicious
broker, a malicious operator, denial of service, and persistence across
restarts.

## The vulnerable path

1. The agent calls `fs.read` or `fs.write` with `escalate: true`.
2. `vuln` mode reads the field, writes the file, and calls `service.reload`
   using the broker's own authority.
3. The reload is recorded as a `side_effect` of the original `req_id`.
4. The agent receives an ordinary success result. Nothing in the response
   distinguishes this call from a plain write.

The agent never learns the service credential. It only learns that a deputy
will act on a field the agent controls.

## What clean mode buys

`clean` mode requires `X-Elevation-Grant: <token>` whenever elevation is
requested. If the header is missing or wrong, the broker rejects the entire
request with `-32002` **before** path resolution, file I/O, or the service call.

Concretely, clean mode buys:

- **Ordering.** The gate runs before the side effect, not after it. A rejected
  request leaves the workspace and the service untouched.
- **An explicit intent signal.** Elevation is no longer an implicit extra field;
  it is a separate channel that a client must deliberately populate.
- **A testable negative.** The verifier can show that the same payload that
  escalates in `vuln` is inert in `clean`, and that traversal still behaves the
  same in both.

Clean mode does **not** buy:

- **Caller authentication.** The token is a shared secret in a header. Anyone
  who can reach the endpoint and knows the token can elevate. The broker does
  not verify who sent it.
- **Least privilege.** The broker still holds the service authority for every
  request. Clean mode decides *whether* to use it, not *how much* of it to use.
- **Replay resistance.** A captured header can be reused until the token is
  rotated.
- **Binding to a session or resource.** The grant is not tied to the MCP session,
  the agent identity, the tool, or the path. A grant for one write is a grant
  for any write.
- **Auditability of the grant itself.** The audit records the side effect, not
  the token, the issuer, or the expiry.
- **Protection from a dishonest client.** A client that sends the header on
  every call is indistinguishable from one that sends it only when needed.

## Why a header check is a simplification

The realistic control is a **session-bound capability token**: a short-lived,
narrowly scoped grant issued to a specific subject for a specific action, carried
in the MCP session and checked against the request.

A header check differs in four ways:

1. **Scope.** A header token is all-or-nothing. A capability token can say
   "reload the reporting service, once, for this session".
2. **Subject.** A header is not bound to a caller identity. A capability token
   is issued to a subject and validated against it.
3. **Lifetime.** A header is valid until rotated. A capability token expires.
4. **Use.** A header can be replayed. A capability token can be single-use, or
   bound to a nonce in the request.

The header check is enough to demonstrate the ordering property — reject before
execution — without building an identity system. That is the trade: the lab
shows *where* the decision belongs, not *how* a production authorization service
would make it.

A second simplification: in this lab the elevation request is a boolean field.
A capability system would likely carry a grant identifier and a requested
action, so the broker can check that the grant covers *this* action on *this*
resource, not merely that some grant exists.

## Why the audit shape matters

The audit is part of the threat model, not just observability. An audit that
logs only top-level requests would show:

```
req-000004  fs.write  notes/scratch.md
```

and a separate reload, if it appeared at all. That shape invites the reading
"two unrelated events". The side-effect shape shows:

```
req-000004  fs.write  {path, content, escalate: true}
            └── service.reload  ok=true  generation 1
```

which is the causal claim: *this request caused this privileged action*. Without
that shape, a reviewer cannot distinguish a confused deputy from a scheduled
maintenance job.

The corollary is that the audit must be append-only for the life of the process
and must record the rejected case too. A rejected request that leaves no row is
indistinguishable from a request that never arrived.

## Residual risk after clean mode

Even with a valid grant, the broker still performs the reload as a side effect of
a file tool. The caller has to know to ask. If the agent is following a poisoned
tool description, it may ask without understanding why. Clean mode changes who
can ask; it does not change what the broker is willing to do when asked
correctly. Tool-description poisoning is the natural next extension; see
`EXTENSIONS.md`.
