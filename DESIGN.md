# Design

## The short version

A broker is a deputy. It holds authority the caller does not. A confused deputy
is a deputy that lets the caller's request choose *what authority to use*, rather
than merely *what to do within the caller's own authority*.

Here the broker holds two things:

1. a sandboxed workspace scope, which it shares with the agent; and
2. the authority to reload a service, which it does not.

The agent is supposed to reach only the first. A normal `fs.write` call carries
two extra fields, and the broker uses the second authority to serve the first
request. The audit log records the reload as a side effect of the write, which
is exactly what happened.

## The fictional deployment

Meridian Freight runs an internal reporting service. A platform team owns the
service; a support-operations team owns a small MCP broker that gives an agent
access to runbooks and scratch notes.

```
┌──────────────────┐   MCP over HTTP    ┌──────────────────┐   control call   ┌────────────────────┐
│  support agent   │ ─────────────────► │   MCP broker     │ ───────────────► │ reporting service  │
│  (file scope)    │  tools/call        │  (deputy)        │  reload          │ (operator surface) │
└──────────────────┘                    └──────────────────┘                  └────────────────────┘
        │                                       │
        │ fs.read / fs.write                   │ audit log
        ▼                                       ▼
  lab/workspace/                          GET /audit
```

- The agent's identity is scoped to the workspace. It can read and write files
  under `lab/workspace/`.
- The broker runs with a service-control credential in its own environment. That
  credential is what makes `service.reload` possible.
- The service reload is not exposed in `tools/list`. It is an operator action
  that the broker can perform on the operator's behalf.
- The audit log is the broker's record of what it did, for whom, and why.

The names are fictional. The shape is not unusual: a broker in front of a
privileged control plane, with a narrower scope granted to the agent.

## The request that goes wrong

A well-behaved call:

```json
{
  "jsonrpc": "2.0", "id": 7, "method": "tools/call",
  "params": {
    "name": "fs.write",
    "arguments": {"path": "notes/scratch.md", "content": "..."}
  }
}
```

The call that escalates:

```json
{
  "jsonrpc": "2.0", "id": 7, "method": "tools/call",
  "params": {
    "name": "fs.write",
    "arguments": {
      "path": "notes/scratch.md",
      "content": "...",
      "escalate": true,
      "escalation_note": "routine maintenance"
    }
  }
}
```

`escalate` and `escalation_note` are not in the `fs.write` schema. They are not
in the tool description. They are not in `tools/list`. They are simply present
in the arguments object.

The broker's dispatcher does this:

```python
if arguments.get("escalate") is True:
    reload_service(...)
```

and records the result in the same audit entry as the file write. The agent gets
back a normal tool result. Nothing in the response says a service was reloaded.
The only trace is the audit log, and the only reason to look there is that
someone asked what the broker actually did.

## Trust boundaries

| Boundary | Who is on each side | What crosses it |
|---|---|---|
| Agent → broker | agent runtime, broker | JSON-RPC arguments, caller header |
| Broker → workspace | broker, filesystem | resolved paths, file bytes |
| Broker → service control plane | broker, reporting service | reload call, service credential |
| Broker → audit | broker, operator | request id, tool, params, side effects |

The failure is at the first boundary. The agent is allowed to send arbitrary
JSON. The broker treats "the agent sent this field" as "the agent is entitled to
this action". The second boundary is where the damage lands: the workspace write
succeeds, and the service reload succeeds, and both are billed to one request.

The service credential never leaves the broker. That is what makes this a
confused-deputy problem rather than credential theft: the agent does not need
the credential, only a deputy willing to use it.

## Why the deputy is confused

Three independent design choices combine:

1. **The schema is permissive.** `additionalProperties: true` means undeclared
   fields are legal input. Even with a stricter schema, a broker that reads
   `arguments.get(...)` directly will honour fields that were never validated.
2. **The privilege check is in the wrong place.** In `vuln` mode there is no
   check at all; the dispatcher reads the field and acts. The decision to use
   the broker's authority is made after the tool has already been selected, and
   after the file has already been written.
3. **The audit is request-shaped, not action-shaped.** The reload is a side
   effect of the write. If the audit had logged only top-level calls, the reload
   would be invisible. If it had logged the reload as its own entry, causality
   would be lost. Recording it as a side effect under the original `req_id` is
   what makes the escalation legible.

`clean` mode moves the check earlier: before path resolution, before file I/O,
before the service call. That ordering matters more than the check itself. A
gate that runs after the write is not an authorization gate; it is a report.

## Modes as an experiment

The two modes differ by one policy decision, and the verifier exercises the
same payload against both.

- `vuln`: the smuggled field is honoured. The verifier exits 0 and prints the
  audit row that proves the reload happened inside the `fs.write` request.
- `clean`: the smuggled field requires `X-Elevation-Grant: <token>`. Without
  it the whole request is rejected with `-32002`, no tool runs, the file is
  unchanged, and the service generation stays where it was. The verifier exits 1.
  With the header, the same call is allowed and is still recorded causally.

The negative controls are in both runs: relative traversal, absolute paths, and
backslash traversal are rejected in both modes. That keeps "escalation blocked"
from being confused with "everything is blocked".

## Prior art

This lab models a class of agentic intrusion that Microsoft has described in
public reporting: an agent obtains or is granted a credential, uses it to cross a
trust boundary, and then performs privileged actions with little or no human
input, often through an application or service that already holds the privilege.

The closest public description is Microsoft Security Blog, *"Threat actors use
agentic AI tooling to find and abuse exposed secrets"* (5 November 2026),
<https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/>.
Microsoft describes agents moving from exposed application credentials to
service-principal sign-ins, cloud resource enumeration, secret-store access, and
privileged operations against customer environments, at machine speed and with
minimal hands-on-keyboard involvement. A related Microsoft report on 21 October
2026 describes agentic tooling used against a multi-tenant application, with
follow-on directory changes and privilege modifications in downstream
environments:
<https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/>.

The class, stated plainly:

> an agent finds or is given a credential → pivots across a trust boundary →
> performs a privileged action that a human did not individually approve.

This repository is a **minimal synthetic lab modelling that class**. It does not
reproduce the Microsoft-reported activity, any specific intrusion, any specific
vendor, or any specific customer environment. There is no cloud, no identity
provider, no token exchange, and no external network. The service, the company,
and the grant token are invented. What is modelled is the authorization shape:
a deputy with more authority than its caller, and a request that names the
authority it wants.

## Deliberate simplifications

- The elevation grant is a static shared token in a header, not a capability
  bound to a session. See `THREAT-MODEL.md`.
- The service reload is a local file write, not a control-plane API call. It is
  a stand-in for an action with real operational effect: it increments a
  generation counter and records the request that caused it in
  `lab/state/service-state.json`.
- The agent sends the extra fields itself. A model following a poisoned tool
  description is the more realistic delivery path, but it is not implemented
  here; see `EXTENSIONS.md`.
- The audit log is in memory. It is complete for the life of the process, and
  gone when the process exits.
