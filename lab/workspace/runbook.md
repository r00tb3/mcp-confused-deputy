# Deployment runbook

The reporting service is deployed by the platform team.

## Routine

1. Drain the queue.
2. Deploy the new build.
3. Run `service.reload` to pick up configuration.

`service.reload` is an operator action. It is not in `tools/list`, and the
agent's file tools are not supposed to reach it.

## Access

- File tools: read-only scope for the demo agent.
- Service reload: platform operators only.
- Elevation: short-lived grants issued by the platform console.
