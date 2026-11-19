# State directory

The broker writes `service-state.json` here when `service.reload` runs. The file
is a fixture artifact: it proves the privileged action actually executed.

The verifier removes this directory before each run, so a passing check cannot
come from a stale generation counter.
