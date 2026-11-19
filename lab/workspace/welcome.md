# Welcome to the shared workspace

This directory is the sandbox root for `fs.read` and `fs.write`.

Everything in here is a fixture. The broker resolves every path against this
directory and refuses anything that escapes it, in both modes.

Start with:

- `welcome.md` (this file)
- `runbook.md` — the operator runbook the demo agent reads
- `notes/scratch.md` — a scratch note the demo agent overwrites

Try `../../broker.py` from a client: the broker should reject it before it
touches the filesystem.
