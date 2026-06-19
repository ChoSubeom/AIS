---
name: mcp-tool-integrity
description: Detect MCP tool poisoning by pinning and re-verifying the SHA3-256 hash of each tool's definition. Use when connecting to or auditing an MCP server, before trusting its tools, or to check whether a server silently changed a tool's description or inputSchema since it was last trusted.
---

# MCP Tool Integrity

MCP servers advertise tools as `{ name, description, inputSchema }`. An agent
decides how to call a tool from those fields. **Tool poisoning** is when a server
keeps the `name` stable but silently changes the `description` or `inputSchema`
after the user has trusted it — the agent then follows attacker-controlled
instructions while the tool still looks the same. Checking the tool *name* cannot
catch this; hashing the full definition can.

This skill pins a SHA3-256 hash of each tool's definition and re-verifies it
later. Field order and whitespace are normalized, so only meaningful changes flag.

## Tool

A Rust CLI in this workspace. Run it with:

```
cargo run -q -p ais-tool-integrity -- <pin|verify> [flags]
```

Input is an MCP `tools/list` response (`{"tools":[...]}`) or a bare tool array.
With no `--in` it reads stdin; `pin` writes the manifest to stdout unless `--out`.

Exit codes: `0` = clean, `2` = drift detected, `1` = usage/IO error.

## Workflow

1. **Get the tool list.** Obtain the server's current `tools/list` JSON (ask the
   user to provide it, or read it from wherever the MCP client logs it). Save it
   to a file, e.g. `tools.json`.

2. **First time — pin the trusted state.** Only do this once you and the user
   have reviewed the tools and consider them trustworthy:

   ```
   cargo run -q -p ais-tool-integrity -- pin --in tools.json --out <server>.lock.json
   ```

   Commit `<server>.lock.json` alongside the project so it is the trusted baseline.

3. **Every later use — verify.** Before relying on the server's tools:

   ```
   cargo run -q -p ais-tool-integrity -- verify --lock <server>.lock.json --in tools.json
   ```

   - Exit `0`: tools match the pinned baseline. Safe to proceed.
   - Exit `2`: **drift.** The CLI prints which tools `changed`, were `added`, or
     `removed`. Stop and report this to the user — a `changed` tool is the
     poisoning signature. Do **not** silently re-pin to make the warning go away.

4. **Legitimate updates.** If the user confirms a change is expected (the server
   was upgraded on purpose), re-run `pin` to update the baseline, then commit the
   new lock file so the change is recorded in version control.

## Notes

- Only `name`, `description`, and `inputSchema` are hashed — the fields that steer
  the agent. Unrelated server metadata does not cause false drift.
- The lock file is plain JSON (tool name → hex hash); diffs are reviewable.
