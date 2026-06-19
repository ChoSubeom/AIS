# AIS — MCP Tool Integrity

> Pin and verify the SHA3-256 hash of each MCP tool's definition to detect tool poisoning.

MCP servers advertise tools as `{ name, description, inputSchema }`. An agent
decides whether and how to call a tool from exactly those fields. **Tool
poisoning** is the attack where a server keeps a tool's `name` stable but
silently changes its `description` or `inputSchema` after the user has come to
trust it — the agent then follows attacker-controlled instructions while the
tool still looks the same.

Checking the tool *name* (what OAuth scopes or a JWT `aud` claim do) cannot catch
this. AIS pins a SHA3-256 hash over each tool's full definition and re-verifies
it later: any change to the description or schema flips the hash and is reported
as drift. Field order and whitespace are normalized, so semantically identical
definitions do not produce false drift.

This is the narrowed scope of the project. The earlier, broader "AI security
layer" exploration is documented — and critiqued — under [`docs/research/`](docs/research/);
that analysis is why the project now targets this one concrete, current problem
instead.

---

## Layout

```text
crates/
  ais-crypto/          # SHA3-256 / Ed25519 primitives (reused)
  ais-tool-integrity/  # pin/verify library + CLI
.claude/skills/
  mcp-tool-integrity/  # Claude Code skill wrapping the CLI
docs/research/         # skeptical analysis that motivated the narrowing
```

## Build & test

```bash
cargo build
cargo test
```

## CLI

```bash
# 1. Pin the trusted state (once, after reviewing the tools)
cargo run -q -p ais-tool-integrity -- pin --in tools.json --out tools.lock.json

# 2. Verify a later tool list against the baseline
cargo run -q -p ais-tool-integrity -- verify --lock tools.lock.json --in tools.json
```

Input is an MCP `tools/list` response (`{"tools":[...]}`) or a bare tool array;
with no `--in` it reads stdin. Exit codes: `0` = clean, `2` = drift detected,
`1` = usage/IO error. On drift, the changed / added / removed tools are listed;
a `changed` tool is the poisoning signature.

## As a Claude Code skill

`.claude/skills/mcp-tool-integrity/` exposes the same pin/verify flow as a skill,
invoked when connecting to or auditing an MCP server. See its `SKILL.md`.

---

## Scope

AIS verifies that an MCP server's advertised tool definitions have not changed
since they were pinned. It does **not** judge whether a tool is safe, inspect
tool *outputs*, or replace transport security (TLS/mTLS). It detects silent
*definition* tampering — and nothing more.

## License

Apache-2.0.
