````markdown id="m4v0zi"
# AIS — Implementation Guidance

> Internal engineering guidance for AIS contributors and AI-assisted development.

This document defines the implementation priorities, simplifications,
engineering constraints, and development philosophy for AIS.

The purpose of this document is to:

- reduce scope creep
- keep AIS-Core small
- prevent premature overengineering
- maintain deterministic trust guarantees
- guide both human and AI contributors

This document is intentionally practical and implementation-oriented.

---

# Current Development Phase

AIS is currently focused ONLY on the AIS-Core MVP.

Current implementation target:

- AI Certificate handling
- model signing & verification
- deterministic cryptographic primitives
- secure session framing
- tamper-evident audit chain

Everything else is secondary.

---

# Engineering Philosophy

## 1. Small Core First

AIS-Core MUST remain:

- minimal
- deterministic
- auditable
- formally analyzable

Avoid adding features unless they are strictly required for the core trust model.

When uncertain:

> prefer removing functionality over adding functionality.

---

## 2. Infrastructure Before Intelligence

AIS focuses on infrastructure trust, NOT semantic intelligence.

Avoid implementing:

- LLM classifiers
- moderation systems
- jailbreak detectors
- AI policy reasoning
- semantic scoring engines

unless explicitly required by a future specification version.

---

## 3. Determinism Over Complexity

Prefer:

- explicit state machines
- static protocol definitions
- canonical serialization
- predictable failure semantics

Avoid:

- implicit behaviors
- hidden state
- probabilistic logic
- magic abstractions

---

## 4. Fail-Closed

Security-sensitive operations MUST fail safely.

Examples:

- invalid certificate → reject
- signature mismatch → reject
- sequence mismatch → terminate session
- malformed frame → reject connection

Do not silently recover from protocol violations.

---

# MVP Scope

The MVP is intentionally narrow.

## MUST Implement

### Cryptography

- SHA3-256 hashing
- Ed25519 signatures
- secure random generation
- constant-time signature verification

### Certificates

- AI Certificate structure
- certificate signing
- certificate verification
- model hash validation

### Sessions

- session identifiers
- sequence counters
- authenticated framing
- integrity verification

### Audit

- append-only audit entries
- hash chaining
- deterministic audit hashing

### CLI

- `sign-model`
- `verify-model`

---

## MUST NOT Implement (Yet)

The following are intentionally excluded from MVP:

- transparency logs
- revocation infrastructure
- OCSP/CRL equivalents
- distributed trust systems
- TEE integration
- remote attestation
- semantic classifiers
- provenance-aware transformers
- vector database trust systems
- agent memory trust propagation
- automatic policy inference
- multi-party federation

These are future research directions.

---

# Recommended Technology Choices

These choices prioritize simplicity and reliability over flexibility.

| Area | Recommendation |
|---|---|
| Language | Rust |
| Async Runtime | Tokio |
| Serialization | CBOR |
| Crypto | ed25519-dalek |
| Hashing | sha3 |
| UUIDs | uuid crate |
| Audit Persistence | append-only local storage |
| CLI | clap |
| Proxy | axum or hyper |

Avoid introducing unnecessary dependencies.

---

# Serialization Guidance

Current recommendation:

- use deterministic CBOR serialization
- avoid custom binary protocols initially
- avoid ASN.1 complexity
- avoid protobuf until protocol stabilizes

Canonical serialization is REQUIRED for:

- signatures
- audit hashes
- certificate validation

Field ordering MUST remain deterministic.

---

# Certificate Guidance

Current AI Certificate implementation should remain intentionally simple.

Initial certificate fields:

- issuer
- subject/model identity
- model hash
- public key
- validity period
- signature

Do NOT implement:

- certificate transparency
- intermediate CA hierarchies
- complex extension systems

during MVP stage.

---

# Session Guidance

Initial session implementation should prioritize clarity over optimization.

Current expectations:

- single-session state machine
- explicit sequence counters
- authenticated request framing
- deterministic session termination

Do NOT optimize for:

- high-throughput multiplexing
- distributed session coordination
- QUIC-like complexity

---

# Audit Chain Guidance

Audit logging is a core trust component.

Requirements:

- append-only
- hash chained
- tamper-evident
- deterministic hashing

Recommended initial implementation:

```text
entry_hash = HASH(
    prev_hash ||
    timestamp ||
    request_hash ||
    response_status
)
````

Keep audit structure simple initially.

Distributed transparency systems are intentionally deferred.

---

# Proxy Guidance

AIS Proxy is intended to be:

* lightweight
* transparent
* vendor-neutral

Initial proxy target:

* OpenAI-compatible REST API

Do NOT implement:

* advanced orchestration
* distributed routing
* semantic middleware pipelines
* complex plugin systems

during MVP stage.

---

# AI-Assisted Development Rules

When using AI coding assistants:

## Prioritize Simplicity

Prefer:

* smaller modules
* explicit types
* straightforward control flow

Avoid:

* speculative abstractions
* unnecessary generics
* premature extensibility

---

## Avoid Scope Expansion

AI contributors MUST NOT introduce:

* semantic filtering systems
* alignment logic
* ML classifiers
* distributed consensus
* blockchain systems

unless explicitly requested.

---

## Preserve Determinism

Do not introduce probabilistic decision-making into AIS-Core.

AIS-Core MUST remain deterministic.

---

# Temporary Simplifications

The following simplifications are acceptable during MVP stage.

| Area              | Temporary Simplification   |
| ----------------- | -------------------------- |
| Storage           | local filesystem           |
| Trust Store       | static local trust anchors |
| Revocation        | not implemented            |
| Transparency      | not implemented            |
| TEE Support       | omitted                    |
| Federation        | omitted                    |
| Policy Engine     | omitted                    |
| Distributed Audit | omitted                    |

These simplifications are intentional.

---

# Security Expectations

AIS is currently a research prototype.

Security properties SHOULD NOT be assumed correct without:

* independent review
* cryptographic analysis
* threat modeling
* protocol auditing
* adversarial testing

No production security guarantees currently exist.

---

# Suggested Development Order

Recommended implementation order:

## Phase 1

* workspace setup
* crypto primitives
* AI Certificate structures
* signing & verification CLI

## Phase 2

* session framing
* authenticated requests
* sequence handling

## Phase 3

* audit chain
* persistence layer
* verification tooling

## Phase 4

* OpenAI-compatible proxy
* integration testing

---

# Long-Term Direction

Potential future research directions:

* transparency logs
* revocation systems
* remote attestation
* TEE integration
* provenance-aware inference
* capability-secure AI agents

These are intentionally deferred until AIS-Core stabilizes.

---

# Final Guideline

The most important engineering rule in AIS is:

> Keep AIS-Core small, deterministic, and trustworthy.

```
```
