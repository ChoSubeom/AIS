# AIS — AI Security Layer

> Deterministic cryptographic trust infrastructure for AI inference systems.

AIS is a research-driven security framework designed to provide deterministic trust guarantees for AI inference infrastructure.

The project is inspired by the architectural role of TLS in network security, but focuses specifically on:

* model integrity
* cryptographic attestation
* authenticated inference sessions
* tamper-evident auditability
* capability-based authorization

AIS is **NOT** an alignment framework or a general AI safety system.

---

# Status

⚠️ EXPERIMENTAL RESEARCH PROTOTYPE

AIS is currently an early-stage research and engineering project.

The current prototype includes:

* deterministic cryptographic primitives
* AI Certificate verification
* authenticated session framing
* tamper-evident audit chains
* OpenAI-compatible proxy MVP
* runnable security demonstrations

AIS is now at the stage of proving **practical security usefulness**.

Most components described in the specification are intentionally deferred until AIS-Core stabilizes.

---

# Current Priority

The current implementation focus is strictly limited to the AIS-Core MVP.

Highest priority components:

1. AI Certificate format
2. Model signing & verification
3. SHA3-256 hashing
4. Ed25519 signatures
5. Secure session framing
6. Audit chain
7. OpenAI-compatible proxy MVP

The following are intentionally deferred:

* semantic filtering
* provenance systems
* transparency logs
* revocation systems
* TEE integration
* advanced policy engines
* distributed trust infrastructure

---

# Goals

AIS aims to provide:

* Vendor-neutral AI trust infrastructure
* Deterministic security primitives
* Tamper-evident auditability
* Secure AI proxy architecture
* Capability-based agent authorization
* Cryptographic trust boundaries for inference systems

---

# Non-Goals

AIS does **NOT** attempt to solve:

* AI alignment
* hallucinations
* fairness
* moderation
* jailbreak-proofing
* truthful reasoning
* harmlessness guarantees
* general AI safety

AIS focuses specifically on infrastructure security and trust.

---

# Core Principles

## 1. Deterministic Core

AIS-Core only includes mechanisms that are:

* cryptographically verifiable
* deterministic
* formally analyzable

Probabilistic AI classifiers are never trusted for **allow** decisions.

---

## 2. Layered Trust

AIS separates components by trust level.

| Component      | Trust Model              |
| -------------- | ------------------------ |
| AIS-Core       | Deterministic            |
| AIS-Capability | Deterministic            |
| AIS-Semantic   | Probabilistic / Advisory |
| AIS-Provenance | Research                 |

---

## 3. Fail-Closed

Verification failure MUST result in rejection.

Examples:

* invalid certificate → reject model
* broken session integrity → reject request
* malformed protocol state → terminate session

---

## 4. Vendor Neutrality

AIS is designed to work with:

* OpenAI-compatible APIs
* local inference runtimes
* vLLM
* Ollama
* GGUF-based systems
* future agent frameworks

AIS is intentionally vendor-independent.

---

# Security Boundary

AIS-Core is intended to provide deterministic infrastructure trust guarantees.

AIS does **NOT** guarantee:

* truthful model outputs
* safe reasoning
* alignment
* harmless behavior
* semantic correctness

AIS only attempts to guarantee:

* model identity
* model integrity
* authenticated communication
* session integrity
* audit integrity
* authorization boundaries

---

# Architecture

```text
Client
   ↓
AIS Proxy / Middleware
   ↓
AI Backend (OpenAI / vLLM / Ollama / etc.)
```

AIS operates as a transparent trust layer between clients and AI systems.

The preferred deployment model is proxy-based integration.

---

# Repository Structure

```text
ais/
├── crates/
│   ├── ais-crypto/        # Cryptographic primitives
│   ├── ais-cert/          # AI Certificate handling
│   ├── ais-session/       # Session management
│   ├── ais-audit/         # Audit chain
│   ├── ais-proxy/         # OpenAI-compatible proxy
│   ├── ais-cli/           # CLI utilities
│   ├── ais-capability/    # Future extension
│   └── ais-semantic/      # Experimental layer
│
├── demos/
│   └── examples/
│       ├── replay_attack_demo.rs
│       ├── tamper_demo.rs
│       ├── rogue_model_demo.rs
│       └── openai_proxy_demo.rs
│
├── docs/
│   ├── specification/
│   ├── threat-model/
│   ├── architecture/
│   └── research/
│
├── scripts/
└── README.md
```

---

# Planned Components

| Component      | Purpose                         | Status          |
| -------------- | ------------------------------- | --------------- |
| AIS-Core       | Deterministic trust layer       | In Progress     |
| AIS-Cert       | AI Certificates                 | Implemented MVP |
| AIS-Session    | Secure session framing          | Implemented MVP |
| AIS-Audit      | Tamper-evident logging          | Implemented MVP |
| AIS-Proxy      | OpenAI-compatible proxy         | Implemented MVP |
| AIS-Capability | Capability-based authorization  | Research        |
| AIS-Semantic   | Probabilistic threat mitigation | Experimental    |

---

# Demonstrations

AIS includes runnable demonstrations showing concrete security properties.

These examples are intended to show **practical usefulness**, not just implementation completeness.

## Replay Attack Prevention

Run:

```bash
cargo run --example replay_attack_demo -p ais-demos
```

Shows:

* without AIS → replayed request accepted
* with AIS → replayed request deterministically rejected

Security property demonstrated:

> replay attack prevention through monotonic sequence validation.

---

## Payload Tampering Detection

Run:

```bash
cargo run --example tamper_demo -p ais-demos
```

Shows:

* request payload modified in transit
* integrity verification failure
* request rejected (fail-closed)

Security property demonstrated:

> authenticated session integrity.

---

## Rogue Model Detection

Run:

```bash
cargo run --example rogue_model_demo -p ais-demos
```

Shows:

* modified model weights rejected
* forged certificate rejected

Security property demonstrated:

> model integrity verification through AI Certificates.

---

## End-to-End Proxy Flow

Run:

```bash
cargo run --example openai_proxy_demo -p ais-demos
```

Shows:

```text
Client
   ↓
AIS Proxy
   ↓
Mock Backend
```

Demonstrates:

* session creation
* request forwarding
* replay rejection
* audit append
* fail-closed behavior

Security property demonstrated:

> AIS functioning as a real inference trust layer.

---

# Threat Model

AIS-Core primarily protects against:

| Threat                   | Mitigation                    |
| ------------------------ | ----------------------------- |
| Model tampering          | AI Certificate + Attestation  |
| Rogue model distribution | Certificate chain validation  |
| MITM attacks             | Authenticated session framing |
| Session hijacking        | Session key binding           |
| Replay attacks           | Sequence counter validation   |
| Audit log tampering      | Hash-chained audit logs       |

AIS does **NOT** attempt to solve:

* model correctness
* training-time compromise
* alignment failures
* adversarial reasoning
* hallucinations

---

# MVP Scope

Phase 1 implementation target:

* SHA3-256 hashing
* Ed25519 signatures
* AI Certificate format
* Model signing CLI
* Model verification CLI
* Session framing
* Audit chain
* Proxy MVP

Example:

```bash
ais-cli sign-model \
  --model ./model.gguf \
  --issuer vendor.pem \
  --output model.cert
```

```bash
ais-cli verify-model \
  --model ./model.gguf \
  --cert model.cert
```

---

# Documentation

Detailed specifications are available in:

```text
SPECIFICATION.md
IMPLEMENTATION_GUIDANCE.md
```

Additional supporting material:

```text
/docs/specification/
/docs/threat-model/
/docs/architecture/
/docs/research/
```

---

# Research Direction

Future research areas may include:

* model transparency logs
* certificate revocation
* remote attestation
* TEE integration
* provenance-aware inference
* typed context systems
* capability-secure AI agents

These directions are intentionally deferred until AIS-Core stabilizes.

---

# Security Philosophy

AIS treats AI systems as infrastructure requiring:

* identity
* integrity
* authenticated communication
* authorization boundaries
* auditability

rather than relying purely on probabilistic safety filtering.

---

# Contributing

Contributions are welcome in areas such as:

* Rust systems programming
* cryptography
* protocol design
* AI infrastructure
* formal verification
* threat modeling
* distributed systems

---

# License

Planned license:

```text
Apache License 2.0
```

(subject to change)

---

# Disclaimer

AIS is an experimental research project.

No security guarantees are provided at this stage.

Do **NOT** use AIS in production environments without independent review and auditing.

---

# One-Line Summary

> AIS provides deterministic cryptographic trust infrastructure for AI inference systems.
