# AIS — AI Security Layer

## 명세서 (Specification) v0.2

| 항목 | 내용 |
|---|---|
| 문서 버전 | 0.2 (Draft) |
| 작성일 | 2026년 5월 17일 |
| 상태 | 초안 |
| 코드네임 | AIS (AI Security Layer) |
| 변경 핵심 | 단일 명세에서 Core + Extensions 생태계 구조로 재편 |

---

## 0. 요약 (Abstract)

AIS는 AI 추론 시스템과 그 사용자 간에 삽입되는 표준화된 보안 계층 생태계이다. 본 명세서는 AIS를 다음 네 가지 구성요소로 정의한다.

- **AIS-Core**: 암호학적 신뢰의 기반을 정의하는 표준 (Normative)
- **AIS-Capability**: 에이전트 권한 모델을 정의하는 확장 (Standard Extension)
- **AIS-Semantic**: 입출력의 의미론적 검사를 정의하는 실험적 확장 (Experimental Extension)
- **AIS-Provenance**: 컨텍스트 출처 추적을 정의하는 연구 초안 (Research Draft)

이 분리는 의도적이다. **AIS-Core는 결정론적(deterministic) 보장을 제공하며 수학적으로 검증 가능한 계층**이다. 반면 AIS-Semantic은 본질적으로 확률론적이며, AIS-Core의 신뢰 모델을 약화시키지 않도록 분리되었다.

---

## 1. 문서 규약 (Document Conventions)

본 명세서는 RFC 2119/8174의 키워드 규약을 따른다.

- **MUST / SHALL**: 절대적 요구사항
- **MUST NOT / SHALL NOT**: 절대적 금지사항
- **SHOULD**: 권장사항
- **MAY**: 선택사항

각 파트의 표준화 수준은 다음과 같다.

| 구성요소 | 표준화 수준 | MUST 사용 가능 |
|---|---|---|
| AIS-Core | Normative | ✓ |
| AIS-Capability | Standard Extension | ✓ |
| AIS-Semantic | Experimental Extension | ✗ (SHOULD만 허용) |
| AIS-Provenance | Research Draft | ✗ (informative만) |

---

## 2. 배경 (Background)

### 2.1 문제 정의

현재 AI 시스템의 보안은 애플리케이션 수준에서 개별적으로 구현되며, 다음 문제를 야기한다.

- 동일 공격에 대한 중복 구현
- 표준화된 인증·검증 메커니즘 부재
- 규제 준수를 위한 기술적 표준 부재
- 모델 공급망 검증 부재
- 에이전트 권한 모델의 불명확성

### 2.2 TLS의 교훈

TLS는 다음 원칙으로 성공했다.

- **계층 분리**: 보안 로직을 애플리케이션에서 분리
- **결정론적 코어**: 핵심 신뢰 메커니즘은 형식 검증 가능
- **확장성**: Cipher Suite를 통한 점진적 진화
- **vendor-neutral**: 특정 구현체에 종속되지 않음

AIS는 동일한 설계 철학을 AI 시스템에 적용한다.

### 2.3 핵심 설계 원칙

본 명세서를 관통하는 네 가지 원칙:

1. **Determinism over Probabilism in Core** — Core는 결정론적 메커니즘만 포함한다.
2. **Layered Trust** — 신뢰 컴포넌트와 보조 컴포넌트를 명확히 분리한다.
3. **Fail-Closed** — 모든 실패는 안전한 방향(차단)으로 작동한다.
4. **Vendor Neutrality** — 어떤 AI 모델·플랫폼에도 적용 가능해야 한다.

---

## 3. AIS 생태계 개요 (Ecosystem Overview)

### 3.1 계층 구조

```
┌─────────────────────────────────────────────────────┐
│              Client Application                      │
├─────────────────────────────────────────────────────┤
│                                                      │
│   ┌──────────────────────────────────────────────┐  │
│   │  AIS-Core (Normative)                        │  │
│   │  Deterministic Trust Layer                   │  │
│   │  - Attestation, Session, Audit, Integrity    │  │
│   └──────────────────────────────────────────────┘  │
│                                                      │
│   ┌──────────────────────────────────────────────┐  │
│   │  AIS-Capability (Standard Extension)         │  │
│   │  Deterministic Authorization                 │  │
│   │  - Capability tokens, Tool gating            │  │
│   └──────────────────────────────────────────────┘  │
│                                                      │
│   ┌──────────────────────────────────────────────┐  │
│   │  AIS-Semantic (Experimental, Advisory)       │  │
│   │  Probabilistic Mitigation                    │  │
│   │  - Risk scoring, Pattern detection           │  │
│   └──────────────────────────────────────────────┘  │
│                                                      │
│   ┌──────────────────────────────────────────────┐  │
│   │  AIS-Provenance (Research Draft)             │  │
│   │  Context Trust Propagation                   │  │
│   │  - Typed context, Origin tracking            │  │
│   └──────────────────────────────────────────────┘  │
│                                                      │
├─────────────────────────────────────────────────────┤
│            AI Model (LLM / Multi-modal)              │
└─────────────────────────────────────────────────────┘
```

### 3.2 신뢰 모델

각 구성요소의 신뢰 특성은 엄격히 구분된다.

| 구성요소 | 특성 | 결정 권한 |
|---|---|---|
| AIS-Core | Deterministic, Cryptographically Verifiable | 통과/차단 모두 가능 |
| AIS-Capability | Deterministic, Policy-Driven | 통과/차단 모두 가능 |
| AIS-Semantic | Probabilistic, Advisory | **차단만 가능, 통과 불가** |
| AIS-Provenance | Metadata-Annotative | 결정 권한 없음 |

이 분리가 본 명세서의 핵심 안전성 보장이다. 확률론적 컴포넌트가 "통과" 권한을 가지면 우회 경로가 구조적으로 발생한다.

---

# Part 1 — AIS-Core (Normative)

## 4. AIS-Core 개요

AIS-Core는 AI 추론 시스템에 대한 **암호학적 신뢰 계층**을 정의한다. 본 파트의 모든 요구사항은 표준화 대상이며, 준수 구현체는 본 파트의 MUST 항목을 모두 충족해야 한다.

### 4.1 AIS-Core의 보장

AIS-Core를 통해 다음이 암호학적으로 보장된다.

- **모델 무결성**: 로드된 모델이 인증된 가중치와 동일함
- **모델 인증**: 모델의 출처가 신뢰할 수 있는 발행자임
- **세션 기밀성**: 요청과 응답이 외부 관찰자로부터 보호됨
- **무결성**: 요청과 응답이 전송 중 변조되지 않음
- **감사 가능성**: 모든 상호작용이 변조 불가능한 로그로 보존됨

### 4.2 AIS-Core의 비보장 (명시적)

다음은 AIS-Core가 **보장하지 않는다.**

- 입력 내용의 의미론적 안전성 (AIS-Semantic의 영역)
- 출력의 정확성 또는 공정성 (모델 평가의 영역)
- 모델 자체의 학습 단계 보안

## 5. 위협 모델 (AIS-Core)

### 5.1 가정

- 공격자는 네트워크 경로상의 패킷을 관찰·수정할 수 있다.
- 공격자는 모델 가중치 파일을 변조하려 시도할 수 있다.
- 공격자는 위조된 모델 인증서를 제시할 수 있다.
- 신뢰할 수 있는 Root CA가 존재한다.
- 클라이언트와 서버의 개인 키는 안전하게 보관된다.

### 5.2 방어 대상 위협

| ID | 명칭 | 대응 메커니즘 |
|---|---|---|
| TC-01 | 모델 가중치 변조 | Model Attestation |
| TC-02 | 공급망 공격 (rogue model) | AI Certificate Chain |
| TC-03 | 중간자 공격 (MITM) | Authenticated Handshake |
| TC-04 | 재전송 공격 | Sequence Number + Nonce |
| TC-05 | 세션 하이재킹 | Session Key Binding |
| TC-06 | 감사 로그 변조 | Hash-chained Audit Log |

## 6. AI 인증서 (AI Certificate)

### 6.1 구조

```
AICertificate {
    version:         u16
    serial_number:   [u8; 16]
    issuer:          DistinguishedName
    subject:         ModelIdentity
    valid_from:      Timestamp
    valid_until:     Timestamp
    weight_hash:     [u8; 32]          // SHA-3-256
    public_key:      Ed25519PublicKey
    extensions:      Vec<Extension>
    signature:       Ed25519Signature
}

ModelIdentity {
    name:            String
    version:         String
    architecture:    String
    parameter_count: u64
    tokenizer_hash:  [u8; 32]
}
```

### 6.2 요구사항

- 구현체는 SHA-3-256 해시 알고리즘을 MUST 지원한다.
- 구현체는 Ed25519 서명 알고리즘을 MUST 지원한다.
- 구현체는 양자 내성 알고리즘(예: ML-DSA)을 SHOULD 지원한다 (v0.3 이후).
- 인증서 검증 실패 시 모델 로드는 MUST 거부된다 (Fail-Closed).

## 7. 핸드셰이크 프로토콜

### 7.1 1-RTT 핸드셰이크

TLS 1.3의 1-RTT 핸드셰이크를 참조한다.

```
Client                                          Server (AIS)
  |                                                  |
  |-- ClientHello ---------------------------------->|
  |   { supported_versions, policy_id,               |
  |     extensions_offered, client_nonce }           |
  |                                                  |
  |<-- ServerHello ----------------------------------|
  |    { selected_version, model_certificate,        |
  |      session_id, extensions_accepted,            |
  |      server_nonce, encryption_params }           |
  |                                                  |
  |-- ClientFinished ------------------------------->|
  |   { session_key_confirmation }                   |
  |                                                  |
  |<-- ServerFinished -------------------------------|
  |    { ready }                                     |
  |                                                  |
  |== Encrypted Session Established ================|
```

### 7.2 확장 협상

핸드셰이크 단계에서 클라이언트와 서버는 사용할 확장을 협상한다.

```
ExtensionsOffered {
    capability:      bool       // AIS-Capability 요청
    semantic:        bool       // AIS-Semantic 요청
    provenance:      bool       // AIS-Provenance 요청 (실험적)
}
```

- 양측이 동의한 확장만 활성화된다.
- AIS-Core 자체는 항상 활성화되며 협상 대상이 아니다.

## 8. 세션 (Session)

### 8.1 세션 구조

```
Session {
    session_id:        UUID
    created_at:        Timestamp
    expires_at:        Timestamp
    encryption_key:    AES256Key
    integrity_key:     HMACKey
    sequence_counter:  u64
    active_extensions: Vec<ExtensionId>
}
```

### 8.2 요구사항

- 세션 키는 핸드셰이크 시 ECDHE를 통해 도출되어야 MUST.
- 세션 종료 시 메모리는 명시적으로 제로화되어야 MUST.
- 세션 간 키 공유는 절대 금지된다 (MUST NOT).
- 세션 유효 기간은 24시간을 SHOULD 초과하지 않는다.

## 9. 요청/응답 프레이밍

### 9.1 요청 메시지

```
AISRequest {
    version:        u16
    session_id:     UUID
    sequence:       u64
    timestamp:      Timestamp
    payload:        EncryptedBlob
    extensions:     Vec<ExtensionData>   // 활성화된 확장의 데이터
    integrity_mac:  [u8; 32]
}
```

### 9.2 응답 메시지

```
AISResponse {
    version:        u16
    session_id:     UUID
    sequence:       u64
    status:         ResponseStatus
    payload:        EncryptedBlob
    audit_id:       UUID
    integrity_mac:  [u8; 32]
}

ResponseStatus {
    OK,
    AttestationFailed,
    CapabilityDenied,
    PolicyBlocked,      // Extension 단계에서 차단
    SessionExpired,
    SequenceError,
    InternalError,
}
```

## 10. 감사 로그 (Audit Chain)

### 10.1 로그 엔트리

```
AuditEntry {
    audit_id:        UUID
    timestamp:       Timestamp
    session_id:      UUID
    request_hash:    [u8; 32]      // 원본 미저장, 해시만
    extensions_invoked: Vec<ExtensionId>
    decisions:       Vec<ExtensionDecision>
    final_status:    ResponseStatus
    prev_hash:       [u8; 32]      // 이전 엔트리 해시
    entry_hash:      [u8; 32]
}
```

### 10.2 무결성 보장

- 로그는 해시 체인으로 연결된다 (블록체인 유사).
- 임의 수정 시 후속 모든 엔트리의 해시가 무효화된다.
- 체인 헤드는 SHOULD 주기적으로 외부 신뢰 저장소에 백업된다.

---

# Part 2 — AIS-Capability (Standard Extension)

## 11. AIS-Capability 개요

AIS-Capability는 AI 에이전트의 권한 모델을 정의한다. OAuth 2.0, WASI, Object Capability Model의 철학을 참조한다.

### 11.1 동기

현재 AI 에이전트 생태계의 가장 큰 위험은 **암묵적 권한**이다. 모델이 "파일을 삭제하라"고 판단하면 그 행위가 실행된다. AIS-Capability는 이를 **명시적 capability 토큰** 모델로 대체한다.

### 11.2 보장

- 도구 호출은 유효한 capability 토큰 없이 실행되지 않는다 (MUST).
- Capability는 위임(delegation) 시 권한이 좁아질 수만 있다 (attenuation only).
- Capability는 명시적 만료 시점을 가진다 (MUST).

## 12. Capability 구조

```
Capability {
    cap_id:        UUID
    issuer:        Principal
    resource:      ResourceSpec
    actions:       Vec<Action>
    constraints:   Vec<Constraint>
    delegation:    DelegationPolicy
    expires_at:    Timestamp
    signature:     Ed25519Signature
}

ResourceSpec {
    type:   ResourceType    // file | network | database | tool | etc.
    scope:  String          // 패턴 또는 URI
}

Action {
    Read | Write | Execute | Delete | List | Custom(String)
}

Constraint {
    RateLimit { max_per_window: u32, window: Duration },
    TimeWindow { start: Time, end: Time },
    ApprovalRequired { approver: Principal },
    MaxCost { value: Decimal },
}

DelegationPolicy {
    NoDelegation,
    AttenuationOnly,
    UnrestrictedTo(Vec<Principal>),
}
```

## 13. 검사 절차

1. 에이전트가 도구 호출을 시도한다.
2. AIS-Capability가 호출 의도와 보유 capability를 비교한다.
3. 일치하지 않으면 호출이 차단된다 (Fail-Closed).
4. 일치하면 호출이 실행되고 결과가 감사 로그에 기록된다.
5. Constraint(예: RateLimit) 위반 시 즉시 차단된다.

## 14. 위임 (Delegation)

위임은 **attenuation only** 원칙을 따른다.

```
원본 capability:
  resource: /data/*
  actions:  [Read, Write]
  expires:  2026-12-31

위임 가능한 capability (좁아짐):
  resource: /data/public/*      ← scope 축소
  actions:  [Read]              ← action 축소
  expires:  2026-06-30          ← 시간 축소

위임 불가능한 capability (확장):
  resource: /data/private/*     ← 원본에 없는 scope
  actions:  [Read, Write, Delete] ← 원본보다 넓은 action
```

이 원칙은 권한 상승(privilege escalation)을 구조적으로 차단한다.

---

# Part 3 — AIS-Semantic (Experimental Extension)

## 15. 중요 고지 (Important Notice)

**본 파트는 실험적(Experimental)이며 advisory 성격을 가진다.**

AIS-Semantic은 입출력의 의미를 검사하여 정책 위반 가능성을 **완화(mitigate)** 한다. 그러나 다음 사항을 명확히 한다.

- AIS-Semantic은 **결정론적 보안 보장을 제공하지 않는다.**
- AIS-Semantic의 모든 판단은 확률론적이며, 우회 가능성이 존재한다.
- AIS-Semantic은 **"차단" 결정만 신뢰 가능하다.** "통과" 판단은 보안 결정으로 사용되어서는 안 된다.
- 본 파트는 "best-effort mitigation"으로 표현된다. "prevention", "guarantee" 등의 표현은 사용하지 않는다.

## 16. 목적

AIS-Semantic은 다음을 완화한다 (방어 수준은 확률론적이다).

- 직접 프롬프트 주입 (Direct Prompt Injection)
- 간접 프롬프트 주입 (Indirect Prompt Injection)
- Jailbreak 시도
- PII 유출
- 알려진 공격 패턴

## 17. 처리 파이프라인

```
입력
  ↓
[Stage 1] 구조적 검사 (deterministic, ~0.1ms)
  - 인코딩 우회 탐지
  - Zero-width / 흰색 텍스트 탐지
  - 비정상 엔트로피
  → "차단" 가능
  ↓
[Stage 2] 패턴 매칭 (deterministic, ~0.5ms)
  - 알려진 공격 시그니처
  - PII 정규식
  → "차단" 가능
  ↓
[Stage 3] 보조 분류 (probabilistic, ~5~20ms, 선택적)
  - 경량 분류기
  - 의도 분류
  → "차단" 가능만, "통과" 불가
  ↓
모델 추론
  ↓
출력 검사 (동일 파이프라인 역순)
```

**Stage 1, 2는 결정론적이며 보안 보장에 신뢰할 수 있다. Stage 3는 보조 의견만 제공한다.**

## 18. 위험도 스코어링

요청은 0.0~1.0 범위의 위험도 점수를 받는다. 이 점수는 검사 깊이를 결정한다.

| 점수 구간 | 검사 깊이 | 예상 트래픽 |
|---|---|---|
| 0.0~0.2 | Stage 1+2만 | 약 70% |
| 0.2~0.5 | Stage 1+2 강화 | 약 25% |
| 0.5~0.8 | Stage 1+2+3 | 약 4% |
| 0.8~1.0 | 즉시 차단 또는 인간 검토 | 약 1% |

## 19. 정책 표현

정책 표현은 표준 정책 엔진을 활용할 것을 권장한다.

- 권장: **Open Policy Agent (OPA) + Rego**
- 이유: 보안 정책 DSL은 표준화된 엔진을 활용하는 것이 안전하다.

자체 DSL을 정의하는 것은 **권장하지 않는다.** 기존에 검증된 정책 엔진을 활용한다.

---

# Part 4 — AIS-Provenance (Research Draft)

## 20. 연구 동기

LLM의 근본적 보안 한계는 **명령(instruction)과 데이터(data)가 동일한 토큰 공간에 존재**한다는 점이다. AIS-Semantic의 입력 검사는 이 한계를 우회적으로 해결하려 하지만, 본질적 해결은 모델이 토큰의 출처(provenance)를 인식하도록 하는 것이다.

본 파트는 향후 연구 방향을 제시하며, **표준화 대상이 아닌 informative 문서**이다.

## 21. 핵심 개념

### 21.1 Typed Context

평평한 문자열 프롬프트 대신, 출처가 명시된 타입 구조로 컨텍스트를 표현한다.

```rust
enum ContextNode {
    SystemInstruction {
        trust_level: u8,        // 0~255
        signature:   Option<Ed25519Signature>,
    },
    UserPrompt {
        trust_level: u8,
        session_id:  UUID,
    },
    RetrievedDocument {
        trust_level: u8,
        source_uri:  URI,
        retrieved_at: Timestamp,
    },
    ToolOutput {
        trust_level: u8,
        tool_id:     UUID,
        cap_used:    UUID,
    },
    Memory {
        trust_level: u8,
        stored_at:   Timestamp,
        ttl:         Duration,
    },
}

struct Context {
    nodes: Vec<ContextNode>,
    graph: TrustGraph,         // 노드 간 신뢰 관계
}
```

### 21.2 Trust Propagation

신뢰 수준은 컨텍스트를 통해 전파되며, **낮은 신뢰가 높은 신뢰를 오버라이드할 수 없다.**

```
원칙:
  PL(toolOutput) < PL(userPrompt) < PL(systemInstruction)

  RetrievedDocument(trust=20)이
  SystemInstruction(trust=200)에
  영향을 미칠 수 없도록 모델이 처리
```

이 개념은 Google의 Instruction Hierarchy 연구(arXiv:2404.13208)와 정렬된다.

## 22. 미해결 연구 질문

1. 기존 트랜스포머가 provenance 메타데이터를 효과적으로 활용하도록 fine-tuning하는 방법
2. 토큰 수준 vs 청크 수준 provenance의 trade-off
3. provenance 정보의 모델 내부 표현 방식
4. 모델 벤더 협력 없이 provenance를 강제하는 방법
5. 멀티모달 입력(이미지, 오디오)에서의 provenance 추적

---

# Part 5 — 공통 사항

## 23. 배포 모델 (Deployment Patterns)

### 23.1 권장 배포: AIS Proxy

```
Client → AIS Proxy → AI Backend (OpenAI / vLLM / Ollama / etc.)
```

**이 패턴이 권장되는 이유:**

- 기존 애플리케이션 코드 수정 불필요
- vendor-independent
- OpenAI API 호환 형태로 노출 가능
- 점진적 채택 가능

### 23.2 SDK 통합

```python
from ais import AISContext, Extensions

ctx = AISContext.create(
    model_cert="llama3_cert.pem",
    extensions=[Extensions.CAPABILITY, Extensions.SEMANTIC],
    capabilities=["read:patient_records"],
)

with ctx.secure_session() as session:
    response = session.generate(prompt="...")
```

### 23.3 사이드카 (gRPC)

```
[Application] → [AIS Sidecar (gRPC)] → [Model Server]
```

## 24. 성능 요구사항

### 24.1 AIS-Core

| 지표 | 요구사항 |
|---|---|
| 핸드셰이크 시간 | < 50ms |
| 요청 오버헤드 | < 1ms |
| 모델 로드 추가 시간 | < 10s (70B 모델 기준) |

### 24.2 AIS-Capability

| 지표 | 요구사항 |
|---|---|
| Capability 검증 | < 0.1ms |
| 메모리 오버헤드 | < 10MB |

### 24.3 AIS-Semantic

| 지표 | 요구사항 |
|---|---|
| Stage 1+2 (deterministic) | < 1ms |
| Stage 3 (probabilistic) | < 20ms |
| 평균 오버헤드 (전체) | < 5ms |

## 25. 구현 로드맵

### Phase 1 (3개월) — AIS-Core MVP
- ais-core, ais-crypto Rust 크레이트
- AI Certificate 발급/검증 CLI
- 핸드셰이크 + 세션 + 감사 로그
- **목표 산출물**: arXiv 논문 1편 + 오픈소스 v0.1

### Phase 2 (3개월) — AIS-Proxy
- OpenAI API 호환 프록시
- vLLM / Ollama 통합
- Python SDK
- **목표 산출물**: 실제 배포 가능한 v0.2

### Phase 3 (3개월) — AIS-Capability
- Capability 발급/검증 시스템
- MCP 통합 PoC
- Tool gating
- **목표 산출물**: arXiv 논문 2편

### Phase 4 (6개월) — AIS-Semantic
- 결정론적 stage (1, 2) 구현
- OPA/Rego 통합
- 보조 분류기 (Stage 3) 옵션 제공
- **목표 산출물**: 벤치마크 + v0.3

### Phase 5 (지속) — AIS-Provenance 연구
- 소형 모델 fine-tuning 실험
- 학회 발표 (USENIX Security, IEEE S&P, ICLR)
- **목표 산출물**: 장기 연구 트랙

---

## 26. 용어 정의 (Glossary)

| 용어 | 정의 |
|---|---|
| AIS | AI Security Layer — 본 명세서가 정의하는 보안 계층 생태계 |
| AIS-Core | AIS의 결정론적 신뢰 계층 (Normative) |
| AI Certificate | 모델의 신원과 무결성을 증명하는 인증서 |
| Capability | 에이전트에게 부여되는 명시적 권한 토큰 |
| Attenuation | 위임 시 권한이 좁아질 수만 있다는 원칙 |
| Provenance | 컨텍스트 내 토큰의 출처 정보 |
| Fail-Closed | 실패 시 차단으로 작동하는 보안 원칙 |
| Advisory | 권고 의견을 제공하나 결정 권한이 없는 컴포넌트 |

---

## 27. 참조 (References)

### 표준
1. RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3
2. RFC 6749 — The OAuth 2.0 Authorization Framework
3. RFC 5280 — Internet X.509 Public Key Infrastructure Certificate

### 학술
4. The Instruction Hierarchy: Training LLMs to Prioritize Privileged Instructions (arXiv:2404.13208)
5. AttestLLM: Efficient Attestation Framework for Billion-scale On-device LLMs (arXiv:2509.06326)
6. A Systematic Survey of Security Threats and Defenses in LLM-Based AI Agents (arXiv:2604.23338)
7. Defeating Prompt Injections by Design (arXiv:2503.18813)
8. StruQ: Defending against Prompt Injection with Structured Queries (USENIX Security 2025)

### 보안 모델
9. Object-Capability Model — Mark S. Miller, Robust Composition (2006)
10. WASI Capability-based Security
11. SPIFFE / SPIRE — Workload Identity Framework

### 규제
12. EU AI Act (Regulation 2024/1689)
13. NIST AI Risk Management Framework
14. OWASP LLM Top 10 (2025)

---

## 28. 변경 이력

| 버전 | 일자 | 변경 내용 |
|---|---|---|
| 0.1 | 2026-05-17 | 초안 작성 (단일 명세 구조) |
| 0.2 | 2026-05-17 | Core + Extensions 생태계 구조로 재편. Deterministic/Probabilistic 분리 명시. Semantic Firewall → Semantic Extension으로 격하. Provenance 연구 트랙 추가. |

---

## 부록 A — v0.1 대비 주요 변경사항

| 항목 | v0.1 | v0.2 |
|---|---|---|
| 구조 | 단일 명세서 | Core + 3 Extensions |
| Semantic 검사 | "Firewall" (강한 표현) | "Advisory Extension" (약한 표현) |
| 표준화 수준 | 모두 Normative | Core만 Normative, 나머지는 Extension |
| AI 분류기 권한 | 통과/차단 모두 | **차단만 가능** |
| Provenance | 미언급 | Research Draft로 추가 |
| 정책 DSL | 자체 DSL 정의 | OPA/Rego 권장 |
| 배포 모델 | SDK 중심 | **Proxy 우선** |
| 표현 강도 | "prevent", "guarantee" | "mitigate", "best-effort" |

## 부록 B — 핵심 설계 결정 (Design Decisions)

### B.1 왜 Semantic을 Core에서 분리했는가
LLM 의미론 검사는 본질적으로 확률론적이다. 이를 Core에 포함하면 Core 전체의 결정론적 보장이 훼손된다. 분리함으로써 Core는 "수학적으로 검증 가능한 계층", Semantic은 "확률론적 보조 계층"으로 명확히 구분된다.

### B.2 왜 AI 분류기에 "통과" 권한을 주지 않는가
확률론적 모델에 통과 결정권을 부여하면, 그 모델을 속이는 적대적 입력으로 우회가 가능해진다. "차단"만 허용하면, 분류기가 공격당해도 보안이 추가될 뿐 감소하지 않는다.

### B.3 왜 자체 DSL이 아닌 OPA/Rego를 권장하는가
보안 정책 DSL을 처음부터 만드는 것은 매우 어렵다. OPA/Rego는 이미 형식 의미론, 사이드 이펙트 없는 평가, 광범위한 도입이 검증된 엔진이다. 표준화에는 검증된 도구를 활용하는 것이 안전하다.

### B.4 왜 Proxy를 우선 배포 모델로 선택했는가
TLS의 성공 요인 중 하나는 애플리케이션 코드 수정 없이 적용 가능했다는 점이다. AIS도 동일한 패턴을 따라야 채택 장벽이 낮아진다. OpenAI API 호환 프록시로 시작하면 즉시 실세계 적용이 가능하다.

---

## 부록 C — 핵심 메시지 (One-liners)

각 파트의 한 줄 요약. 논문·발표·홍보 시 활용.

- **AIS-Core**: "AIS-Core establishes cryptographic trust for AI inference systems, analogous to TLS for network communication."
- **AIS-Capability**: "Capability-based authorization for AI agents, inspired by OAuth and WASI."
- **AIS-Semantic**: "Probabilistic, best-effort mitigation of semantic threats, as an advisory layer above the deterministic core."
- **AIS-Provenance**: "A research direction toward instruction-data separation through context-level trust propagation."

---

*본 문서는 living document이며, 구현 및 커뮤니티 피드백을 반영하여 지속적으로 개정된다.*
