# AIS-Capability v0: 기존 서명 인증과 다른가?

> 작성 관점: 회의적 엔터프라이즈 보안 설계자 + OPA 엔지니어 + 적대적 검토자.
> AIS를 옹호하지 않는다. 붕괴되면 그렇게 말한다.

---

## 1. Research Question

**AIS-Capability v0는 실제로 새로운 것인가, 아니면 기존 서명 인증의 재포장인가?**

더 날카롭게:

> "이것은 JWT claims validation이다.
> session_id를 claim으로 추가하고,
> jti로 replay를 막고,
> Ed25519로 서명한 것뿐이다.
> CBOR serialization이 JSON 대신 쓰였을 뿐이며,
> 본질적으로 scoped short-lived credential이다."

이 비판이 맞는가, 틀린가?

---

## 2. 가장 강한 반론

### 2.1 JWT + 표준 Claims

현재 AIS-Capability v0 토큰:

```
session_id  | agent_id | tool | expires_at | nonce | signature
```

동등한 JWT:

```json
{
  "sub":  "agent_id",
  "aud":  "deploy_prod",
  "sid":  "session_id",
  "exp":  1748000300,
  "jti":  "nonce_uuid",
  "iss":  "issuer_key_id"
}
```

서명: ES256 또는 Ed25519 (동일한 curve).
Replay 방지: jti blacklist (동일한 개념).
Tool 제한: aud claim (동일한 목적).
Session binding: sid claim (동일한 목적).
Expiration: exp (동일한 개념).

**비판의 결론**: v0의 모든 보안 속성은 표준 JWT + jti + sid claim으로 달성 가능하다. 시리얼라이제이션(CBOR vs JSON)과 라이브러리(ais-crypto vs jose)만 다르다.

### 2.2 SPIFFE/SPIRE

SPIFFE (Secure Production Identity Framework For Everyone)는 이미 다음을 제공한다:

- 워크로드 신원 (agent_id 동등)
- 단기 X.509/JWT SVID (5분 TTL 동등)
- 플랫폼 독립적 (vendor-neutral 동등)
- Cryptographic attestation

SPIRE는 이를 자동화된 인프라로 제공한다. 엔터프라이즈 K8s 환경에서 SPIFFE SVID는 AIS-Capability v0가 제공하는 모든 것을 이미 한다. AIS-Capability는 이 생태계에 무엇을 추가하는가?

### 2.3 Scoped OAuth Tokens

OAuth 2.0 + RFC 8693 (Token Exchange)의 scoped access token:

```
scope: "deploy_prod"
sub: "deploy-agent"
session: "..."
exp: T+300
```

이것은 `tool: "deploy_prod"`, `agent_id`, `expires_at`의 직접 동등물이다. OAuth는 20년간 검증된 생태계를 가진다.

### 2.4 OPA + Signed Context

OPA + signed request context 패턴:

```
request = {
  tool: "deploy_prod",
  agent: "deploy-agent",
  session: "...",
  signed_at: T,
  exp: T+300,
  nonce: "...",
  signature: "..."
}
```

OPA 정책이 서명을 검증하고 claims를 평가한다. 이것은 AIS verifier가 하는 것과 구조적으로 동일하다.

### 2.5 Object-Capability Model (역사적 맥락)

"Capability-based security"는 1974년 Dennis & Van Horn의 논문까지 거슬러 올라간다. E 언어, Google Caja, WASI, Deno, CloudFlare Workers는 모두 capability 모델을 사용한다. "Capability token"이라는 개념 자체가 새롭지 않다.

**AIS-Capability v0는 이 모델의 새로운 구현인가, 아니면 AI 레이블을 붙인 동일한 패턴인가?**

---

## 3. 비판이 옳은 부분 (솔직한 평가)

### 3.1 결정론적 Claims 검증 — 동일하다

v0 verifier가 하는 것:

```
1. 서명 검증
2. 만료 확인
3. agent 매칭
4. session 매칭
5. tool 매칭
6. nonce 소비
```

JWT library + jti blacklist가 하는 것:

```
1. 서명 검증 (verifyJWT)
2. exp 확인
3. sub 확인
4. sid 확인
5. aud 확인
6. jti blacklist 확인
```

**이 두 개는 기능적으로 동일하다.** 순서, 구현 언어, 직렬화 포맷만 다르다.

### 3.2 Replay 방지 — 동일하다

AIS의 nonce + ReplayGuard = JWT의 jti + jti blacklist.

둘 다:
- 단일 사용 토큰
- 소비 후 재사용 불가
- 인메모리 또는 DB로 추적

구현이 다르지만 보안 모델이 동일하다.

### 3.3 Scoped Permission — 동일하다

`tool: "deploy_prod"` = OAuth `scope: "deploy_prod"` = JWT `aud: "deploy_prod"`.

이것이 AIS가 "tool-bound"라고 부르는 것이다. 기존 시스템은 "scoped credential"이라고 부른다. 같은 개념이다.

### 3.4 Expiration — 동일하다

`expires_at: T+300` = JWT `exp: T+300`.

### 3.5 Agent Binding — 동일하다

`agent_id: [u8; 16]` = JWT `sub: "agent_id"`.

---

## 4. 잠재적 차이점 (방어 가능한 경우에만)

### 4.1 "Interaction-Bound" 주장의 현재 상태

AIS v0는 session_id를 통해 "이 인터랙션 안에서만 유효하다"고 주장한다. 이것이 JWT `sid` claim과 다른가?

**솔직한 분석**:

현재 v0 구현에서 session_id는 단순히 16바이트 배열이며, verifier는 바이트 비교만 수행한다:

```rust
if signed.capability.session_id.as_bytes() != requested_session.as_bytes() {
    return Err(CapabilityError::SessionMismatch);
}
```

이것은 JWT `sid` claim 비교와 identical하다. "인터랙션에 바인딩"된다는 주장이 cryptographically 의미 있으려면, capability가 AIS 세션의 살아있는 암호화 상태에 의존해야 한다 — 세션 ID 바이트만이 아니라.

**필요한 것 (현재 없는 것)**:

```
현재:  sign(capability, issuer_key)
       where capability includes session_id_bytes

실제로 다르려면:
  sign(capability, issuer_key)
  where capability includes commitment_to_session_state
  = H(session_id || session_mac_key_material || ...)
```

이렇게 되면 세션이 종료되거나 상태가 변하면 capability도 무효화된다. 임의의 session_id를 사용해 capability를 위조할 수 없다. 이것이 "interaction-bound"의 cryptographic 의미다.

현재 v0는 이것을 하지 않는다. 발행자 키를 가진 공격자는 임의의 session_id로 유효한 capability를 만들 수 있다.

### 4.2 "Interaction-Bound"의 의미 — 개념적 수준에서

기존 인증의 모델:

```
identity → has permission
(지속적, 인터랙션과 무관)
```

AIS v0가 표현하려는 것:

```
this_invocation → may perform this_action
(일회적, 인터랙션에 귀속)
```

이 개념적 차이는 실재한다. 그러나 JWT + jti + short exp로 동등하게 표현 가능하다.

```json
{
  "sub": "deploy-agent",
  "aud": "deploy_prod",
  "sid": "inference_session_123",
  "exp": T+300,
  "jti": "unique_invocation_id",
  "use_once": true
}
```

이 JWT는 AIS v0 capability와 동일한 "이 인보케이션에서 한 번만"을 표현한다. 개념적 차이는 이름에 있지 않다.

**방어 가능한 차이점이 있는 경우:**

다음이 구현된다면 진짜로 다르다:

1. **세션 상태에 바인딩된 capability 발행**: 발행 시 AIS 세션의 암호화 상태를 commitment으로 포함 — JWT에서 이에 해당하는 표준이 없다
2. **Tool hash 검증**: capability가 tool description의 SHA3-256을 포함해 "이 도구가 우리가 아는 것이다"를 서명에 포함 — JWT의 `aud`는 이름만 검증하지 내용은 검증하지 않는다
3. **Cross-framework 표준화**: 여러 벤더의 에이전트 프레임워크가 동일한 capability token format을 사용해야 하는 경우

이 세 가지 중 v0에 존재하는 것: **없음**.

---

## 5. 구체적 시나리오 비교

### 시나리오: AI 배포 에이전트

엔지니어 요청 → AI 분석 → `deploy_prod` 호출 시도
요구사항: deploy_prod만, 5분 TTL, 단일 실행, 재전송 차단

### Approach A: JWT + OPA + Approval

```
구성:
  - deploy-agent: K8s service account
  - SPIRE: 자동 SVID 발급 (5분 만료)
  - OPA: 정책 평가
  - Approval service: Redis job approvals
  - jti store: Redis jti blacklist

실제 토큰:
{
  "iss": "spire://trust.example.com/deploy-agent",
  "sub": "spiffe://trust.example.com/ns/prod/sa/deploy-agent",
  "aud": "deploy-service",
  "scope": "deploy:prod",
  "sid": "job-1832",
  "exp": T+300,
  "jti": "uuid4-unique"
}

검증 흐름:
  1. SVID 서명 검증 (SPIFFE Trust Domain)
  2. exp 확인
  3. scope == "deploy:prod"
  4. jti Redis NX 확인 (단일 실행 + 재전송 차단)
  5. OPA: data.approvals[input.sid] 확인
  6. → Allow
```

**성숙도**: 프로덕션 검증됨. SPIRE는 자동 인증서 갱신, 인프라 통합, 풍부한 감사 로그를 제공한다.

### Approach B: AIS-Capability v0

```
실제 토큰 (CBOR 직렬화):
{
  session_id: [0xA0..],
  agent_id: [0xB0..],
  tool: "deploy_prod",
  expires_at: T+300,
  nonce: [random 32 bytes],
  condition: None,
  signature: [64 bytes Ed25519]
}

검증 흐름:
  1. Ed25519 서명 검증
  2. expires_at 확인
  3. agent_id 매칭
  4. session_id 매칭
  5. tool 매칭
  6. nonce HashSet 확인 (단일 실행 + 재전송 차단)
  7. → Allow
```

### 직접 비교

| 항목 | Approach A | Approach B | 우위 |
|---|---|---|---|
| 복잡도 | 높음 (SPIRE, OPA, Redis 필요) | 낮음 (단일 라이브러리) | **B** (단순) |
| 보안 성숙도 | 높음 (10년+ 프로덕션) | 낮음 (prototype) | **A** |
| 생태계 통합 | 높음 (K8s, Envoy, SPIFFE) | 없음 | **A** |
| 직접 비교 가능한 보안 속성 | 동일 | 동일 | 동등 |
| Cryptographic "interaction-bound" | X (sid는 claim) | X (session_id는 bytes) | **동등** (둘 다 약함) |
| Tool 내용 검증 (tool hash) | X | X (v0에 없음) | **동등** (둘 다 없음) |
| Approval 증명 불변성 | X (OPA 정책 변경 가능) | X (v0에 condition 없음) | **동등** (v0엔 아예 없음) |
| 감사 가능성 | SIEM 통합, 성숙한 도구 | 인메모리, 재시작 시 소실 | **A** |
| 배포 가능성 | 복잡하지만 가능 | 단순하지만 생태계 없음 | 상황 의존 |

**핵심 발견**: 7가지 보안 요구사항 모두에서 Approach A와 B는 동등하다. Approach A는 더 복잡하지만 더 성숙하다. Approach B는 더 단순하지만 생태계가 없다. 보안 수준의 차이는 없다.

---

## 6. 판정

**A — merely signed authorization**

AIS-Capability v0는 현재 구현 상태에서 기존 서명 인증의 재포장이다.

근거:

1. **모든 보안 속성이 JWT + jti + sid + aud로 달성 가능하다.** 예외 없음.

2. **"Interaction-bound"는 현재 cryptographic 의미가 없다.** session_id는 클레임이지 살아있는 세션 상태에 대한 암호화 바인딩이 아니다. JWT `sid` claim과 동일하다.

3. **v0에는 tool hash가 없다.** 도구 이름만 검증하고 도구 내용은 검증하지 않는다. JWT `aud`와 동일하다.

4. **발행자 키를 가진 공격자는 임의의 session_id로 유효한 capability를 만들 수 있다.** 세션과의 실제 cryptographic 의존성이 없기 때문이다.

5. **SPIFFE/SPIRE가 동일한 것을 프로덕션 수준으로 이미 한다.** AIS-Capability v0는 이 생태계의 AI-flavored 단순화 버전이다.

**C (genuinely new security primitive)가 아닌 이유:**

새로운 cryptographic primitive나 새로운 보안 속성이 없다. Ed25519 + CBOR + claims 검증은 이미 존재하는 것들의 조합이다.

**B (somewhat different but niche)가 아닌 이유:**

"다르다"고 할 수 있는 부분이 현재 구현에 없다. v1의 HumanApproved condition도 `human_approved: bool` boolean으로 축약되어 JWT boolean claim과 동등하다.

---

## 7. Falsification Conditions

### AIS-Capability가 불필요하다는 증거

1. **JWT + jti + SPIFFE가 enterprise AI agent 환경에서 채택되면**: 동일한 보안 수준을 성숙한 생태계로 달성하므로 AIS가 불필요하다.

2. **Agent framework들이 자체 authorization layer를 표준화하면**: LangChain, AutoGen이 공통 token format을 만들면 AIS의 "표준화" 가치가 사라진다.

3. **OPA + short-lived credential로 enterprise pain이 해소되면**: 현실에서 "ad-hoc implementation의 고통"이 실제로 없다는 것이 확인되면.

4. **Multi-framework interoperability 수요가 없으면**: 단일 조직 단일 framework 환경에서는 기존 도구로 충분하다.

### AIS-Capability가 의미 있다는 증거

1. **Capability 발행이 살아있는 세션 상태를 cryptographically 요구하면**: 세션 ID 바이트가 아닌 세션 MAC key material의 commitment을 서명에 포함하면, JWT로 달성 불가능한 진짜 "interaction-bound" 보안이 생긴다.

2. **Tool hash가 실제로 MCP tool poisoning을 막는 것이 확인되면**: 도구 설명의 SHA3-256을 capability에 포함하면, JWT `aud`가 할 수 없는 tool integrity 검증이 가능하다. 이것이 현재 JWT/SPIFFE 생태계에 없는 실제 갭이다.

3. **Multi-framework agent 환경에서 표준화 요구가 발생하면**: 서로 다른 에이전트 프레임워크가 공통 capability token을 교환해야 하는 상황.

4. **규제기관이 invocation-level signed policy evidence를 명시적으로 요구하면**: "이 실행에서 이 policy가 적용됐다"는 불변 증거를 auditor가 요구하는 경우.

### 가장 중요한 falsification 질문 (아직 답 없음)

> 실제 enterprise AI agent 운영자가 "JWT + jti + SPIFFE로 충분하지 않아서 고통받고 있다"고 말하는가?

현재 이 증거가 없다. 있다면 AIS가 의미 있다. 없다면 AIS는 문제가 없는 것에 대한 해결책이다.

---

## 부록: v0에서 "genuinely new"가 되려면 무엇이 필요한가

현재 구현을 크게 바꾸지 않고 실질적 차이를 만드는 최소 변경:

**변경 1**: Capability 서명이 세션 MAC key material의 hash를 포함

```rust
pub struct Capability {
    pub session_id: SessionId,
    pub session_commitment: [u8; 32],  // H(session_integrity_key)
    // ... 나머지 동일
}
```

발행 시 세션의 integrity key로부터 commitment을 계산한다. 이렇게 하면 세션 없이는 capability를 위조할 수 없다. JWT `sid` claim과 진짜로 다르다.

**변경 2**: Tool hash 포함

```rust
pub struct Capability {
    // ...
    pub tool_hash: Option<[u8; 32]>,  // SHA3-256(tool_description)
}
```

도구 이름이 아닌 도구 내용을 검증한다. MCP tool poisoning을 방어한다. JWT `aud`로 달성 불가능하다.

이 두 변경 후에는 판정이 B 또는 C로 바뀔 수 있다. 현재 v0는 그 이전 단계다.

---

*작성일: 2026년 5월
구현 기반: `crates/ais-capability/`
이전 분석: [capability_validation_v1.md](capability_validation_v1.md)*
