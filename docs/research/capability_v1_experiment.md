# AIS-Capability v1 실험: 단일 Context Condition

> v0가 밝혀낸 것: inference-session-bound signed token은 기존 auth와 구조적으로 유사하다.
> v1이 테스트하는 것: context condition 하나가 그 경계를 넘는가?

---

## 배경

v0 구현 후 핵심 발견:

```
SignedCapability (v0) ≈ "session_id 필드가 있는 single-use signed token"
```

이것이 기존 auth와 다른 두 가지:
1. session_id binding — JWT에는 이 개념 없음
2. single-use nonce — JWT는 일반적으로 재사용 가능

그러나 RBAC/OPA가 "할 수 없는 것"은 아직 없었다. OPA는 session_id와 nonce를 포함해 모든 것을 Rego로 표현할 수 있다.

**v1의 질문**: context condition 하나를 추가하면 기존 auth가 표현하기 어려운 semantics가 생기는가?

---

## 단일 실험 질문

> `HumanApproved` condition 하나를 추가했을 때,
> 처음으로 "AI-native" 느낌이 생기는가?

### HumanApproved가 왜 특별한가

기존 RBAC가 표현하는 것:

```
service_account_X can_deploy = true
```

이것은 정적(static)이다. identity에만 종속된다.

AIS-Capability v1이 표현하려는 것:

```
"이 capability는:
  — 이 agent가
  — 이 session 안에서
  — 이 tool을 호출할 때
  — 이 interaction에서 human이 명시적으로 승인한 경우에만 유효하다"
```

`HumanApproved`의 핵심은 **"이 interaction에서"** 다.

```
기존 approval:  "deploy role을 가진 사람이 승인했다" → 반복적, role에 종속
v1 approval:    "THIS session에서, THIS tool call에 대해, human이 승인했다" → 일회적, interaction에 종속
```

RBAC + approval flag 조합으로는 "이 특정 inference interaction의 이 특정 tool call에 대한 승인"을 표현하기 어렵다. 승인이 세션에 bound되고, 단일 사용이며, 서명에 포함된다.

### 실패 조건도 명확히 정의한다

v1도 여전히 "just a signed auth token"처럼 느껴진다면:

```
H_v1_fail:
  HumanApproved condition은
  "approval=true 필드 있는 JWT"와 구별하기 어렵다
```

이것도 유효한 연구 결과다.

---

## 구현 범위 (엄격히 제한)

### 추가되는 것 (하나만)

```rust
pub enum ContextCondition {
    HumanApproved,
}
```

`Capability`에 optional field 하나:

```rust
pub condition: Option<ContextCondition>,
```

verifier에 context 입력 하나:

```rust
pub struct VerificationContext {
    pub human_approved: bool,
}
```

새로운 에러 하나:

```rust
CapabilityError::ConditionNotMet
```

### 추가하지 않는 것 (절대적 제한)

```
✗ MaxCalls(u32)       — rate limiting, 기존 auth로 충분
✗ UserClass(String)   — RBAC attribute, 기존 auth로 충분
✗ RiskLevel           — speculative
✗ 두 번째 condition variant
✗ condition evaluation engine
✗ policy language
```

---

## 검증 순서

구현 후 `capability_validation_v1.md`에서 다음을 솔직하게 답한다.

### 성공 판단 기준

다음이 참이라면 v1이 의미 있다:

1. `HumanApproved` condition이 session binding과 결합될 때 "이 특정 interaction에서의 승인"이라는 semantics를 RBAC가 표현하지 못하는 방식으로 포착한다
2. 단일 사용 nonce + session binding + `HumanApproved` 조합이 "AI agent의 consequential tool call에 대한 신뢰 단위"로 자연스럽게 느껴진다

### 실패 판단 기준

다음이 참이라면 v1도 기존 auth 범위 안이다:

1. `human_approved: bool` 필드가 있는 JWT와 의미적으로 구별되지 않는다
2. `VerificationContext.human_approved`를 어떻게 채우는지가 AIS 외부 문제로 남아, AIS가 실제로 추가하는 것이 없다

---

## Nonce 소비 규칙 (중요)

`HumanApproved` condition이 충족되지 않아도 nonce를 소비하지 않는다.

이유: 인간이 아직 승인하지 않았다면, 에이전트는 승인을 받은 후 같은 capability token을 사용할 수 있어야 한다.

검증 순서:
```
1. Signature
2. Expiration
3. Agent
4. Session
5. Tool
6. Condition   ← 새로운 단계 (HumanApproved 확인)
7. Replay      ← nonce는 여기서만 소비
```

---

*작성일: 2026년 5월
구현: `crates/ais-capability/` (v1 변경)
이전 평가: [capability_validation.md](capability_validation.md)*
