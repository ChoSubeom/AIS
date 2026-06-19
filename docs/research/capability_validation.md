# AIS-Capability v0: Post-Implementation Research Assessment

> 이 문서는 구현 후 솔직한 평가다.
> AIS를 옹호하지 않는다. 가설이 약해지는 방향의 발견도 그대로 기술한다.

---

## 배경

`crates/ais-capability`는 다음 질문을 검증하기 위한 prototype이다:

> **inference-session-bound authorization이 ordinary signed authorization과
> 의미 있게 다른가?**

구현된 것:
- Ed25519-signed capability token (tool, agent, session, expiry, nonce)
- Fail-closed verifier (6단계 순서 고정)
- Single-use ReplayGuard (in-memory)
- 33개 테스트 (unit + integration, 실패 케이스 우선)

---

## 1. "Signed JWT와 다른가?"

### 솔직한 답: 구조적으로는 매우 유사하다

`SignedCapability`는 본질적으로 다음이다:

```
CBOR-serialized payload + Ed25519 signature
```

JWT는 다음이다:

```
JSON-serialized payload + RS256/ES256 signature
```

직접 비교:

| 항목 | JWT (일반) | SignedCapability |
|---|---|---|
| 서명 알고리즘 | RS256/ES256/HS256 | Ed25519 |
| 직렬화 | JSON | CBOR |
| 만료 | exp claim | expires_at |
| 발행자 | iss claim | issuer 미포함 (public key implicit) |
| 대상 | sub/aud | agent_id |
| 리소스 | custom claim | tool |
| 단일 사용 | 일반적으로 없음 | nonce + ReplayGuard |
| Context binding | 없음 | session_id |

**결론**: 형태는 signed token이다. 두 가지 차별점이 있다:
1. **session_id binding** — JWT에는 이 개념이 없다
2. **single-use nonce** — JWT는 일반적으로 재사용 가능하다

---

## 2. Session binding이 의미 있는가?

### 의미 있다 — 그러나 조건부다

`session_id` binding이 추가하는 것:

```
같은 agent + same tool capability라도
다른 session에서는 사용할 수 없다
```

테스트 `session_binding_is_enforced`가 이를 확인한다. session_a를 위해 발행된 capability는 session_b에서 사용할 수 없다.

**이것이 의미 있는 경우:**

- AIS session이 "이 inference interaction"을 cryptographically 표현할 때
- capability가 "특정 추론 맥락에서만 이 도구를 사용할 수 있다"를 표현할 때

**이것이 의미 없는 경우:**

- 현재 v0에서 session이 단순히 "16바이트 배열이 일치하는가"로 축약될 때
- AIS session의 MAC 검증, replay protection이 함께 동작하지 않는 standalone 사용 시

**솔직한 평가**: session binding의 가치는 AIS session 전체 컨텍스트에서만 의미 있다. 이 crate을 독립적으로 사용하면 "session_id라는 이름의 필드를 가진 JWT"와 구별이 어렵다.

---

## 3. OPA/Cedar가 이것을 할 수 있는가?

### 대답: 기술적으로 yes, 의미적으로는 yes

**OPA Rego로 동일한 검증 표현:**

```rego
allow {
  input.signature_valid          # 별도 검증 후
  now < token.expires_at
  input.agent_id == token.agent_id
  input.session_id == token.session_id
  input.tool == token.tool
  not data.used_nonces[token.nonce]
}
```

이 정책은 v0 verifier와 동등하다.

**그러나 OPA는 다음을 제공하지 않는다:**

- `inference session`이라는 개념이 first-class로 존재하지 않는다
- 각 조직이 "session_id"를 어떻게 표현할지 직접 정의해야 한다
- AIS session continuity, replay guard와 통합된 표준 방법이 없다

**결론**: OPA로 동일한 것을 구현할 수 있다. AIS-Capability가 제공하는 것은 **AI agent authorization의 표준화된 표현과 AIS 인프라와의 통합**이다. 그것이 충분히 차별화되는지는 실제 사용 사례에서 검증되어야 한다.

---

## 4. 진짜 "AI-native"한 것은 무엇인가?

### Single-use, session-bound 조합

가장 AI-specific하게 느껴진 것:

```
capability가 단 한 번의 inference interaction에만 유효하다
```

이것을 다시 표현하면:

- `session_id` — 이 capability는 "어떤 inference session"에 귀속된다
- `nonce` — 이 capability는 "이 세션 내에서 한 번만" 사용된다

전통적인 authorization:
```
"service account X는 prod deploy API를 호출할 수 있다"  ← 반복적
```

AIS-Capability v0:
```
"이 세션 내에서, 이 에이전트는 prod deploy를 한 번 호출할 수 있다"
```

이 "이 세션 내에서, 한 번만"이 AI agent의 tool use 패턴과 자연스럽게 대응된다. 에이전트의 각 tool call은 특정 inference 맥락에서 발생하는 단일 이벤트다.

---

## 5. 어떤 가정이 약한가?

### 약점 1: Context conditions 없음

v0에서 가장 크게 빠진 것은 `context_conditions`다. 

```
원래 vision:
  allow deploy only if:
    - user_class = "internal"
    - request_risk = "low"
    - ...

v0 실제:
  allow deploy if:
    - agent 맞음
    - session 맞음
    - tool 맞음
    - 만료 안 됨
    - replay 아님
```

context conditions 없이 "context-aware authorization"이라는 주장은 매우 약하다. v0는 context-binding이 아닌 session-binding이다.

### 약점 2: Tool hash 없음

MCP tool poisoning 방어 (C 방향)가 v0에 없다. tool 이름만 검증하고 tool description의 무결성은 검증하지 않는다. `deploy_prod`라는 이름의 tool이 실제로 예상하는 것을 하는지 보증하지 못한다.

### 약점 3: 발행자 연쇄 없음

capability를 누가 발행했는지 token 자체에 포함되지 않는다. public key가 "신뢰할 수 있는 발행자의 것"인지 확인하는 메커니즘이 없다. 이것은 기존 AI Certificate의 CA ecosystem 부재 문제와 동일한 구조다.

### 약점 4: ReplayGuard가 인메모리

단일 프로세스, 재시작 시 소실. 실제 distributed deployment에서는 별도의 distributed nonce store가 필요하다. v0의 ReplayGuard는 research 목적에는 충분하지만 production에는 부족하다.

---

## 6. Verifier의 실패 순서가 중요한가?

### 예상보다 중요하다

구현 중 발견된 것: 실패 순서가 보안 속성에 영향을 미친다.

현재 순서: signature → expiry → agent → session → tool → replay

**nonce를 replay 단계(마지막)에서만 소모하는 것이 중요하다:**

```
wrong_agent → AgentMismatch → nonce 소모되지 않음 → 올바른 에이전트가 나중에 사용 가능
```

만약 nonce를 먼저 소모했다면:

```
wrong_agent → nonce 소모됨 → AgentMismatch
  → 올바른 에이전트가 나중에 시도해도 ReplayDetected
```

이 설계는 "실패한 검증이 legitimate use를 방해하지 않는다"는 보안 속성을 구현한다. 테스트 `failed_agent_check_does_not_burn_nonce`가 이를 검증한다.

이 속성이 AI-specific하게 의미 있는지: 에이전트가 capability를 잘못 제시했을 때 capability를 소진시키지 않는 것은 실용적이다.

---

## 7. 가설은 구현 후 강해졌는가, 약해졌는가?

### 부분적으로 강해졌고, 부분적으로 약해졌다

**강해진 것:**

- Session-bound single-use authorization의 구현 자체는 clean하다. 코드가 명확하고 테스트가 통과한다.
- Fail-ordered verifier의 설계가 생각보다 의미 있다 — 순서가 보안 속성에 영향을 미친다.
- "이 세션에서, 이 에이전트가, 이 도구를 한 번만 사용할 수 있다"는 AI tool use의 자연스러운 표현이다.

**약해진 것:**

- context conditions 없이 "context-aware"라고 부를 수 없다. 현재는 "session-scoped signed permission"에 더 가깝다.
- OPA와의 실질적 차이가 v0에서는 크지 않다. tool hash, context conditions, delegation이 없으면 OPA + 일부 Rego로 동등하게 구현 가능하다.
- AIS session과 분리해서 사용하면 그냥 "session_id 필드가 있는 JWT"다.

### 가설의 현재 상태

H1("high-assurance AI 인터랙션이 표준화된 trust guarantees로부터 이익을 얻을 수 있는가")에 대해:

- v0는 그 가능성의 skeleton을 만들었다
- 가설이 "yes"가 되려면 context conditions + tool integrity + AIS session 통합이 함께 필요하다
- v0 단독으로는 "yes"를 주장하기 어렵다

---

## 다음 단계 (있다면)

v0가 meaningful하다는 것을 입증하려면 다음이 필요하다:

1. **Context conditions 추가** — `user_class`, `request_risk` 같은 inference-time context를 capability에 포함
2. **Tool hash 통합** — tool description의 sha3-256을 capability에 bind
3. **AIS session 통합** — AIS session의 MAC + replay protection과 capability verification을 함께 사용하는 example

이 세 가지 없이는 AIS-Capability의 "AI-native" 주장이 약하다.

그리고 가장 중요한 것: **실제 enterprise agent 환경에서 이 capability token format을 사용해보는 것**. 코드가 맞더라도 실제 pain을 해결하지 못하면 가설은 여전히 검증되지 않는다.

---

*작성일: 2026년 5월
구현: `crates/ais-capability/`
설계 참조: [capability_v0.md](capability_v0.md)
가설: [h1_validation.md](h1_validation.md)*
