# AIS-Capability v0: 설계 초안

> 연구에서 설계로 넘어가는 첫 번째 문서.
> AIS-Capability가 무엇을 하려는지, 기존 시스템과 어떻게 다른지,
> 그리고 최소 구현 범위가 무엇인지를 정의한다.
> 이 문서는 AIS-Capability가 필요하다고 가정하지 않는다.
> 설계를 기술하면서 동시에 반증 조건을 유지한다.

---

## 1. Problem

### AI 에이전트가 만드는 authorization 갭

기존 RBAC/OAuth의 authorization 모델:

```
identity → has permission → resource
```

이것은 정적(static) 모델이다. "서비스 계정 X는 API Y를 호출할 수 있다." 권한은 identity에만 종속된다.

AI 에이전트 환경에서 실제로 필요한 것:

```
(identity, inference context, session state, interaction lineage)
→ may have permission
→ specific tool
→ under specific constraints
```

구체적인 예:

```
배포 에이전트가 prod deploy tool을 호출할 수 있는 조건:
  AND: 이 세션에서 사람이 명시적으로 승인했다
  AND: 이 세션의 request class가 low-risk로 분류되었다
  AND: 이 세션 내에서 아직 deploy를 호출하지 않았다 (max 1회)
  AND: 세션이 재전송된 것이 아니다
  AND: 이 tool description이 등록된 것과 일치한다
```

기존 RBAC는 이 중 "배포 에이전트가 deploy API를 호출할 수 있다"까지만 표현한다. 나머지 조건들은 각 팀이 애플리케이션 레이어에서 직접 구현해야 한다.

### 이것이 문제인가?

**현재**: 대부분의 조직이 애플리케이션 레이어에서 이를 처리하거나, 단순히 처리하지 않는다. 실질적인 운영 피해 사례는 아직 충분히 문서화되지 않았다.

**미래 시나리오**: 에이전트가 더 자율적이고 consequential한 행동을 할수록, 이 조건들을 각 팀이 달리 구현하는 것이 불일치와 취약점을 만들 가능성이 있다.

**정직한 현재 판단**: 이것이 "지금 당장 해결해야 하는 심각한 문제"인지는 아직 불명확하다. 이 설계는 그 가능성을 탐색하는 prototype이다.

---

## 2. 기존 접근법 비교

### RBAC (Role-Based Access Control)

```
장점:  단순, 이해하기 쉬움, 어디서나 지원됨
단점:  role이 static, context-aware 불가
표현:  "deploy-agent role은 deploy API를 호출할 수 있다"
갭:    세션 상태, 호출 횟수 제한, 동적 조건 표현 불가
```

### ABAC (Attribute-Based Access Control)

```
장점:  속성 기반으로 더 유연
단점:  속성 정의가 시스템마다 다름, AI 개념 없음
표현:  "user.department=engineering AND resource.env=prod → allow"
갭:    inference session, tool chain state를 attribute으로 정의해야 함
      — 표현 가능하지만 비표준
```

### OPA/Rego

```
장점:  매우 표현력 높음, formal semantics, 사이드 이펙트 없음
단점:  AI 개념을 직접 정의해야 함, 팀마다 다르게 구현됨
표현:  inference session, tool call count, session state를
       Rego로 표현 가능 — 그러나 표준 없음
갭:    "inference-session-aware policy"를 작성하는 표준 방법이 없다
```

**중요 수정**: OPA는 여기서 설명하는 모든 것을 기술적으로 표현할 수 있다. 문제는 기술적 표현 가능성이 아니라 **표준화 부재**다.

조직마다 "inference session"을 다르게 정의하고, "tool call lineage"를 다르게 추적하고, "session-bound permission"을 다르게 구현한다. AIS-Capability가 제안하는 것은 이 AI-specific 개념들의 공통 표현 방식이다.

### AWS IAM / Cedar

```
장점:  선언적, 검증 가능, AWS 환경에서 강력
단점:  AI agent semantics 없음, inference context 개념 없음
갭:    ABAC와 유사 — 표현 가능하지만 AI 개념 비표준
```

### 비교 요약

| 시스템 | AI-native semantics | Session binding | Tool integrity | 표준화 |
|---|---|---|---|---|
| RBAC | ✗ | ✗ | ✗ | ✓ (범용) |
| ABAC | ✗ (직접 정의) | ✗ | ✗ | 부분 |
| OPA/Rego | ✗ (직접 정의) | ✗ (직접 정의) | ✗ | ✗ (조직별) |
| Cedar | ✗ (직접 정의) | ✗ | ✗ | 부분 |
| AIS-Capability (제안) | ✓ | ✓ | ✓ (C와 결합) | 목표 |

핵심 차이: AIS-Capability의 목표는 기존 시스템보다 "더 강력한" 정책 엔진이 아니라, AI agent authorization에 특화된 **공통 semantics layer**다.

---

## 3. AIS-Capability 가설

### 핵심 개념: Inference-Session-Bound Authorization

```
Capability = 특정 inference session 안에서
             특정 조건이 충족될 때만
             특정 tool을 호출할 수 있는 권한
```

이것이 기존 permission과 다른 점:

```
기존 permission:  identity에 종속 (정적)
AIS Capability:   identity + session + context에 종속 (동적)
```

### 표현 목표

다음 조건들을 표준화된 Capability token으로 표현:

1. **Tool scope**: 어떤 tool을 호출할 수 있는가
2. **Session binding**: 어떤 session에서만 유효한가
3. **Invocation constraints**: 최대 호출 횟수, TTL
4. **Context conditions**: 어떤 context 조건이 충족되어야 하는가
5. **Approval requirements**: 인간 승인이 필요한가
6. **Attenuation**: 위임 시 권한이 좁아질 수만 있다 (확장 불가)

### 이것이 충분히 차별화되는가?

솔직한 평가:

- 기술적 표현: OPA/Cedar로 대부분 가능
- 차별점: AI 개념의 공통 표현 → 다른 agent frameworks 간 interoperability
- 가장 강한 주장: Tool integrity (C)와 결합될 때 — capability가 specific tool version에 cryptographically bind됨
- 약한 주장: 단일 조직 내 단일 framework에서만 사용될 경우 OPA로 충분할 수 있음

**이 설계의 가치는 multi-framework, multi-organization agent interoperability가 실제로 필요해질 때 가장 커진다. 현재 그 필요성은 emerging이지 established가 아니다.**

---

## 4. Capability Token 설계

### 기본 구조

```json
{
  "version": 1,
  "cap_id": "<uuid>",
  "issued_at": 1748000000,
  "expires_at": 1748000300,

  "subject": {
    "agent_id": "deploy-agent-v2",
    "session_id": "<session-uuid>"
  },

  "resource": {
    "tool": "deploy_prod",
    "tool_hash": "<sha3-256 of tool description>"
  },

  "constraints": {
    "max_invocations": 1,
    "requires_human_approval": true,
    "valid_in_session_only": true,
    "context_conditions": {
      "user_class": ["internal"],
      "request_risk": ["low", "medium"]
    }
  },

  "delegation": "none",

  "issuer": "<issuer-id>",
  "signature": "<ed25519-signature>"
}
```

### 필드 설명

**`session_id`**: Capability가 특정 AIS session에만 유효하다. 세션 밖에서 사용 시 거부. 이것이 기존 token과의 핵심 차이다.

**`tool_hash`**: Tool description의 SHA3-256. Tool integrity와 결합 — "이 tool description이 바뀌지 않았을 때만 유효". MCP tool poisoning 방어의 기술적 표현.

**`max_invocations`**: 이 capability로 tool을 호출할 수 있는 최대 횟수. 한 번 사용 후 소진.

**`requires_human_approval`**: 프록시가 human approval 신호를 확인한 후에만 허가. (현재 "approval"의 표현 방식은 미정 — 이것이 v0의 한계 중 하나)

**`valid_in_session_only`**: true이면 다른 세션에서 이 token을 재사용할 수 없다.

**`delegation`**: `none`이면 이 capability를 다른 에이전트에게 위임 불가. Object-Capability Model의 attenuation only 원칙.

### Attenuation 예시

```
원본 capability:
  tool: "*"  (모든 tool)
  max_invocations: unlimited
  context: any

위임 가능한 capability (좁아짐):
  tool: "read_db"  (축소)
  max_invocations: 3  (제한)
  context: { user_class: ["internal"] }  (조건 추가)

위임 불가능 (확장):
  tool: "deploy_prod"  (원본에 없음)
  max_invocations: unlimited  (원본보다 넓음)
```

---

## 5. Threat Model

### AIS-Capability가 다루는 위협

**과잉 행동(Over-action):**
에이전트가 세션 컨텍스트를 벗어나 허가되지 않은 tool을 호출하려 할 때 거부.

**Tool 대체(Tool substitution):**
Tool description이 변경된 tool을 호출하려 할 때 거부 (tool_hash 검증).

**세션 재전송(Session replay):**
만료된 세션의 capability token을 재사용하려 할 때 거부.

**위임을 통한 권한 상승(Delegation escalation):**
에이전트가 자신이 받은 것보다 더 넓은 권한을 sub-agent에게 위임하려 할 때 거부.

**무단 컨텍스트 실행:**
허가된 user class가 아닌 컨텍스트에서 tool을 호출하려 할 때 거부.

### AIS-Capability가 다루지 않는 위협 (명시적)

**프롬프트 인젝션:**
에이전트가 이미 허가받은 tool을 악의적 프롬프트에 속아 사용하는 경우 — capability는 "사용 가능한지"를 검증하지, "사용 결정이 올바른지"를 검증하지 않는다.

**환각으로 인한 잘못된 tool 호출:**
모델이 잘못된 reasoning으로 올바른 tool을 잘못 호출 — reasoning quality는 capability scope 밖이다.

**학습 단계 백도어:**
모델 자체에 심어진 악의적 행동 — capability는 inference layer에서 작동하지 training layer에서 작동하지 않는다.

**Capability 발행자 자체 손상:**
발행자가 악의적인 capability를 발행 — CA 생태계 신뢰 문제와 동일하다.

이 항목들은 AIS-Capability의 설계 범위가 아님을 명확히 해야 한다. Capability는 "authorized scope 내에서 올바르게 행동하는가"가 아니라 "authorized scope 내에서 행동하는가"를 검증한다.

---

## 6. OPA/Cedar와의 정직한 비교

### OPA가 이것을 할 수 있는가?

**대답: 기술적으로 가능하다.**

다음 Rego 코드는 위 조건 대부분을 표현할 수 있다:

```rego
allow {
  input.agent == "deploy-agent-v2"
  input.session_id == data.active_sessions[_]
  count(data.invocations[input.session_id]["deploy_prod"]) < 1
  input.user_class == "internal"
  data.approvals[input.session_id]["deploy_prod"] == true
}
```

**그러나:**

1. `inference session`이라는 개념을 각 조직이 `data.active_sessions`에 직접 정의해야 한다
2. `tool_hash` 검증을 OPA 정책에 포함하는 표준 방법이 없다
3. AIS session과 OPA 간 통합 레이어를 직접 구축해야 한다
4. 다른 agent framework(LangChain, AutoGen, CrewAI)와 이 정책이 호환되지 않는다

**핵심**: OPA가 표현 불가능한 것이 아니라, **AI-native 개념의 표준화된 표현**이 없는 것이다. AIS-Capability가 제안하는 것은 이 공통 어휘(vocabulary)다.

### AIS-Capability가 OPA보다 나은 조건

- 여러 agent framework가 공통 capability token format을 사용해야 할 때
- Tool integrity (tool_hash)를 authorization logic에 통합할 때
- AIS session continuity와 capability를 함께 검증할 때

### OPA가 AIS-Capability보다 나은 조건

- 단일 조직의 단일 framework에서만 사용될 때
- 이미 성숙한 OPA 인프라가 있을 때
- AI-specific interoperability가 필요하지 않을 때

**이 비교가 중요하다**: AIS-Capability를 "OPA 대체"로 포지셔닝하면 안 된다. "AI-native authorization semantics의 표준화"로 포지셔닝해야 한다.

---

## 7. Minimal Prototype Scope

v0에서 구현할 것과 하지 않을 것.

### 구현할 것 (v0)

```rust
// 1. Capability token 데이터 구조
struct Capability {
    cap_id:       [u8; 16],
    session_id:   [u8; 16],
    agent_id:     String,
    tool:         String,
    tool_hash:    Option<[u8; 32]>,
    constraints:  CapabilityConstraints,
    issued_at:    u64,
    expires_at:   u64,
    issuer:       String,
    signature:    [u8; 64],
}

struct CapabilityConstraints {
    max_invocations:       Option<u32>,
    requires_approval:     bool,
    valid_in_session_only: bool,
}

// 2. Capability 검증 함수
fn verify_capability(
    cap: &Capability,
    session_id: &[u8; 16],
    tool: &str,
    tool_hash: Option<&[u8; 32]>,
    invocation_count: u32,
    public_key: &[u8; 32],
) -> Result<(), CapabilityError>

// 3. Capability 발행 (단순화)
fn issue_capability(
    subject: CapabilitySubject,
    resource: CapabilityResource,
    constraints: CapabilityConstraints,
    private_key: &[u8; 32],
) -> Result<Capability, CapabilityError>

// 4. 호출 카운터 (세션 범위)
struct InvocationCounter {
    counts: HashMap<(SessionId, ToolName), u32>,
}
```

### 구현하지 않을 것 (v0)

```
✗ context_conditions 평가 (user_class, request_risk 등)
  → 이것은 policy engine 영역이며 v0 범위를 초과

✗ delegation 메커니즘
  → attenuation 검증 로직이 복잡, v1으로 延期

✗ human approval 통합
  → approval 신호의 표현 방식 미결정

✗ CA 인프라
  → v0는 local 신뢰 앵커 사용 (AI Certificate MVP와 동일)

✗ 분산 invocation counting
  → v0는 단일 프로세스 인메모리
```

### v0의 검증 목표

v0 구현을 통해 답하려는 질문:

1. Capability token + session binding이 기술적으로 작동하는가?
2. Tool hash 검증이 MCP-like 환경에서 의미 있게 통합되는가?
3. 기존 AIS session (replay guard, audit chain)과 Capability를 함께 사용하면 어떤 인터페이스가 나오는가?
4. 실제로 OPA와 비교했을 때 "AI-native semantics"가 구현 단순성을 높이는가, 아니면 오히려 복잡도를 증가시키는가?

이 네 가지 질문에 답하는 것이 v0의 목표다.

---

## 8. Open Questions

이 설계가 아직 답하지 않은 것들.

**Q1: Human approval을 어떻게 표현하는가?**

`requires_approval: true`를 설정했을 때, AIS 레이어는 "approval이 이루어졌다"는 신호를 어디서 받는가? 이것은 별도의 approval API가 필요하며, 현재 미설계 상태다.

**Q2: Context conditions의 범위를 어디까지 잡는가?**

`user_class: ["internal"]` 같은 조건은 누가 평가하는가? AIS 프록시가 이것을 평가하려면 user identity 정보를 알아야 하며, 이는 IAM 연동을 필요로 한다. v0에서 context conditions를 제외한 이유다.

**Q3: Multi-agent 위임 시 attenuation을 어떻게 검증하는가?**

Agent A가 Agent B에게 capability를 위임할 때, B가 받은 capability가 A의 capability보다 좁음을 cryptographically 검증하는 방법이 필요하다. 이것은 capability chain 검증 로직을 필요로 하며 v0 범위를 초과한다.

**Q4: 이것이 실제로 OPA + Rego 대비 개발자 경험을 개선하는가?**

가장 중요한 실용적 질문. AIS-Capability token이 AI agent 개발자에게 더 자연스러운가, 아니면 "그냥 OPA Rego로 쓰는 게 낫다"는 결론이 나오는가? v0 구현 후에만 답할 수 있다.

---

## 결론

이 문서는 AIS-Capability의 첫 번째 설계 초안이다.

핵심 주장:

- 기존 policy engine이 AI-specific authorization을 표현하지 못하는 것이 아니다
- 표준화된 AI-native authorization semantics가 없어 각 조직이 ad-hoc으로 구현한다
- AIS-Capability는 그 공통 어휘와 session binding을 제공하려 한다

이 주장이 실제 가치를 만드는지는 v0 구현 후 OPA와의 실제 비교, 그리고 enterprise 환경에서의 검증을 통해 확인되어야 한다.

현재 이 설계는 가설이다. 코드가 이를 검증하거나 반증할 것이다.

---

*작성일: 2026년 5월
참조: [why_ais.md](why_ais.md), [h1_validation.md](h1_validation.md),
[agent_incidents.md](agent_incidents.md),
[scenarios/enterprise_agent.md](scenarios/enterprise_agent.md)*
