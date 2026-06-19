# AIS-Capability v1: 구체적 시나리오 비교 분석

> 작성 관점: 회의적인 엔터프라이즈 보안 설계자 + OPA 엔지니어 + 적대적 검토자.
> AIS를 옹호하지 않는다. 기존 스택이 더 나으면 그렇게 말한다.

---

## 시나리오

**환경**: 회사 내부 AI 배포 에이전트

**플로우**:
1. 엔지니어가 AI에게 "deploy ticket #1832"를 요청한다
2. AI가 롤아웃 계획을 분석한다
3. AI가 `deploy_prod` 도구 호출을 시도한다

**보안 요구사항**:
- `deploy_prod`만 허용 (다른 도구 차단)
- human approval 필수
- 5분 TTL
- 단일 실행 (동일 승인으로 두 번 배포 불가)
- 재전송 차단
- 잘못된 도구/에이전트/세션 차단

---

## 1. 시나리오 상세 비교

### Approach A: 기존 엔터프라이즈 스택

**구체적 구현**:

```
구성요소:
  - deploy-agent: Kubernetes 서비스 계정 (RBAC)
  - 승인 시스템: Slack bot → Redis approved_jobs::{job_id}
  - 정책 엔진: OPA (Envoy sidecar로 배포)
  - 인증: JWT (OIDC, 5분 만료)
  - 멱등성: job_id (UUID, Redis SET NX)
```

**실제 흐름**:

```
1. AI 오케스트레이터가 deploy_prod 호출 준비
2. 승인 요청:
   POST /approval-service/request
   { "job_id": "uuid-1832", "tool": "deploy_prod",
     "agent": "deploy-agent", "plan": "..." }
   → Slack 메시지 전송

3. 엔지니어가 Slack에서 "Approve" 클릭
   → Redis: approved_jobs::uuid-1832 = { approved_at, approver }

4. 오케스트레이터가 deploy_prod 호출 시도:
   JWT (sub=deploy-agent, exp=T+300) 포함

5. OPA 정책 평가:
   allow {
     input.tool == "deploy_prod"
     input.agent == "deploy-agent"
     data.approved_jobs[input.job_id].approved_at >= time.now() - 300
     not data.executed_jobs[input.job_id]  # 단일 실행
   }

6. OPA → allow
   → 실행, Redis: executed_jobs::uuid-1832 = true

7. OPA → deny
   → 차단, 이유 로그
```

**이것이 이미 해결하는 것**:
- deploy_prod만 허용 ✓
- human approval ✓
- 5분 TTL ✓
- 단일 실행 (job_id + executed_jobs) ✓
- 재전송 차단 (executed_jobs) ✓
- 잘못된 에이전트 차단 (JWT sub 검증) ✓
- 잘못된 도구 차단 (OPA policy) ✓

---

### Approach B: AIS-Capability v1

**실제 구현 (현재 코드)**:

```rust
// 발행 (승인 후)
let cap = issue_capability(
    Capability {
        session_id: current_ais_session,
        agent_id: deploy_agent_id,
        tool: "deploy_prod".to_string(),
        expires_at: now + 300,
        nonce: generate_nonce(),
        condition: Some(ContextCondition::HumanApproved),
    },
    &issuer_private_key,
)?;

// 검증 (도구 호출 시)
verify_capability(
    &cap,
    "deploy_prod",
    &deploy_agent_id,
    &current_ais_session,
    now,
    &issuer_public_key,
    &mut replay_guard,
    &VerificationContext { human_approved: approval_state },
)?;
```

**흐름**:

```
1. AI가 deploy_prod 호출 의도 선언
2. AIS 오케스트레이터가 승인 요청 (별도 채널, AIS 밖)
3. 엔지니어 승인 → approval_state = true
4. 발행자가 HumanApproved condition 포함한 SignedCapability 발행
5. 에이전트가 capability + ctx 제시
6. AIS verifier: 서명 → 만료 → 에이전트 → 세션 → 도구 → 조건 → 재전송 순서로 검증
7. 통과 시 실행, nonce 소비
```

---

## 2. 의미적 비교

### 진짜 다른 것

**하나만 있다**: 승인 요구사항이 서명된 토큰 내부에 있다.

```
Approach A (OPA):
  "deploy_prod를 실행하려면 승인이 필요하다"
  → 서버 사이드 정책 (수정 가능)
  → 토큰과 분리됨

Approach B (AIS-Capability v1):
  "이 토큰은 HumanApproved 조건을 요구한다"
  → Ed25519 서명에 포함됨
  → 토큰 수정 시 서명 무효화
  → 발행자가 다시 서명하지 않는 한 조건 변경 불가
```

구체적으로 의미하는 것: 나중에 "이 배포가 승인을 요구했는가?"라는 감사 질문에 대해, AIS는 토큰 자체가 불변의 cryptographic 증거가 된다. OPA 정책은 그 이후에 수정될 수 있다.

### 재포장에 불과한 것

나머지 5가지는 기존 스택이 이미 제공하는 것의 재포장이다.

| 보안 속성 | Approach A | Approach B | 실질적 차이 |
|---|---|---|---|
| 도구 제한 | OPA 정책 | 서명된 tool 필드 | 없음 (동등한 보증) |
| 단일 실행 | idempotency key | nonce + replay guard | 없음 (동등한 보증) |
| TTL | JWT exp | expires_at | 없음 (동등한 보증) |
| 에이전트 바인딩 | JWT sub | agent_id | 없음 (동등한 보증) |
| 세션 바인딩 | job_id / workflow_id | session_id | 거의 없음 (이름만 다름) |
| **승인 요구사항 증명** | **수정 가능한 OPA 정책** | **불변 서명 조건** | **있음** |

"세션 바인딩"에 대해 더 정확히 말하면:

```
Approach A의 "session": job_id (배포 작업 단위)
Approach B의 "session": AIS inference session (AI 추론 상호작용 단위)
```

이 두 개념은 이 시나리오에서 사실상 동일하다. 엔지니어가 "deploy ticket #1832"를 요청한 상호작용이 하나의 단위이고, 그것이 job_id이자 inference session이다. AIS의 session binding이 새로운 보안을 추가하지는 않는다.

---

## 3. 보안 분석

### AIS-Capability v1이 개선하는 공격

**1. 내부자에 의한 정책 변조**

OPA 정책은 서버 사이드 상태다. OPA 인프라에 접근 권한이 있는 내부자가 승인 요구사항을 조용히 제거할 수 있다.

```
수정 전: data.approved_jobs[input.job_id] 확인 필요
수정 후: 해당 줄 삭제
→ 이제 승인 없이 배포 가능
```

AIS-Capability v1에서 이 공격은 실패한다. 조건을 제거하려면 토큰을 재발행해야 하고, 재발행은 로그에 남는다.

**그러나**: 이 공격이 실제 엔터프라이즈 위협 모델에서 우선순위가 높은가? OPA 변경은 일반적으로 Git 기반 변경 관리, CI/CD 파이프라인, 다중 승인을 거친다. 이것이 현실적 공격 벡터인지는 조직에 따라 다르다.

**2. 토큰 이식(Token Portability) 공격 완화**

AIS session_id binding으로 인해, 훔친 capability token을 다른 세션에서 재사용하기 어렵다. 일반적인 JWT bearer token은 세션에 묶이지 않는 경우가 많다.

**그러나**: session binding은 OPA에서도 job_id 또는 session claim으로 구현 가능하다. 이것은 OPA의 기술적 한계가 아니라 구현 선택의 문제다.

### 변화 없는 공격

**1. 프롬프트 인젝션**

외부 소스의 악의적 텍스트가 AI를 조작해 "deploy ticket #9999"를 요청하도록 만들 수 있다. AIS capability는 올바른 에이전트가 올바른 도구를 호출하는 것을 검증하지, AI가 왜 그것을 호출하는지를 검증하지 않는다. 이 공격에서 AIS는 무력하다.

**2. 발행자 손상**

capability를 발행하는 서비스가 손상되면, 공격자는 HumanApproved 조건 없이 유효한 token을 발행할 수 있다. 이것은 OPA 서버 손상과 동등한 위협이다.

**3. ctx.human_approved 우회**

이것이 v1의 가장 심각한 약점이다.

```rust
verify_capability(
    &cap,
    "deploy_prod",
    &agent,
    &session,
    now,
    &public_key,
    &mut guard,
    &VerificationContext { human_approved: true },  // ← 이 값을 누가 보장하는가?
)
```

AIS verifier는 토큰이 `HumanApproved`를 요구한다는 것을 검증한다. 그러나 `ctx.human_approved = true`를 어떻게 채우는지는 AIS 외부 문제다. 이 boolean을 설정하는 코드가 손상되면 조건이 우회된다.

이것은 Approach A의 `data.approved_jobs[job_id]` Redis 조회와 동등한 취약점이다. 공격 표면이 이동했을 뿐, 제거되지 않았다.

**4. 환각으로 인한 잘못된 배포**

AI가 ticket #1832가 아닌 다른 것을 배포하기로 잘못 결정할 수 있다. capability는 "deploy_prod를 호출할 수 있는가"를 확인하지, "올바른 것을 배포하는가"를 확인하지 않는다.

---

## 4. 엔터프라이즈 현실 평가

**"우리는 이미 OPA + approval + JWT로 이것을 한다"는 주장이 성립하는가?**

성립한다. 구체적으로:

숙련된 엔터프라이즈 보안 엔지니어가 이 시나리오를 보면 다음과 같이 말할 것이다:

```
"당신이 구현한 것의 95%는 우리가 이미 하는 것입니다.
 나머지 5%는 '승인 요구사항이 서명된 토큰에 포함된다'는 것인데,
 우리 위협 모델에서 OPA 정책 변조는 우선순위가 낮습니다.
 정책 변경은 GitOps 워크플로우로 추적되고, 다중 리뷰어가 있으며,
 변경 감사 로그가 있습니다.
 AIS-Capability를 도입하면 새로운 infrastructure 복잡도가 추가되고,
 CA 관리와 session lifecycle을 새로 구현해야 합니다.
 현재 pain point가 없는 문제에 대한 해결책입니다."
```

이것은 합리적인 반론이다.

**"OPA + approval + JWT"로 충분하지 않은 경우:**

1. **규제 감사 시 "이 배포에 승인이 요구됐다는 증거"를 제시해야 할 때**: OPA 정책은 사후 변경 가능하지만 AIS 토큰은 불변 cryptographic 증거를 제공한다. HIPAA, SOC 2 감사자가 정책 기록 대신 배포 토큰 자체를 요구하는 경우.

2. **Multi-vendor agent 환경에서**: 서로 다른 벤더의 에이전트 프레임워크가 공통 capability token format을 사용해야 할 때 표준화 가치가 생긴다. 단일 조직 단일 프레임워크라면 OPA로 충분하다.

3. **Policy 서버를 신뢰하기 어려운 환경**: Air-gapped 시스템이나 내부자 위협이 실제로 높은 환경에서.

---

## 5. 최종 판단

**판정: B — AIS-Capability v1은 대부분 기존 authorization과 유사하며 의미적 차이가 소폭 있다**

선택 근거:

단순한 signed JWT 수준이 아닌 이유(C가 아닌 이유):
- session binding이 실제로 구현되어 있고
- single-use nonce가 작동하고
- 조건이 서명에 포함되는 것은 진짜 추가다

그러나 "의미 있게 다르다"(A)고 할 수 없는 이유:
- 이 시나리오의 7가지 보안 요구사항 중 6개는 기존 스택이 이미 동등하게 제공한다
- 실질적으로 추가되는 것은 "승인 요구사항의 불변 cryptographic 증명" 하나다
- 대부분의 엔터프라이즈 위협 모델에서 이것은 필수가 아닌 Nice-to-have다
- `ctx.human_approved`의 신뢰성이 AIS 외부에 의존하며, 이것이 핵심 약점이다

---

## 6. 가장 강한 비판

**AIS-Capability v1의 핵심 결함: `human_approved`는 boolean 패스-스루다**

현재 구현:

```rust
pub struct VerificationContext {
    pub human_approved: bool,
}
```

이 boolean이 `true`로 채워지는 코드가 신뢰의 실제 경계다. AIS-Capability verifier는 토큰이 승인을 요구한다는 것을 보장하지만, 승인이 실제로 이루어졌다는 것을 보장하지 않는다.

이것은 근본적인 아키텍처 문제다:

```
AIS가 보장하는 것:
  "이 토큰은 human_approved = true를 요구한다"

AIS가 보장하지 않는 것:
  "human_approved가 실제로 human에 의해 설정되었다"
```

이 gap을 메우려면 AIS가 IAM 시스템, approval workflow, 사용자 인증과 통합되어야 한다. 그 통합이 없으면 악의적 또는 버그가 있는 코드가 `VerificationContext { human_approved: true }`를 설정해 조건을 우회할 수 있다.

Approach A에서 OPA는 Redis를 조회해 승인을 확인한다. 이것도 Redis가 손상되면 우회 가능하지만, 승인 상태가 외부 시스템에 저장되어 있어 AIS보다 명확한 신뢰 체인을 가진다.

**결론**: AIS-Capability v1에서 "HumanApproved" 조건은 capability token 레벨에서는 강하지만, 런타임 검증 레벨에서는 호출자가 제공하는 boolean에 의존하며 그 boolean의 신뢰성은 AIS 범위 밖이다. 이것은 사람들이 "AI-native authorization"에서 기대하는 것보다 훨씬 약한 보증이다.

---

## 7. 가장 강한 옹호

**AIS-Capability v1의 실제 가치: 불변 정책 귀속(immutable policy attribution)**

기존 OPA+JWT 스택에서:

```
질문: "2026년 5월 18일 오후 2시 32분에 실행된 이 배포는 human approval을 요구했는가?"

대답: "당시 OPA 정책을 확인해야 한다. 그런데 그 정책은 이후에 수정됐을 수 있다."
```

AIS-Capability v1에서:

```
질문: "이 배포는 human approval을 요구했는가?"

대답: "예. 배포 시 사용된 capability token에 HumanApproved condition이 포함되어 있으며,
     issuer의 Ed25519 서명으로 변조 불가능하게 바인딩되어 있습니다.
     이 토큰은 2026-05-18T14:27:00Z에 발행되었고, 서명은 현재도 유효합니다."
```

이것은 HIPAA, SOC 2, EU AI Act 감사 맥락에서 실질적 가치를 가진다. 정책 파일이 언제 어떻게 변경됐는지를 추적하는 것보다, 각 실행 당시의 정책이 실행 자체에 포함된 것이 감사적으로 더 강하다.

**좀 더 구체적으로**:

병원이 AI 배포 에이전트를 운영한다고 가정하면. HIPAA 감사에서 "이 AI 에이전트의 각 배포 결정에 human oversight가 있었는가?"를 증명해야 한다. OPA 정책 기록과 CI/CD 변경 이력으로 이를 증명하는 것은 가능하지만 간접적이다. 각 실행의 capability token이 "HumanApproved를 요구했다"는 것을 cryptographically 증명하는 것은 직접적이고 부인 불가능하다.

이것이 AIS-Capability v1의 가장 좁지만 가장 방어 가능한 가치 제안이다: **런타임 보안 강화가 아니라 감사 가능성 향상(auditability improvement)**.

---

## 결론

AIS-Capability v1은 enterprise deployment agent 시나리오에서:

- **하지 않는 일**: 기존 OPA + approval + JWT가 해결하지 못하는 런타임 공격을 막음
- **하는 일**: 정책 요구사항(특히 approval)을 서버 사이드 상태에서 토큰 내 불변 서명으로 이동시킴
- **핵심 약점**: `human_approved` boolean의 신뢰성이 AIS 외부에 의존
- **핵심 가치**: 감사 맥락에서 "이 실행에 이 조건이 요구됐음"을 cryptographically 증명

숙련된 보안 엔지니어가 "우리는 이미 이것을 OPA로 한다"고 말하는 것은 6/7 속성에 대해 정확하다. 나머지 1/7(불변 정책 귀속)이 얼마나 중요한가는 조직의 규제 요구사항과 위협 모델에 따라 다르다.

---

*작성일: 2026년 5월
구현 기반: `crates/ais-capability/`
설계 참조: [capability_v0.md](capability_v0.md), [capability_v1_experiment.md](capability_v1_experiment.md)*
