# H1 검증 계획

> AIS 연구 가설을 지지하거나 반증하기 위한 증거 기준을 정의한다.
> 이 문서는 AIS를 옹호하지 않는다.

---

## 1. Research Question

### H1 가설

```
H1:

High-assurance AI interactions may benefit from
standardized trust guarantees
beyond ad-hoc application-level implementations.
```

### 각 용어의 정의

**"High-assurance AI interactions"**

모든 AI 시스템에 적용되는 것이 아니다. 다음 중 하나 이상에 해당하는 경우:

- AI의 결정이 법적·의료적·금융적 결과를 초래한다
- 자율 에이전트가 외부 시스템(DB, API, 배포 파이프라인)에 영향을 미친다
- 규제 감사(HIPAA, EU AI Act 등)에서 AI 인터랙션의 증거를 요구한다
- 모델 교체 또는 조작이 비즈니스·운영 리스크를 만든다

적용되지 않는 경우: 일반 챗봇, 텍스트 요약, 내부 검색 보조 등 결과에 책임이 따르지 않는 용도.

**"Trust guarantees"**

다음을 의미한다:

- 어떤 모델이 이 요청을 처리했는가 (model identity)
- 이 요청이 인증된 세션에서 왔는가 (session authenticity)
- 이 요청-응답 쌍을 나중에 귀속할 수 있는가 (attribution)
- 에이전트가 허가된 범위 내에서만 행동했는가 (capability bounds)

다음을 의미하지 않는다: 모델 출력의 정확성, 안전성, 공정성.

**"Standardized"**

인터넷 표준(TLS 같은 범용 프로토콜)을 의미하지 않는다.

단일 조직 내부의 일관된 구현이어도 이 가설을 충족한다:
- 동일 조직 내 여러 AI 시스템이 일관된 방식으로 trust를 구현
- 감사관이 모든 AI 인터랙션에 동일한 보증 수준을 기대할 수 있음

**"Beyond ad-hoc application-level implementations"**

현재 상태의 대안과 비교한다:
- 각 팀이 model logging, audit, permission을 독립적으로 구현
- 일관성 없음, 외부 검증 어려움, 조직 전체 신뢰 모델 부재

---

## 2. Why This Question Exists

### AI가 새로운 trust 문제를 만드는 이유

**자율 에이전트의 consequential actions:**

AI가 단순 답변 생성에서 tool 실행, DB 수정, 코드 배포, 외부 API 호출로 이동하면 "어떤 모델이 이 결정을 내렸는가"라는 질문의 중요성이 달라진다. OAuth는 "서비스 계정이 이 작업을 했다"를 기록하지만, "어떤 inference chain이 이 결정을 만들었는가"는 기록하지 않는다.

**Multi-step inference chains:**

에이전트가 여러 단계의 추론을 거쳐 최종 행동에 이르는 경우, 사후 재구성이 어렵다. 현재 표준 로그는 개별 API 호출을 기록하지, 추론 과정의 연속성을 추적하지 않는다.

**모델 provenance 불확실성:**

자체 호스팅 환경에서, 어떤 모델 버전이 실행 중인지 cryptographically 보증하는 메커니즘이 현재 표준화되어 있지 않다. TLS 서버 인증서는 서버 프로세스를 인증하지 모델 가중치를 인증하지 않는다 (`tls_overlap.md` §3.1 참조).

### 기존 시스템이 이미 충분할 수 있는 이유

동일하게 중요한 반론들:

**OAuth + RBAC로 대부분의 접근 제어가 가능하다.** "어떤 AI가 이 API를 호출했는가"는 서비스 계정으로 이미 추적 가능하다.

**SIEM + 애플리케이션 로깅으로 감사 요구사항을 충족할 수 있다.** 대부분의 규제기관은 "audit trail"을 요구하지 "cryptographic hash chain"을 명시하지 않는다. Splunk, Elastic의 서명 로그가 감사관을 만족시킬 수 있다.

**Kubernetes + Istio가 서비스 레벨 신뢰를 제공한다.** Service mesh 환경에서는 mTLS, 정책 제어, 감사가 이미 제공된다.

**현실적으로 호스팅 AI API가 지배적이다.** OpenAI, Anthropic API 환경에서는 모델 가중치에 접근할 수 없어 AI Certificate가 적용 불가능하다. 가장 많이 사용되는 환경에서 AIS 핵심 기능이 작동하지 않는다 (`scenarios/public_cloud_api.md` 참조).

---

## 3. H1을 지지하는 증거

### 이론적 지지 (현재 확인된 것)

**T1 — 규제 추세의 방향성**

EU AI Act(2024)는 고위험 AI 시스템에 technical documentation과 로깅을 요구한다 (Article 12-17). NIST AI RMF는 AI 시스템의 거버넌스와 감사 가능성을 강조한다. 이 방향이 "AI 인터랙션 신뢰 보증에 대한 규제 압력이 증가하고 있다"는 것을 보여준다.

**T2 — 에이전트 자율성 증가 추세**

AI 에이전트가 더 많은 도구 호출, 더 자율적인 행동, 더 긴 multi-step 추론을 수행하는 방향으로 이동하고 있다. 이 추세가 지속되면 "어떤 모델이 어떤 결정을 내렸는가"라는 귀속 문제는 더 pressing해질 것이다.

**T3 — 모델 신원에 대한 Gap 존재**

TLS는 서버 프로세스를 인증하지, 그 서버가 실행하는 모델을 인증하지 않는다. 이 gap은 기술적 사실이다 (`tls_overlap.md` §3.1). Self-hosted AI 환경에서 "올바른 모델이 실행 중인가"를 소프트웨어 레벨에서 보증하는 표준 메커니즘이 현재 없다.

### 실용적 지지 (아직 확인되지 않은 것)

**P1 — 규제 감사에서의 inference-specific 요구사항**

HIPAA, EU AI Act 감사관이 AI 추론 요청에 대해 "어떤 모델이 이 환자 관련 질의를 처리했는가"를 구체적으로 요구하는 사례. 현재 미확인.

**P2 — AI incident에서의 attribution failure**

AI 에이전트의 잘못된 행동을 사후 재구성하려 했으나 "어떤 모델 버전이 이 결정을 내렸는가"를 입증하지 못한 실제 사례. 현재 미확인.

**P3 — Ad-hoc 구현의 실질적 실패**

조직에서 팀마다 다른 AI audit/permission 구현으로 인해 실질적 보안 문제가 발생한 사례. 현재 미확인.

**P4 — Multi-agent 환경에서의 trust negotiation 문제**

에이전트 A가 에이전트 B의 결과를 신뢰해야 하는 상황에서, 각 에이전트의 trust model이 달라 문제가 발생한 사례. 현재 미확인.

**현재 상태**: 이론적 지지(T1-T3)는 어느 정도 확인되지만 실용적 지지(P1-P4)는 전부 미확인이다. H1의 실용적 가치는 P1-P4 중 하나 이상이 확인될 때 강화된다.

---

## 4. H1을 반증하는 조건

다음 중 하나 이상이 확인되면 H1은 약화되거나 무효화된다.

### F1 — 규제기관이 기존 로그를 수용한다

HIPAA, EU AI Act 감사 실제 사례에서 SIEM + 서명된 애플리케이션 로그가 AI 추론 감사 요구사항을 충족한다는 것이 확인된다면, AIS 감사 체인의 가치는 크게 감소한다.

**반증 가능성 평가: 높음.** 규제기관은 기술 중립적으로 "audit trail"을 요구하는 경우가 많다. 기존 인프라로 충분할 가능성이 상당하다.

### F2 — Ad-hoc 구현이 실제로 잘 작동한다

조직들이 팀별 독립 구현으로 AI audit, permission, model identity를 충분히 잘 관리하고 있으며, 표준화의 필요성을 체감하지 못한다.

**반증 가능성 평가: 높음.** 현재 고통의 증거가 없다. "있으면 좋겠다"와 "없어서 실제로 문제다"는 다르다.

### F3 — 호스팅 AI가 영구적으로 지배적이다

OpenAI, Anthropic, Google 같은 호스팅 AI API 사용이 계속 지배적이라면, AI Certificate가 적용되지 않는 환경이 대부분을 차지하고, AIS의 핵심 기능인 모델 신원 바인딩이 근본적으로 적용 불가능하다.

**반증 가능성 평가: 중간.** 현재 추세는 호스팅 AI 지배적이나, 기업 내부 모델 증가 추세도 존재한다.

### F4 — 조직들이 운영 부담을 거부한다

CA 인프라 운영, 세션 관리, AIS 프록시 유지 등의 운영 비용이 실질적 보안 이점보다 크다는 판단이 확인된다면, "technically valuable but operationally impractical"이 된다.

**반증 가능성 평가: 중간~높음.** 내부 PKI 운영 경험이 있는 조직은 소수다.

### F5 — TEE와 signed container가 더 강한 대안으로 정착한다

Intel TDX, AMD SEV, 서명된 컨테이너(sigstore/cosign)가 모델 무결성 보증의 표준이 되면, AIS AI Certificate가 존재 이유를 잃는다.

**반증 가능성 평가: 중간.** TEE는 비용과 운영 복잡도가 있어 중소 조직에서는 여전히 대안 필요.

### F6 — 측정 가능한 개선이 없다

실제 배포에서 AIS 적용 전후를 비교할 때, compliance quality, forensics capability, incident response time 등에서 통계적으로 유의미한 개선이 없다.

**반증 가능성 평가: 불명.** 현재 이 비교를 수행할 수 있는 배포 사례가 없다.

---

## 5. Validation Strategy

H1을 실제로 검증하거나 반증하기 위한 접근법.

### 단기 검증 (문서 분석, 4~8주)

**목표**: F1과 T1에 대한 1차 증거 확보

1. EU AI Act Article 12-17 세부 분석: AI 추론 감사에 cryptographic binding을 명시적으로 요구하는가, 아니면 기술 중립적으로 "audit trail"을 요구하는가?
2. HIPAA Security Rule의 ePHI 접근 로그 요구사항: AI 간접 접근(LLM을 통한 환자 정보 조회)이 기존 audit scope에 포함되는가?
3. NIST AI RMF의 거버넌스 요구사항: standardized trust implementation을 명시적으로 권장하는가?
4. 기존 SIEM 벤더(Splunk, Elastic, Wiz)의 AI security 기능 분석: 현재 도구가 AI 추론 감사를 어디까지 커버하는가?

**기대 결과**: F1 또는 T1 방향으로 1차 데이터 확보.

### 중기 검증 (인터뷰, 2~4개월)

**목표**: P1-P4에 대한 실용적 증거 또는 F2 반증

인터뷰 대상:
- 병원 IT/compliance 담당자 (의료 on-prem AI 경험)
- 금융 기관 CISO 또는 내부 감사팀 (AI 결정 책임 추적 요구)
- Enterprise AI/ML 엔지니어 (agent audit 현실 경험)
- 규제 컨설턴트 (AI Act/HIPAA compliance 현장)

핵심 질문:
- "AI 추론 감사에서 현재 SIEM으로 충족되지 않는 요구사항이 있는가?"
- "어떤 모델 버전이 이 결정을 내렸는지 사후에 cryptographically 증명해야 했던 상황이 있었는가?"
- "AI trust 구현이 팀마다 달라서 실질적 문제가 생긴 사례가 있는가?"

**기대 결과**: P1-P4 중 하나 이상 확인되면 H1 강화. 없으면 F2 강화.

### 장기 검증 (실증 비교, 6개월+)

**목표**: F6 평가

- AIS 구현 환경과 기존 인프라 환경의 side-by-side 비교
- 측정 지표: compliance audit 준비 시간, incident investigation 시간, policy enforcement 일관성
- 규제 감사관의 평가: AIS 감사 체인과 SIEM 로그에 대해 다른 반응을 보이는가?

이 단계는 이전 단계에서 H1이 약화되지 않은 경우에만 의미 있다.

---

## 6. Current Assessment

각 AIS 구성요소의 현재 증거 수준.

### AI Certificate (모델 신원)

**증거 수준: 약함 (Weak)**

- 기술적 개념은 유효하다: TLS는 모델을 인증하지 않는다
- 그러나 CA 생태계가 없어 현재 self-signed 수준
- 더 강한 대안 존재: TEE 원격 증명, 서명된 컨테이너
- Hosted AI 환경에서 적용 불가 (`scenarios/public_cloud_api.md`)
- 배포 시 내부 CA 운영이 전제조건 (`deployment_assumptions.md` §2.1)

**무엇이 바뀌면 강해지는가**: 주요 모델 런타임(Ollama, vLLM)이 AI Certificate를 기본 지원하거나, 규제기관이 모델 신원 바인딩을 명시적으로 요구하는 경우.

---

### Session Continuity (세션 귀속)

**증거 수준: 약~중간 (Weak-Moderate)**

- 추론 요청을 특정 인증된 세션에 귀속하는 것은 TLS가 제공하지 않는 애플리케이션 레이어 속성이다
- 그러나 현재 구현에서 세션 생성은 인증 없이 이루어진다 — IAM과 연동되지 않으면 "인증된 세션"이라는 주장이 약하다 (`threat_model_limits.md` §2, TC-05)
- 기존 JWT + Bearer token이 유사한 기능을 제공한다

**무엇이 바뀌면 강해지는가**: 세션 생성이 조직 IAM과 바인딩되고, "세션-사용자-모델" 3자 연결이 검증 가능해지는 경우.

---

### Replay Protection (재전송 방어)

**증거 수준: 중간 (Moderate) — 단, 범위 제한적**

- TC-04는 AIS MVP에서 가장 구현이 검증된 속성이다
- 벤치마크 결과 (Apple Silicon, release build, local loopback):
  재전송 거부 ~31M ops/s, 중앙값 < 1 ns
- 그러나 TLS 레코드 레이어가 전송 수준 재전송을 이미 방어한다
- 세션 경계를 넘는 재전송은 탐지하지 못한다 (`threat_model_limits.md` §2, TC-04)
- Job queue 기반 중복 실행(enterprise agent 시나리오)은 별도 멱등성 처리가 필요하다

**무엇이 바뀌면 강해지는가**: 세션 경계 재전송 탐지가 구현되고, 타임스탬프 검증이 추가되는 경우.

---

### Audit Chain (변조 증거 감사)

**증거 수준: 약~중간 (Weak-Moderate)**

- 개념적 가치: 애플리케이션 레이어에서 tamper-evident 추론 감사는 TLS가 제공하지 않는 것이다
- 그러나 현재 구현은 인메모리 — 프로세스 재시작 시 소실 (`threat_model_limits.md` §2, TC-06)
- 요청 본문 해시만 기록; "어떤 환자 데이터가 포함되었는가"는 기록하지 않아 HIPAA 요구사항을 직접 충족하지 못함 (`scenarios/hospital_llm.md`)
- SIEM + 서명 로그가 더 성숙하고 운영 도구가 풍부하다

**무엇이 바뀌면 강해지는가**: 지속 저장소 구현, 외부 증인(witness) 연동, 요청 컨텍스트 정보 포함, 규제기관이 hash-chain 구조를 명시적으로 선호하는 경우.

---

### Capability Model (에이전트 권한 경계)

**증거 수준: 평가 불가 (Unassessable)**

AIS-Capability는 현재 구현되지 않았다. 설계 사양만 존재한다.

- 개념적 가치는 있다: OAuth 스코프는 "AI 에이전트가 어떤 도구를 어떤 조건에서 호출할 수 있는가"를 세분화하지 못한다 (`scenarios/enterprise_agent.md`)
- OPA + Rego가 유사한 기능을 이미 제공한다
- 구현 없이 증거 수준을 평가하는 것은 불가능하다

**무엇이 바뀌면 평가 가능해지는가**: AIS-Capability 구현 후 실제 에이전트 환경에서 OPA와 비교하는 경우.

---

## 7. Honest Conclusion

### 현재 증거 요약

| AIS 구성요소 | 증거 수준 | 주요 불확실성 |
|---|---|---|
| AI Certificate | 약함 | CA 생태계 없음, TEE가 더 강함 |
| Session continuity | 약~중간 | IAM 연동 부재, JWT로 대체 가능 |
| Replay protection | 중간 | 범위 제한적, TLS와 중복 일부 |
| Audit chain | 약~중간 | 인메모리, SIEM 대비 열위 |
| Capability model | 평가 불가 | 미구현 |

### H1의 현재 상태

H1은 아직 검증되지도, 반증되지도 않았다.

이론적 지지(규제 추세, 에이전트 자율성 증가, 모델 신원 gap)는 어느 정도 확인되지만, 실용적 지지(실제로 ad-hoc 구현이 충분하지 않아 문제가 생긴 사례)는 현재 없다. 이것이 H1의 핵심 불확실성이다.

### AIS가 취할 수 있는 위치

현재 증거 수준에서 AIS는 다음 중 어디에 해당하는지 불명확하다:

**Unnecessary** — SIEM + OAuth + signed containers로 충분하며 추가 레이어가 불필요한 경우.

**Niche** — Self-hosted, regulated, air-gapped 환경에서만 의미 있는 경우. 전체 AI 시장의 소수.

**Conditionally valuable** — 에이전트 자율성이 증가하고 규제 요구사항이 구체화될 경우 가치가 생기는 경우.

**Increasingly useful** — AI가 더 autonomous하고 consequential해질수록 표준화 필요성이 커지는 경우.

현재 데이터로 이 네 가지를 구분할 수 없다.

### 이 문서의 목적

H1이 반증되더라도 그것은 프로젝트 실패가 아니다.

"표준화된 AI trust guarantees가 필요하지 않다"는 것이 확인된다면, 그것은 정직한 연구 결과다. 필요 없는 것을 만들지 않는 것도 공학적 가치가 있다.

H1 검증의 다음 단계는 §5의 단기 검증에서 시작된다 — EU AI Act, HIPAA 문서 분석으로 F1 또는 T1에 대한 1차 데이터를 확보하는 것.

---

*작성일: 2026년 5월
참조: [why_ais.md](../why_ais.md), [tls_overlap.md](../tls_overlap.md),
[deployment_assumptions.md](../deployment_assumptions.md),
[threat_model_limits.md](../threat_model_limits.md),
[scenarios/hospital_llm.md](scenarios/hospital_llm.md),
[scenarios/enterprise_agent.md](scenarios/enterprise_agent.md),
[scenarios/public_cloud_api.md](scenarios/public_cloud_api.md)*
