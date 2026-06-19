# AI 에이전트 인시던트 조사

> 실제 AI 에이전트 인시던트가 기존 시스템으로 해결되지 않는 신뢰 갭을 드러내는가?
> 이 문서는 AIS를 옹호하지 않는다. 증거가 약하면 그대로 기술한다.

---

## 1. Research Question

**핵심 질문:**

실제 AI 에이전트 인시던트가 더 표준화된 신뢰 보증을 정당화하는 신뢰 갭을 드러내는가?

**이 질문이 다루지 않는 것:**
- 환각(hallucination) — 모델 품질 문제
- 출력의 정확성 — 평가 문제
- AI 정렬 실패 — 모델 안전 문제
- 모델 지능 부족 — 역량 문제

**이 질문이 다루는 것:**
- 상호작용 신뢰(interaction trust): 이 요청이 어디서 왔고, 어떤 모델이 처리했는가
- 권한 부여(authorization): 에이전트가 허가된 범위 내에서만 행동했는가
- 귀속 가능성(provenance): 이 행동의 원인을 사후에 재구성할 수 있는가
- 연속성(continuity): 요청이 중복 처리되거나 재전송되지 않았는가
- 책임 추적(accountability): 어떤 모델이 어떤 결정을 내렸는지 입증할 수 있는가

**방법론적 주의사항:**

공개된 인시던트만 분석한다. 기밀 운영 사고는 포함되지 않으며, 이는 심각한 선택 편향(selection bias)을 만든다. 이 문서는 "AI 에이전트의 전체 인시던트 현황"이 아니라 "공개 사례에서 신뢰 갭을 식별할 수 있는가"에 답하는 시도다.

---

## 2. Classification Framework

인시던트를 다섯 가지 범주로 분류한다. 각 범주마다 AIS 관련성을 평가한다.

### A. Reasoning Failure (추론 실패)

**설명:** 모델이 잘못된 결정을 내리거나, 부정확한 정보를 생성하거나, 의도치 않은 논리적 결론에 도달하는 실패.

**대표 사례:** 환각, 잘못된 코드 생성, 부정확한 법적·의료적 판단, 멀티스텝 추론 오류.

**일반적 원인:** 모델 역량 한계, 훈련 데이터 편향, 문맥 창(context window) 한계.

**기존 시스템의 충분성:** 이것은 보안 문제가 아니라 공학 문제다. 테스트, 평가, 인간 검토, 안전 장치(guardrails)가 표준 대응이다.

**AIS 관련성: 없음 (NONE)**

이 범주의 실패에 신뢰 레이어는 개입 지점이 없다. 모델이 잘못된 답변을 내놓는 것은 세션 무결성이나 모델 인증서로 막을 수 없다. 이 점을 명확히 하는 것이 중요하다.

**신뢰도: 높음 (High)**

---

### B. Authorization Failure (권한 부여 실패)

**설명:** 에이전트가 권한이 없거나 의도되지 않은 리소스에 접근하거나, 과도한 권한으로 과잉 행동을 취하는 실패.

**대표 사례:** 에이전트가 의도보다 더 많은 파일을 삭제, 필요 이상의 API 호출, 권한 없는 DB 수정, 예상치 못한 외부 서비스 호출.

**일반적 원인:** 과잉 권한 부여(over-provisioned service accounts), 불명확한 tool scope 정의, 에이전트 행동에 대한 RBAC 미적용.

**기존 시스템의 충분성:** IAM, RBAC, Kubernetes RBAC, OAuth 스코프, API 게이트웨이 정책으로 대부분 해결 가능하다. 이미 성숙한 도구 생태계가 있다.

**AIS 관련성: 낮음~중간 (LOW to MEDIUM)**

AIS-Capability 개념은 AI 에이전트의 도구 호출에 세분화된 권한 경계를 제공한다. 그러나 이것은 현재 구현되지 않았으며, OPA + Rego, Kubernetes Admission Controller가 유사한 기능을 이미 제공한다. AIS가 추가하는 것은 AI-specific semantics — 그것이 충분히 차별화되는지는 불명확하다.

**신뢰도: 중간 (Moderate)**

---

### C. Interaction Provenance Failure (상호작용 귀속 실패)

**설명:** 인시던트 조사 시 "어떤 모델이, 어떤 입력으로, 어떤 결정을 내렸는가"를 재구성하지 못하는 실패.

**대표 사례:** 모델 버전 불명확, 멀티에이전트 체인에서 원인 모델 식별 불가, 에이전트 행동의 감사 경로(audit trail) 부재.

**일반적 원인:** 애플리케이션 레이어 로깅 부재, 모델 버전 관리 미흡, 에이전트 오케스트레이션의 black-box 특성.

**기존 시스템의 충분성:** SIEM + structured application logging으로 상당 부분 해결 가능하다. 그러나 "어떤 LLM inference가 이 결정을 만들었는가"는 기존 로그 구조가 명시적으로 다루지 않는 경우가 있다.

**AIS 관련성: 중간~높음 (MEDIUM to HIGH) — 가장 방어 가능한 영역**

AIS 감사 체인이 다루려는 핵심 갭과 가장 직접적으로 연결된다. 그러나 실제 인시던트에서 provenance failure가 독립적 원인으로 명시적으로 기록된 사례는 드물다.

**신뢰도: 약함 (Weak) — 이론적 관련성은 있으나 실증 사례 부족**

---

### D. Continuity / Replay Failure (연속성/재전송 실패)

**설명:** 동일한 에이전트 작업이 중복 실행되거나, 실패한 작업이 재시도 중 부작용을 일으키는 실패.

**대표 사례:** Job queue at-least-once delivery로 인한 티켓 중복 생성, DB 중복 쓰기, 배포 두 번 트리거.

**일반적 원인:** Job queue의 전달 보장(delivery guarantee) 설정 오류, 멱등성(idempotency) 미구현.

**기존 시스템의 충분성:** 높음. Kafka 트랜잭션, 애플리케이션 레이어 idempotency key, at-exactly-once semantics로 해결해야 한다. 이것은 AIS가 아닌 job queue 설계 문제다.

**AIS 관련성: 낮음 (LOW)**

AIS의 세션 내 재전송 방어(TC-04)는 세션 범위 내에서만 작동한다. Job queue 재전송은 새로운 세션으로 동일 작업이 다시 시작되는 것이므로 AIS가 탐지하지 못한다 (`threat_model_limits.md` §2, TC-04 참조). 이 실패 범주에서 AIS의 가치는 제한적이다.

**신뢰도: 높음 (High) — AIS 관련성이 낮다는 것에 대한 신뢰도가 높음**

---

### E. Prompt Injection / Context Hijacking (프롬프트 인젝션/컨텍스트 탈취)

**설명:** 외부 데이터(웹페이지, 이메일, 문서, DB 레코드)에 포함된 악의적 명령이 에이전트의 행동을 의도치 않게 조작하는 실패.

**대표 사례:** 방문한 웹페이지의 숨겨진 텍스트가 AI 어시스턴트의 응답을 조작, RAG 컨텍스트에 주입된 명령어로 에이전트 유도, 악의적 이메일 내용으로 AI 어시스턴트 동작 변경.

**일반적 원인:** LLM의 근본적 구조적 취약성 — instruction과 data가 동일한 토큰 공간에 존재함.

**기존 시스템의 충분성:** 불충분하지만 AIS도 해결하지 못한다. 샌드박싱, 입력 필터링, privileged instruction 분리, fine-tuning이 현재 주요 완화 방법이다.

**AIS 관련성: 낮음~없음 (LOW to NONE)**

이것이 이 문서에서 가장 중요한 판단 중 하나다.

Prompt injection은 OWASP LLM Top 10 2025의 1위 위협이다. 그러나 AIS는 이 문제를 근본적으로 다루지 않는다. 세션 MAC, 재전송 방어, AI Certificate — 이 중 어느 것도 모델이 외부 데이터에서 명령을 추출하는 것을 막지 못한다. AIS-Semantic이 이를 부분적으로 다루려 했지만, 명세서 자체가 "probabilistic advisory only"로 격하했다.

"가장 큰 AI 에이전트 보안 위협에 AIS 관련성이 낮다"는 것은 솔직하게 인정되어야 한다.

**신뢰도: 높음 (High) — AIS 관련성이 낮다는 것에 대한 신뢰도가 높음**

---

## 3. Real Incident Survey

공개 문서화된 인시던트와 연구 보고서를 기반으로 조사한다. 각 인시던트의 AIS 관련성을 비판적으로 평가한다.

---

### Incident 1: Bing Chat / Microsoft Copilot 간접 프롬프트 인젝션 (2023)

#### Summary

2023년 3월, Johann Rehberger와 다른 보안 연구자들이 Bing Chat(현 Microsoft Copilot)에서 간접 프롬프트 인젝션을 시연했다. 악의적으로 작성된 웹페이지를 방문하면, 페이지 내 숨겨진 텍스트가 Bing Chat의 행동을 조작할 수 있었다. 연구자들은 이를 통해 Bing Chat이 사용자를 악의적 사이트로 유도하거나 개인 정보를 요청하도록 만들 수 있음을 보였다.

#### Root Cause

LLM이 외부 데이터(웹 컨텐츠)와 사용자 instruction을 구별하지 못하는 구조적 취약성. 모델이 웹 컨텐츠에서 추출한 텍스트를 신뢰할 수 있는 명령으로 처리한다.

#### Existing Mitigations

- 시스템 프롬프트 강화 (privileged instruction)
- 입력 필터링 및 패턴 매칭
- Fine-tuning으로 instruction hierarchy 학습
- 출력 모니터링

#### AIS Relevance: NONE

AIS 구성요소 — 세션 MAC, AI Certificate, 재전송 방어 — 중 어느 것도 이 공격 벡터를 차단하지 못한다. 문제는 모델이 외부 데이터에서 명령을 추출한다는 것이며, 이것은 세션 신뢰 레이어가 아닌 모델 아키텍처와 훈련의 문제다.

#### Confidence: Strong

---

### Incident 2: MCP Tool Poisoning (Invariant Labs, 2025)

#### Summary

2025년 초, Invariant Labs 연구팀이 Model Context Protocol(MCP) 생태계에서 "Tool Poisoning" 공격을 문서화했다. 악의적으로 설계된 MCP 서버가 misleading tool description을 제공해 AI 에이전트가 의도하지 않은 행동(데이터 탈취, 무결성 손상)을 취하도록 유도할 수 있었다. 또한 "rug pull" 패턴 — 초기에 안전한 도구로 등록한 후 서버 업데이트를 통해 악의적 동작을 추가하는 — 도 식별되었다.

#### Root Cause

에이전트가 연결한 MCP 서버(도구 제공자)의 신원 및 무결성을 검증하는 메커니즘이 없다. 도구 설명(tool description)이 암호학적으로 바인딩되지 않아 서버 측에서 임의 수정이 가능하다.

#### Existing Mitigations (현재 권장)

- 신뢰할 수 없는 MCP 서버 차단 (whitelist)
- 도구 호출 전 인간 검토
- 도구 실행 샌드박싱
- MCP 서버 소스 감사

#### AIS Relevance: MEDIUM to SPECULATIVE

이것이 이 조사에서 AIS 관련성이 가장 높은 사례다.

AIS AI Certificate 개념을 MCP 서버 신원 바인딩에 적용하면: "이 도구 설명은 이 서버가 발행했으며 이후 변경되지 않았다"를 cryptographically 보증할 수 있다. Rug pull 패턴은 certificate가 적용되면 탐지 가능하다.

**그러나:**
- 이것은 현재 AIS 구현에 없다. AI Certificate는 모델 파일을 위한 것이지 MCP 서버 도구 설명을 위한 것이 아니다
- 동일한 보증은 도구 설명의 signed hash를 MCP 프로토콜에 추가함으로써 AIS 없이도 달성 가능하다
- AIS가 필요한 것이 아니라 "certificate-like binding for tool descriptions"가 필요한 것이며, 이것은 별도 스펙이다

**결론**: 이 사례는 tool provenance 바인딩의 가치를 보여주지만, AIS 자체의 필요성을 직접 입증하지는 않는다.

#### Confidence: Moderate

---

### Incident 3: AutoGPT/에이전트 루프 및 리소스 소진 (2023)

#### Summary

AutoGPT, BabyAGI 등 초기 자율 에이전트 프레임워크를 사용한 많은 사용자들이 에이전트가 의도된 작업 범위를 벗어나 무한 루프에 진입하거나, 과도한 API 크레딧을 소비하거나, 의도치 않은 외부 서비스에 접근하는 경험을 보고했다. 일부는 에이전트가 파일 시스템에 예상치 못한 변경을 가하거나, 외부 API에 수십 번의 불필요한 호출을 한 사례를 기록했다.

#### Root Cause

행동 경계(action bounds)가 없음. 작업 종료 조건 불명확. 에이전트에게 부여된 권한이 의도보다 광범위함.

#### Existing Mitigations

- 실행 예산(execution budget) — 최대 step 수, 최대 API 호출 수
- 인간 확인 루프(human-in-the-loop)
- 샌드박스 환경에서만 실행
- 에이전트에게 최소 권한 원칙 적용

#### AIS Relevance: LOW

이 실패는 에이전트가 너무 많은 권한을 가졌거나 적절한 경계가 없어서 발생한다. 현재 주요 대응은 실행 예산과 최소 권한 원칙 — 기존 IAM/RBAC 개념으로 해결 가능하다.

AIS-Capability가 구현된다면 "에이전트는 최대 N번의 DB 쿼리만 실행 가능"과 같은 세분화된 제약을 cryptographically 표현할 수 있다. 그러나 이것은 현재 미구현이며, rate limiting + circuit breaker + execution budget 조합으로 이미 많은 경우 해결된다.

#### Confidence: Moderate

---

### Incident 4: Samsung/Apple 직원 ChatGPT 데이터 유출 (2023)

#### Summary

2023년 삼성 전자 직원들이 독점 코드와 회의 기록을 ChatGPT에 입력했고, 이 데이터가 OpenAI의 학습 데이터로 사용될 수 있다는 사실이 알려졌다. 삼성은 이후 사내 ChatGPT 사용을 제한했다. Apple도 유사한 이유로 직원들의 ChatGPT 사용에 제한을 가했다.

#### Root Cause

직원들의 AI 서비스 이용 정책 부재 또는 미준수. 데이터 유출 방지(DLP) 시스템이 AI 서비스 사용에 적용되지 않음. 기업 정보 유출에 대한 인식 부족.

#### Existing Mitigations

- DLP 정책 + AI 서비스 모니터링
- Enterprise AI 사용 정책 수립
- 사내 AI 솔루션으로 전환
- API 사용 시 데이터 처리 조항 검토

#### AIS Relevance: NONE

이것은 데이터 거버넌스와 사용자 행동 문제다. 신뢰 프로토콜 레이어와 관련이 없다. DLP 시스템과 정책 교육이 적절한 대응이다.

#### Confidence: Strong

---

### Incident 5: Coding Agent 의도치 않은 파일 변경 패턴 (일반 패턴, 2024-2025)

#### Summary

Cursor, Devin, Claude Code 등 코딩 에이전트 사용자들의 보고를 종합하면, 일반적인 패턴이 있다: 에이전트가 명시적으로 요청하지 않은 파일을 변경하거나, 예상보다 많은 API 크레딧을 사용하거나, 관련 없어 보이는 코드를 수정한다. 개별 사례는 대부분 공개적으로 문서화되지 않지만, X(트위터), GitHub discussions, HackerNews에서 반복적으로 보고된다.

*주의: 이것은 개별 문서화된 인시던트가 아니라 사용자 커뮤니티의 집합적 패턴 보고다.*

#### Root Cause

에이전트의 추론 범위가 사용자 의도보다 광범위하게 해석되는 경향. 파일 시스템 접근 권한이 필요 이상으로 광범위. 에이전트의 행동 계획(action plan) 투명성 부족.

#### Existing Mitigations

- 명시적 파일 접근 범위 제한
- 변경 전 인간 확인
- 읽기 전용 모드 우선 실행
- 변경 이력 검토

#### AIS Relevance: LOW to MEDIUM

이 패턴에서 AIS-Capability가 부분적으로 관련된다: "이 세션에서 에이전트는 /src/feature/ 내 파일만 수정할 수 있다" 같은 명시적 capability bound.

그러나 이것은 이미 IDE의 workspace 설정, file watcher, git hooks, 샌드박스 환경으로 어느 정도 해결된다. AIS가 추가하는 것이 "cryptographic binding" 외에 무엇인지 불명확하다.

#### Confidence: Weak (개별 인시던트 미문서화)

---

### Incident 6: 멀티에이전트 신뢰 전파 문제 (연구 수준, 2024-2025)

#### Summary

Anthropic, OpenAI 등의 연구 보고서와 학술 논문에서 멀티에이전트 시스템의 신뢰 전파 문제가 식별되었다. Agent A가 Agent B에게 지시를 전달할 때, Agent B는 그 지시가 합법적인 오케스트레이터에게서 왔는지, 혹은 프롬프트 인젝션을 통해 조작된 것인지 구별하기 어렵다. "Agent A가 이 지시를 내릴 권한이 있는가"를 검증하는 표준 메커니즘이 없다.

*이것은 현재 시스템에서 사용하는 단어의 학술적 패턴 분석이다. 단일 고장 인시던트로 문서화되지는 않았다.*

#### Root Cause

에이전트 간 인증(inter-agent authentication) 표준 부재. 에이전트는 수신한 요청의 출처를 cryptographically 검증하지 않는다.

#### Existing Mitigations

- 오케스트레이터 에이전트의 명시적 신원 헤더 포함
- 요청 서명 (비표준, 각 시스템마다 다르게 구현)
- 신뢰할 수 있는 오케스트레이터만 허용하는 whitelist

#### AIS Relevance: MEDIUM to HIGH

이것이 이 조사에서 이론적으로 AIS 관련성이 가장 강한 영역이다. AIS 세션 인증 개념이 "이 에이전트 요청은 이 인증된 세션에서 왔다"를 표준화된 방식으로 제공할 수 있다.

**그러나 중요한 제한:**
- 이것은 현재 생산 환경에서 발생한 documented incident가 아니라 연구 수준의 위협 분석이다
- 실제 피해를 야기한 멀티에이전트 신뢰 실패 사례는 공개되지 않았다
- 대부분의 엔터프라이즈 멀티에이전트 배포는 아직 초기 단계다

**이 사례에서 H1의 가치 주장은 "미래의 시나리오"에 의존한다. 현재 증거는 이론적이다.**

#### Confidence: Weak (연구 수준, 실제 인시던트 미확인)

---

### Incident 7: Air Canada 챗봇 할인 정책 허위 안내 소송 (2024)

#### Summary

Air Canada의 챗봇이 존재하지 않는 환불 정책을 허위로 안내했고, 법원은 Air Canada가 챗봇 제공 정보에 대해 책임이 있다고 판결했다. Air Canada는 "챗봇은 별도 법인"이라는 주장으로 책임을 회피하려 했으나 기각되었다.

#### Root Cause

모델 환각. 챗봇이 허위 정책을 "생성"했으며, 기업이 이 출력에 대한 검증 메커니즘 없이 배포했다.

#### Existing Mitigations

- 응답 범위를 정책 문서로 제한 (RAG)
- 인간 검토 또는 규칙 기반 검증
- 배포 전 충분한 테스트

#### AIS Relevance: NONE

이것은 순수한 추론 품질 실패다. AIS 신뢰 레이어가 환각을 막을 수 없다. 올바른 모델이 정확히 인증된 상태로 환각을 했다면, AIS는 이를 감지하거나 방지하지 못한다.

#### Confidence: Strong

---

### Incident 8: HackerOne AI Pentest 에이전트 권한 상승 취약점 보고 (일반 패턴, 2024-2025)

#### Summary

HackerOne, Bugcrowd 등의 버그 바운티 플랫폼에서 AI 에이전트 통합 시스템에 대한 취약점 보고가 증가하고 있다. 공통 패턴: AI 에이전트가 tool calling을 통해 의도하지 않은 권한 상승을 달성하거나, 에이전트의 컨텍스트 내 데이터가 악용되는 사례.

*이것은 특정 인시던트가 아닌 보고 패턴 분석이다.*

#### Root Cause

에이전트 도구 실행에 대한 권한 경계 불명확. 에이전트가 도구를 호출할 때 사용자 권한과 에이전트 권한의 분리 없음.

#### Existing Mitigations

- Principle of least privilege (에이전트 서비스 계정)
- 도구별 권한 분리
- 에이전트 행동 감사 로그

#### AIS Relevance: LOW to MEDIUM

IAM + RBAC + 감사 로깅으로 대부분 처리 가능하다. AIS-Capability가 도구별 세분화된 권한을 더 표준화된 방식으로 제공할 수 있지만, 기존 도구가 충분한 경우 AIS의 추가 가치가 불분명하다.

#### Confidence: Weak (특정 인시던트 미확인, 패턴 분석)

---

## 4. Pattern Analysis

### 지배적인 실패 유형

인시던트 조사 결과, AI 에이전트 실패의 압도적 다수는 다음에 속한다:

1. **추론 실패** (환각, 잘못된 결정): AIS 관련성 없음. 이것이 가장 많이 보고되는 카테고리다.
2. **프롬프트 인젝션**: AIS 관련성 낮음~없음. OWASP LLM 1위 위협임에도 AIS가 다루지 못한다.
3. **기본 IAM/권한 설정 오류**: AIS 관련성 낮음. 기존 도구로 해결 가능.

### 신뢰 갭이 실제로 나타나는 영역

더 작은 규모이지만 실재하는 영역:

1. **MCP/tool provenance**: 도구 설명의 무결성 바인딩 부재. 제한적이지만 가장 concrete한 증거.
2. **멀티에이전트 inter-agent authentication**: 현재 비표준. 미래 문제의 가능성이 있으나 현재 documented incident 없음.
3. **인시던트 조사의 provenance 어려움**: 감사 경로가 부족해 "어떤 모델이 이 결정을 내렸는가"를 재구성하기 어려운 경우가 있다는 간접 증거.

### 현재 시스템이 충분한 영역

- 전송 보안: TLS로 충분
- 사용자 인증: IAM으로 충분
- 데이터 거버넌스: DLP + 정책으로 충분
- 재전송 방어: 애플리케이션 멱등성으로 충분
- 기본 접근 제어: RBAC + OAuth로 충분

### 선택 편향 경고

이 분석은 공개적으로 보고된 인시던트에만 의존한다. 실제로 중요한 AI 신뢰 실패가 있었다면:

- 기업이 공개하지 않을 가능성 높음
- "AI가 잘못된 결정을 내렸다"로 분류되어 신뢰 실패로 기록되지 않을 수 있음
- 내부 운영 사고는 이 분석에 포함되지 않음

**이 분석이 "신뢰 실패가 드물다"는 것을 의미하지 않는다. 단지 공개 증거가 부족하다는 것을 의미한다.**

---

## 5. Counterarguments

AIS와 유사한 시스템에 대한 가장 강한 반론들.

### C1. SIEM + IAM + signed containers로 이미 충분하다

대부분의 엔터프라이즈 환경에서 Kubernetes + Istio + SIEM + OAuth 조합이 AI 에이전트 보안을 충분히 커버한다. AIS가 추가하는 것은 이 위에 레이어를 하나 더 얹는 것이며, 추가 가치가 운영 비용을 정당화하지 못할 수 있다.

**강도: 높음.** 이것이 가장 현실적인 반론이다.

### C2. 가장 큰 위협(프롬프트 인젝션)에 AIS 관련성이 없다

OWASP LLM Top 10 2025 1위 위협인 프롬프트 인젝션은 AIS가 다루지 않는다. 만약 AIS가 AI 에이전트의 신뢰 레이어라면, 가장 중요한 실제 위협에 개입하지 못하는 레이어의 가치는 제한적이다.

**강도: 높음.**

### C3. Hosted AI가 지배적이며 AI Certificate가 적용 불가능하다

현재 대부분의 AI 에이전트는 OpenAI, Anthropic, Google API 위에 구축된다. 이 환경에서 AI Certificate의 핵심 전제(모델 가중치 접근)가 불가능하다 (`scenarios/public_cloud_api.md`). AIS의 가장 차별화된 기능이 가장 많이 사용되는 환경에서 작동하지 않는다.

**강도: 높음.**

### C4. 멀티에이전트 신뢰 문제는 아직 충분히 painful하지 않다

멀티에이전트 시스템의 inter-agent trust 문제는 이론적으로 의미 있지만, 현재 이것으로 인해 실질적인 운영 피해가 발생했다는 공개 증거가 부족하다. 문제가 충분히 painful해지기 전에 표준을 만드는 것은 premature optimization일 수 있다.

**강도: 중간.** 증거 부족이 "문제 없음"을 의미하지 않지만, 긴급성을 정당화하지도 않는다.

### C5. OPA + Envoy + 서명된 컨테이너로 AIS-Capability를 대체할 수 있다

AIS-Capability가 제공하려는 기능(도구 호출 권한 경계)은 OPA + Rego + Kubernetes Admission Controller로 이미 구현 가능하다. AIS-specific 표준의 필요성이 불명확하다.

**강도: 중간~높음.** AI-specific semantics가 충분히 차별화되는지는 미검증.

### C6. 운영 복잡도가 이점을 초과한다

CA 인프라 운영, 세션 관리, AIS 프록시 유지 관리의 비용이 보안 이점보다 클 수 있다. 특히 현재 인시던트 조사 결과 trust 실패가 주요 원인이 아닌 경우가 많아 ROI가 불명확하다.

**강도: 중간.** 이것은 empirical하게 측정되어야 하지만 현재 데이터가 없다.

---

## 6. Preliminary Assessment

현재 증거 수준에 따른 AIS 구성요소별 평가.

| 구성요소 | 증거 강도 | 비고 |
|---|---|---|
| Certificate / Provenance | **Weak** | 이론적 gap 존재(모델 신원 바인딩). 그러나 현재 CA 생태계 없음, TEE가 더 강함, hosted AI에서 불가능. 실제 인시던트에서 certificate 부재가 핵심 원인으로 기록된 사례 없음. |
| Session Continuity | **Speculative** | 세션별 귀속의 이론적 가치 있음. 그러나 현재 구현에서 세션 생성 비인증, IAM 연동 없음. 기존 JWT로 대체 가능. 인시던트에서 직접 언급 없음. |
| Replay Resistance | **Weak** | TC-04는 AIS MVP의 가장 잘 구현된 속성. 그러나 실제 인시던트에서 AIS 수준의 replay protection이 필요했던 사례 없음. TLS와 멱등성 처리가 대부분 커버. |
| Auditability | **Weak-Moderate** | MCP tool poisoning 및 멀티에이전트 조사 어려움에서 간접 증거. 그러나 SIEM이 더 성숙하고, AIS audit chain은 현재 인메모리. "cryptographic binding이 signed SIEM log보다 의미 있는가"는 미검증. |
| Capability Model | **Promising (미구현)** | Authorization failure 패턴에서 도구 호출 권한 경계의 필요성이 간접적으로 보인다. 그러나 AIS-Capability 미구현, OPA로 대체 가능, AI-specific 가치 미검증. |

---

## 7. Honest Conclusion

### 인시던트 조사의 핵심 발견

1. **AI 에이전트 실패의 대다수는 AIS와 관련이 없다.** 추론 실패, 프롬프트 인젝션, 기본 IAM 설정 오류가 지배적이며, 신뢰 레이어가 개입할 지점이 아니다.

2. **AIS 관련성이 있는 영역은 좁다.** Tool/MCP provenance binding, 멀티에이전트 inter-agent authentication, 인시던트 조사의 inference attribution. 이 영역들은 이론적으로 방어 가능하지만, 현재 documented evidence가 약하다.

3. **가장 큰 AI 에이전트 보안 위협에 AIS가 개입하지 못한다.** 프롬프트 인젝션은 신뢰 프로토콜 레이어가 아닌 모델 아키텍처와 샌드박싱으로 다루어야 한다.

4. **기존 시스템이 많은 문제를 이미 해결한다.** TLS + mTLS + IAM + RBAC + SIEM은 현재 배포된 AI 에이전트 환경에서 충분한 보안을 제공하는 경우가 많다.

### H1 검증 방향에 미치는 영향

이 조사는 H1("high-assurance AI 인터랙션이 표준화된 신뢰 보증으로부터 이익을 얻을 수 있는가")에 대해 다음을 시사한다:

- **약한 지지**: MCP tool poisoning 패턴이 tool provenance binding의 가치를 보여준다. 멀티에이전트 trust 문제는 미래 시나리오로서 relevant하다.
- **강한 반증 위험**: 가장 빈번한 실패 유형에 AIS 관련성이 없다. 기존 시스템이 많은 경우 충분하다. 공개 인시던트에서 "AIS가 있었다면 막을 수 있었다"는 사례를 찾기 어렵다.

### 현재 AIS의 위치

이 조사에 기반하면 AIS는 현재 다음 중 하나에 해당할 가능성이 있다:

- **Mostly unnecessary** — 현재 인시던트 패턴에서 AIS가 개입할 수 있는 영역이 작고, 기존 시스템이 대부분 커버한다.
- **Niche utility** — MCP/tool ecosystems와 멀티에이전트 환경의 특정 신뢰 문제에 대해 부분적 가치를 제공한다.
- **Future relevance** — 에이전트가 더 자율적이고 consequential해질수록 신뢰 갭이 더 pressing해질 수 있다.

이 세 가지를 현재 데이터로 구분하는 것은 불가능하다.

**이 문서가 AIS에 대해 약한 결론을 내리는 것이 중요하다.** 강한 주장을 하기 위해서는 실제 운영 환경에서 "AIS 같은 것이 없어서 실질적 피해가 발생한" documented cases가 필요하다. 현재 그 증거는 없다.

---

*작성일: 2026년 5월
참조: [h1_validation.md](h1_validation.md), [why_ais.md](why_ais.md),
[scenarios/enterprise_agent.md](scenarios/enterprise_agent.md),
[scenarios/hospital_llm.md](scenarios/hospital_llm.md),
[threat_model_limits.md](threat_model_limits.md)*
