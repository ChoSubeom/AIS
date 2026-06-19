# AIS의 목적 재평가

> 회의적 분석 이후의 연구 노트 — AIS는 무엇을 위한 프로젝트인가?

---

## 들어가며

이 문서는 앞서 작성된 세 편의 회의적 연구 노트
([tls_overlap.md](tls_overlap.md),
[deployment_assumptions.md](deployment_assumptions.md),
[threat_model_limits.md](threat_model_limits.md))와
세 편의 시나리오 분석
([scenarios/](scenarios/))을
바탕으로, AIS의 목적과 방향을 재검토한다.

마케팅 문서가 아니다.
AIS가 무엇을 달성할 수 있고, 무엇을 달성하기 어려운지를
가능한 한 솔직하게 기술하는 것이 목적이다.

---

## 1. 최초의 직관

AIS의 출발점은 다음 직관이다.

> "AI 시스템에도 TLS와 유사한 신뢰 레이어가 필요할 수 있다."

이 직관은 나름의 근거를 가진다.
TLS는 네트워크 통신에 신원·무결성·기밀성을 제공했고,
그 이전에는 각 애플리케이션이 보안을 개별 구현했다.
AI 시스템도 현재 비슷한 상황이다 — 인증, 감사, 무결성 보증이
애플리케이션마다 개별 구현된다.

따라서 AI 인터랙션을 위한 공통 신뢰 레이어를 만들겠다는 아이디어 자체는 무리하지 않다.

**그러나** 분석을 거친 지금, "AI의 TLS"라는 프레이밍은
지나치게 넓고 일부 misleading하다는 결론에 이르렀다.
이 문서는 그 이유를 설명하고, 더 방어 가능한 방향을 제시한다.

---

## 2. 분석을 통과하지 못한 주장들

### 2.1 "AIS는 AI의 TLS다"

이 프레이밍은 여러 이유에서 성립하지 않는다.

**TLS가 이미 다루는 영역이 너무 많다.**
전송 암호화, 서버 인증, MITM 방어, 재전송 방어는
TLS 1.3 + mTLS로 충분히 처리된다.
(`tls_overlap.md` §2 참조)
AIS의 세션 MAC은 TLS 위에서 같은 기능을 중복으로 수행한다.

**생태계 없이 범용 신뢰 레이어는 성립하지 않는다.**
TLS가 성공한 것은 Web PKI, 브라우저, 서버 소프트웨어가 동시에 채택했기 때문이다.
AI Certificate가 의미 있으려면 모델 제조사, 런타임, CA 생태계가 모두 참여해야 한다.
현재 그 생태계는 존재하지 않는다.
(`deployment_assumptions.md` §3.2 참조)

**AIS는 TLS를 전제로 동작한다. 대체하지 않는다.**
AIS는 TLS 위에서 애플리케이션 레이어의 AI 특화 신뢰 속성을 추가하는 역할이다.

### 2.2 일반적인 전송 보안 주장

명세서의 위협 TC-03(MITM)과 관련 주장들은
전송 레이어에서 이미 해결된 문제들이다.
현재 AIS MVP의 MITM 방어는 사실상 TLS에 위임되어 있다.
(`threat_model_limits.md` §2, TC-03 참조)

### 2.3 클라우드 API 환경에서의 범용 적용

공개 클라우드 AI API 환경에서는
모델 가중치에 접근할 수 없으므로 AI Certificate 검증이 원천 불가능하다.
AIS의 핵심 기능 중 하나가 가장 광범위한 사용 환경에서 작동하지 않는다.
(`scenarios/public_cloud_api.md` 참조)

### 2.4 광범위한 공급망 보안 주장

CA 생태계와 인증서 폐기 메커니즘 없이는
TC-02(공급망 공격) 방어 주장은 이론적 수준에 머문다.
(`threat_model_limits.md` §2, TC-02 참조)

---

## 3. 방향 재설정: 핵심 질문

분석을 통해 명확해진 것은, AIS가 추구해야 할 방향이
"AI의 TLS"나 "cryptographic logging"이 아니라는 점이다.

**더 정확한 중심 질문:**

> High-assurance AI 인터랙션에서,
> trust guarantees를 표준화하는 것이 가치 있는가?

이것은 "TLS 같은 인터넷 표준이 필요한가"라는 질문이 아니다.
Cross-org interoperability가 없어도, 단일 조직의 내부 표준이어도 이 질문에 "yes"라고 답할 수 있다.

웹의 역사는 이 질문이 의미 있음을 보여주는 하나의 근거다.

```
초기 웹 보안:  앱마다 crypto 직접 구현
  ↓ 표준화의 가치: 독립 감사, 일관성, 취약점 공유 수정
SSL/TLS: 전송 신뢰의 표준화

초기 웹 인증:  앱마다 login 직접 구현
  ↓ 표준화의 가치: interoperability, 검증된 구현
OAuth/JWT: 인증 위임의 표준화
```

AI에서 같은 질문이 성립하려면 다음이 필요하다:
애플리케이션마다 달리 구현된 AI trust가 실질적 문제를 만들고 있어야 한다.
현재 그 근거는 아직 충분하지 않다.

이 질문에 "yes"라면 AIS 같은 레이어가 가치 있다.
"no"라면, model identity와 audit은 서비스 레이어에서 각자 구현하면 충분하다.
현재 이 질문은 열려 있다.

Audit chain은 이 신뢰 레이어가 작동했다는 사실의 **귀속 기록**이다.
로깅 도구가 아니라 신뢰 레이어의 부산물이다.

### 3.1 AI Certificate의 역할: Provenance Anchor

Certificate는 단독으로 완전한 신뢰를 제공하지 않는다.
그러나 trust layer가 "어떤 모델"을 보장하려면 anchor가 필요하다.

```
anchor 없는 traceability:  "model=v4라고 로그에 쓰여 있다"
anchor 있는 traceability:  "model=v4임이 cryptographically bound되어 있다"
```

이 차이가 Trust Layer의 핵심 가치 제안이다.
Certificate는 self-hosted 환경에서만 작동하며,
hosted API 환경에서는 anchor 없이 나머지 속성들만 제공된다.
이 한계는 인정되어야 하며, 환경별 보증 수준이 다름을 명시해야 한다.

---

## 4. MVP = Foundation Only

이 구분이 중요하다.

**현재 MVP가 구현한 것:**

```
✓ 추론 세션 인증 (session framing + MAC)
✓ 재전송 방어 (sequence counter) — 가장 검증된 속성
✓ 모델 신원 바인딩 (AI Certificate) — CA 생태계 없이
✓ 변조 증거 감사 (hash-chain audit) — 인메모리, 프로세스 재시작 시 소실
```

**아직 구현되지 않은 것:**

```
✗ 에이전트 능력 경계 (AIS-Capability) — 설계만 존재
✗ 지속 감사 저장소 (persistent audit) — 인메모리 한계
✗ CA 생태계 — 외부 신뢰 앵커 없음
✗ 인증서 폐기 — 미구현
```

현재 MVP는 trust layer의 **토대(foundation)**이다. Trust layer 그 자체가 아니다.

이것은 결함이 아니다 — 연구 프로토타입이 그래야 하는 방식이다.
그러나 MVP를 "완성된 신뢰 레이어"로 제시하면 오해를 만든다.

---

## 5. 현실적인 배포 범위

시나리오 분석 결과, AIS가 의미 있는 환경은 좁다.

### 현실적으로 적합한 환경

- **온프레미스 AI 인프라**: 단일 조직이 모델·런타임·신뢰 앵커를 제어하는 환경
- **규제된 환경**: AI 인터랙션의 귀속 가능성이 법적·정책적으로 요구되는 환경
- **에어갭 시스템**: 외부 CA 없이 내부 신뢰 앵커로 운용하는 고립 환경
- **고보증 배포**: 에이전트 권한 경계와 모델 무결성이 명시적으로 요구되는 환경

### 아마도 불필요한 환경

- **공개 클라우드 AI API**: 모델 가중치 접근 불가, AI Certificate 적용 불가
- **TLS + mTLS + OAuth가 이미 갖춰진 환경**: 전송 보안과 접근 제어가 충분히 커버됨
- **소비자용 AI 서비스**: 운영 복잡도 대비 추가 가치 불분명

`scenarios/` 하위 문서에서 각 환경을 구체적으로 평가한다.

---

## 6. 연구 가설

이 분석을 종합한 핵심 연구 가설:

> **High-assurance AI 인터랙션에서,
> trust guarantees를 표준화하는 것이
> application-level 구현 대비 의미 있는 가치를 제공하는가?**

이 가설은 `h1_validation.md`에서 검증 기준을 정의한다.

"표준화"는 인터넷 표준을 의미하지 않는다.
단일 조직 내부의 일관된 구현이어도 이 가설을 검증할 수 있다.

가설이 성립하기 위한 조건:
- AI 인터랙션이 autonomous하고 consequential한 방향으로 실제로 이동하고 있어야 한다
- Application-level 구현의 불일치가 이론적 불편함이 아닌 실질적 운영 문제를 만들어야 한다
- 표준화의 이점(일관성, 독립 감사 가능성)이 추가 운영 비용을 초과해야 한다

**이 조건들이 충족된다는 보장은 현재 없다.**
특히 두 번째 조건 — 실질적 고통이 있는가 — 이 가장 불확실하며 empirical 검증이 필요하다.

---

## 7. 결론

**"AI의 TLS"로서의 AIS는 방어하기 어렵다.**

범용 전송 보안 레이어 주장은 TLS와 중복이고,
CA 생태계 없이 공급망 보안 주장은 성립하지 않으며,
클라우드 API 환경에서는 핵심 기능이 작동하지 않는다.

**AIS가 실제로 탐색하는 질문은 다르다:**

> High-assurance AI 인터랙션에서,
> trust guarantees를 표준화하는 것이
> 각 서비스가 개별 구현하는 것보다 가치 있는가?

인터넷 표준이 필요하다는 주장이 아니다.
Enterprise 내부에서, regulated 환경에서, 일관된 trust 구현이
ad-hoc 구현보다 나은 결과를 만드는지가 질문이다.

이 질문은 아직 답이 없다.
AI가 더 autonomous하고 consequential해질수록 더 pressing해질 수 있다.
그렇지 않을 수도 있다.

**현재 AIS의 위치:**

AIS는 이 가설의 **prototype candidate**이다.
MVP는 그 prototype의 foundation이다 — 완성된 신뢰 레이어가 아니다.

Audit chain은 신뢰 레이어의 귀속 기록이지 로깅 도구가 아니다.
Certificate는 provenance anchor이며 self-hosted 환경에서만 현재 작동한다.
AIS-Capability가 구현되기 전까지 agent capability 주장은 설계 의도에 불과하다.

protocolization이 필요한지는 연구를 통해 검증되어야 한다.
현재 단계에서 이것을 확신하는 것은 premature하다.

---

*작성일: 2026년 5월
참조: [tls_overlap.md](tls_overlap.md), [deployment_assumptions.md](deployment_assumptions.md),
[threat_model_limits.md](threat_model_limits.md), [h1_validation.md](h1_validation.md),
[scenarios/](scenarios/)*
