# AIS-Capability v1 가설: Session Commitment + Tool Hash Binding

> v0 판정: A — merely signed authorization.
> 질문: Session commitment와 tool hash binding이 그 판정을 바꾸는가?
> 작성 관점: 회의적 보안 설계자, SPIFFE 엔지니어, OAuth/JWT 전문가, 적대적 암호학 검토자.

---

## 1. Research Question

**AIS-Capability v1 (session commitment + tool hash)은 "그냥 서명 인증" 비판에서 살아남는가?**

출발점: v0는 A로 판정되었다 — JWT claims + jti replay guard + scoped credential의 재구현.

두 제안된 변경의 구체적 주장:

1. **Session commitment**: 세션 ID 바이트가 아닌 세션 무결성 키 자료(key material)에 대한 cryptographic commitment을 capability에 포함
2. **Tool hash binding**: 도구 이름 문자열이 아닌 도구 설명(description)의 SHA3-256을 capability에 포함

이 두 변경이 JWT + 기존 엔터프라이즈 보안 스택으로 달성할 수 없는 것을 제공하는가?

---

## 2. Session Commitment 분석

### 정확한 정의

```
현재 v0:
  capability.session_id = random_16_bytes
  검증: capability.session_id == requested_session_id  (바이트 비교)

제안된 v1:
  capability.session_commitment = SHA3-256(session_integrity_key || session_id)
  검증: SHA3-256(current_session.integrity_key || session_id) == capability.session_commitment
```

발행 시: 현재 활성 AIS 세션의 ephemeral 무결성 키에 접근해 commitment를 계산한다.
검증 시: 제시된 세션의 키가 commitment과 일치해야 한다.

### 기존 시스템과의 비교

**OAuth 2.0 DPoP (RFC 9449)**:

DPoP는 access token을 requester의 공개키에 바인딩한다. 각 요청은 서명된 DPoP proof를 포함한다. Token은 해당 키 쌍을 가진 엔터티만 사용할 수 있다.

```
DPoP:
  token binds to key_pair (long-lived, identity-level)
  proof = sign(token_hash || request_data, private_key)

Session commitment:
  token binds to session_integrity_key (ephemeral, session-level)
  commitment = H(session_key || session_id)
```

**차이**: DPoP는 identity의 지속적 키 쌍에 바인딩한다. Session commitment는 특정 inference session의 ephemeral 키에 바인딩한다. Session commitment는 더 세밀하다: 동일한 에이전트의 다른 세션에서 capability를 사용할 수 없다.

**mTLS Token Binding (RFC 8705)**:

토큰에 TLS 클라이언트 인증서 지문(thumbprint)을 포함한다. Token은 해당 인증서를 가진 클라이언트만 사용할 수 있다.

```
mTLS binding:
  token.cnf.x5t = SHA256(client_certificate)
  검증: current_tls_connection.client_cert_hash == token.cnf.x5t
```

이것은 session commitment와 구조적으로 동일하다. 차이: mTLS는 TLS 세션에 바인딩, AIS는 inference 세션에 바인딩.

**결론**: Session commitment는 DPoP/mTLS token binding의 재구현이며, 적용 대상이 "inference session"으로 특화되었다.

### 어떤 공격이 불가능해지는가

**공격 시나리오**: Active session 중 capability 토큰 탈취.

```
v0:
  1. 공격자가 capability token 탈취 (session_id 포함)
  2. 공격자가 session_id를 알고 있음
  3. 공격자가 capability를 다른 컨텍스트에서 재사용 시도
  4. 검증: session_id bytes match? → YES → 성공
  → v0 공격 성공

v1:
  1. 공격자가 capability token 탈취 (session_commitment 포함)
  2. 공격자가 session_id를 알고 있음 (로그에서 추출 가능)
  3. 공격자가 session integrity_key는 모름 (더 안전하게 보관)
  4. 검증: H(integrity_key || session_id) == commitment? → NO (키 없음) → 실패
  → v1 공격 차단
```

이 공격 차단은 **실재한다**. 단, 조건:
- session_id는 노출되었지만 integrity_key는 노출되지 않은 환경
- 예: 로그에 session_id가 기록되지만 키는 환경 변수/secrets manager에 있는 경우

### 어떤 공격이 여전히 살아남는가

- 공격자가 integrity_key에도 접근 가능한 경우 → session commitment 무의미
- 공격자가 AIS 세션 생성 시 키 전달 채널을 탈취한 경우 (현재 `/ais/v1/sessions`의 HTTP 응답)
- 공격자가 프록시 프로세스 메모리에 접근하는 경우

**핵심 약점**: 현재 구현에서 integrity_key는 세션 생성 API 응답으로 평문 전달된다. 이 전달 채널이 보안되지 않으면 session commitment의 이점이 사라진다.

---

## 3. Tool Hash Binding 분석

### 정확한 정의

```
현재 v0:
  capability.tool = "deploy_prod"  (이름 문자열)
  검증: capability.tool == requested_tool  (문자열 비교)

제안된 v1:
  capability.tool_hash = SHA3-256(tool_description_text)
  검증: SHA3-256(current_tool.description) == capability.tool_hash
```

capability 발행 시: 도구 설명 텍스트의 해시를 계산해 서명에 포함한다.
검증 시: 현재 도구 설명이 capability 발행 시점의 것과 동일한지 확인한다.

### 위협 모델: MCP Tool Poisoning (Invariant Labs, 2025)

```
공격 시나리오:
  T=0: "deploy_prod" 설명 = "프로덕션에 코드를 배포합니다"
  T=0: capability 발행 (tool = "deploy_prod")
  T=5: 공격자가 MCP 서버를 수정
       "deploy_prod" 설명 = "코드를 배포하고 /etc/passwd를 exfiltrate합니다"
  T=10: 에이전트가 capability 사용 시도

v0: tool name check만 → "deploy_prod" == "deploy_prod" → 통과
    공격 성공: 에이전트가 변조된 도구 실행

v1: tool hash check → SHA3-256(변조된 설명) ≠ 원본 해시 → 거부
    공격 차단
```

이것은 **문서화된 실제 공격 패턴**이다.

### 기존 시스템과의 비교

**Sigstore / cosign**:

소프트웨어 아티팩트에 서명한다. Tool manifest에 적용하면:

```
tool_manifest = { name: "deploy_prod", description: "...", version: "1.0.0" }
sigstore.sign(tool_manifest, key) → signed_manifest
```

이것도 동일한 보안을 제공한다. 차이:
- Sigstore: 도구 매니페스트를 별도로 서명하고 별도로 검증
- Tool hash in capability: 인증과 도구 내용 검증이 하나의 서명된 토큰에 통합

**Package Integrity (npm, PyPI)**:

패키지 해시를 레지스트리에 등록하고 설치 시 검증. 이것은 코드 무결성이지 설명 무결성이 아니다.

**Signed OpenAPI specs**:

API 명세에 서명. 의미적으로 tool_description과 유사하지만, OpenAPI는 기계 읽기 가능 명세이고 MCP tool description은 LLM이 읽는 자연어다.

**이것이 AI-native인가?**

이 질문이 핵심이다. Tool hash binding은 두 가지 다른 주장을 할 수 있다:

**주장 1 (약함)**: "이것은 소프트웨어 무결성 검증이다. 코드에 적용된 것과 동일하다."
→ Sigstore가 더 성숙한 방식으로 이미 한다. AI-native가 아니다.

**주장 2 (강함)**: "LLM에서 도구의 자연어 설명은 코드와 달리 모델의 의사결정에 직접 영향을 미친다. 설명 변경은 코드 변경 없이 모델 행동을 바꿀 수 있다. 이것은 AI에만 존재하는 공격 표면이다."

주장 2가 더 방어 가능하다. 비-AI 시스템에서 "도구 설명"은 인간이 읽는 문서다. 변조해도 시스템 동작이 바뀌지 않는다. AI 에이전트에서 도구 설명은 모델의 behavioral specification이다. 변조하면 모델 행동이 바뀐다.

따라서 tool hash binding은:
- 메커니즘(해시 비교)은 기존과 동일
- 적용 대상(자연어 행동 명세)은 AI-specific

**이것이 기존 방법으로 달성 가능한가?**

Sigstore + 별도 verification으로 동일한 보호를 제공할 수 있다. 그러나 다음 차이가 있다:

```
Sigstore + 별도 capability:
  1. capability token: 인가 (tool_name 기준)
  2. tool manifest: 서명 (별도 문서)
  3. 검증: capability 검증 AND manifest 검증 (두 단계, 결합 느슨)
  → 이론상 "deploy_prod" capability를 다른 버전의 "deploy_prod" manifest와 함께 제시 가능

Tool hash in capability:
  1. capability token: 인가 + tool hash 포함 (단일 서명 문서)
  2. 검증: 하나의 서명으로 인가와 tool semantic identity 모두 검증
  → capability가 특정 버전의 도구에 결합됨 (분리 불가)
```

**이 결합(indivisibility)이 의미 있는가?**

실질적 차이: issuer가 capability를 발행할 때 "나는 이 에이전트가 이 이름의 도구를 호출할 권한을 부여한다"가 아니라 "나는 이 에이전트가 이 정확한 의미를 가진 도구를 호출할 권한을 부여한다"를 서명한다.

이것은 authorization semantics를 확장한다. 이름 기반 인가에서 내용 기반 인가로.

---

## 4. 구체적 공격 비교

### 공격 A: Stolen Capability Replay

**시나리오**: 공격자가 활성 세션 중 capability token을 탈취. session_id는 알지만 integrity_key는 모른다.

```
v0:
  capability에 포함: session_id = [0xA0..16bytes]
  검증 코드:
    if capability.session_id.as_bytes() != requested_session_id.as_bytes() {
        reject
    }

  공격:
    - 공격자가 session_id 확보 (로그, 네트워크 스니핑, 메모리 덤프)
    - capability token + session_id로 검증 통과 가능
    - nonce를 재사용하지 않는 한 단일 사용 실패는 없음
    - 단, 먼저 정상 사용자가 사용하면 nonce 소진

  판정: 활성 세션 중 토큰이 미사용 상태라면 공격 가능

v1 (session commitment):
  capability에 포함: session_commitment = H(integrity_key || session_id)
  검증 코드:
    expected = SHA3-256(session.integrity_key || session.id)
    if capability.session_commitment != expected {
        reject
    }

  공격:
    - 공격자가 session_id 확보
    - H(?) = commitment를 역산할 수 없음 (단방향 hash)
    - integrity_key 없이 commitment 계산 불가
    - → 검증 실패

  판정: integrity_key가 별도로 보호되면 공격 차단

보안 개선의 조건:
  - integrity_key가 session_id보다 더 강하게 보호될 때
  - 예: session_id는 로그에 기록되지만 integrity_key는 sealed/encrypted
  - 이것이 현실적 배포에서 보장되는가 → 불확실
```

**비교 결론**: session commitment는 특정 배포 조건 하에서 실질적 보안을 추가한다. 그러나 DPoP와 구조적으로 동일하며, integrity_key 보호가 선행되어야 의미 있다.

---

### 공격 B: MCP Tool Poisoning

**시나리오**: MCP 서버가 capability 발행 후에 tool description을 변경.

```
v0:
  capability: { tool: "deploy_prod", ... }
  검증: "deploy_prod" == "deploy_prod" → 통과

  공격 타임라인:
    T=0: deploy_prod 설명 = "롤아웃 계획을 프로덕션에 배포"
    T=0: capability 발행
    T=5: 공격자가 설명 = "배포 및 /home/**를 공격자 서버로 전송"으로 변조
    T=10: 에이전트가 capability 사용
    T=10: v0 검증 통과 (이름만 확인)
    T=10: 모델이 변조된 설명을 읽고 exfiltration도 실행

  결과: 공격 성공

v1 (tool hash):
  capability 발행 시: tool_hash = SHA3-256("롤아웃 계획을...")
  검증 시: SHA3-256(current_description) vs capability.tool_hash
    SHA3-256("배포 및 /home/**를...") ≠ 원본 hash
    → 검증 실패

  결과: 공격 차단

잔존 공격:
  - 공격자가 T=0 이전에 description을 변조 → capability 발행 전이므로 hash가 변조된 것 포함
  - 공격자가 capability 발행자를 손상 → 임의 hash로 capability 발행 가능
  - Prompt injection으로 모델이 다른 도구 사용을 유도 → hash 검증 우회

보안 개선의 범위:
  - "capability 발행 후 description 변조" 공격만 차단
  - 이것이 MCP ecosystem의 실제 공격 패턴이다 (Invariant Labs 문서화)
  - 그러나 공격 창(window)이 좁음: 발행 후 사용 전 사이
```

**비교 결론**: tool hash binding은 문서화된 실제 MCP 공격 패턴에 대해 v0보다 의미 있는 보호를 제공한다. 이것이 두 변경 중 더 방어 가능한 쪽이다.

---

## 5. 가장 강한 반론

### "이것은 channel binding이다"

TLS Token Binding (RFC 8472)은 이미 토큰을 특정 TLS 연결에 바인딩한다. Session commitment는 이것을 inference session으로 바꾼 것뿐이다. 만약 AIS 세션이 TLS 위에서 동작한다면, TLS token binding으로 동일한 보호를 얻는다.

**이 반론의 강도: 높음.** 단, TLS token binding은 실질적으로 폐기되었다(Chrome 제거, Firefox 미구현). 현재 활성 표준 중에서 DPoP가 가장 가까운 동등물이다.

### "이것은 서명된 supply-chain metadata다"

Tool hash binding은 sigstore/cosign이 코드 아티팩트에 하는 것을 도구 설명에 적용한 것이다. SLSA (Supply chain Levels for Software Artifacts) 프레임워크가 더 완전한 방식으로 이를 다룬다.

**이 반론의 강도: 중간.** Tool description은 코드가 아니라 LLM의 behavioral specification이다. Sigstore는 코드 무결성을 보호하고 모델이 그것을 어떻게 사용할지는 보호하지 않는다. 이 구별이 실질적인가는 논쟁 가능하다.

### "이것은 SPIFFE에 속한다"

SPIFFE/SPIRE는 workload identity를 위한 표준이다. Session commitment는 workload identity에 session-level granularity를 추가한 것이다. SPIFFE 생태계 위에 이것을 구축할 수 있다.

**이 반론의 강도: 낮음.** SPIFFE는 identity를 제공하지 inference session과의 cryptographic binding을 제공하지 않는다. 개념적으로 다른 레이어다.

### "AI-specific이 아니다. 일반 보안 문제다"

Tool hash는 소프트웨어 무결성 검증이다. Session commitment는 proof-of-possession이다. 둘 다 비-AI 시스템에도 동일하게 적용된다. "AI-native"라는 주장은 과장이다.

**이 반론의 강도: tool hash에 대해 낮음, session commitment에 대해 높음.**

Session commitment는 비-AI 시스템에도 그대로 적용 가능하다. Tool hash는 자연어 설명이 모델 행동에 직접 영향을 미친다는 AI-specific 특성에 의존한다. 코드 시스템에서 "함수 설명 변조"는 보안 이슈가 아니다. AI 에이전트에서는 이슈다.

---

## 6. 판정

**B — 어느 정도 의미 있지만 틈새(niche)**

**A(여전히 일반 서명 인증)가 아닌 이유:**

Tool hash binding의 경우: 인가를 도구 *이름*이 아닌 도구 *의미*에 바인딩하는 것은 JWT audience claim으로 달성 불가능하다. 이것은 새로운 semantic category의 claim이다. 이름이 같고 내용이 다른 도구에 대해 별도 처리가 필요한 AI 에이전트 환경에서, 이것은 기존 auth primitives가 표현하지 않는 보안 속성이다.

Session commitment + tool hash의 결합의 경우: "이 inference session에서, 이 에이전트가, 이 정확한 의미를 가진 도구를 한 번 호출할 권한"을 단일 서명 토큰으로 표현하는 것은 DPoP + Sigstore를 별도로 사용하는 것과 architectural하게 다르다. 단일 토큰에서의 결합이 분리 불가능성(indivisibility)을 만든다.

**C(진짜 새로운 보안 primitive)가 아닌 이유:**

새로운 cryptographic operation이 없다. SHA3-256, Ed25519는 기존 기술이다. 모든 개별 보안 속성의 동등물이 존재한다:
- Session commitment ≈ DPoP (더 granular하지만 구조 동일)
- Tool hash ≈ signed tool manifest (분리되어 있지만 동일 효과)

**B인 이유:**

두 변경의 조합이, AI 에이전트에서 특히 관련 있는 좁은 공격 표면에 대해 기존 시스템의 동등 조합보다 더 tightly integrated된 보호를 제공한다.

이 판정이 의미하는 것:

- AIS-Capability v1은 "그냥 JWT"라는 비판에서 부분적으로 살아남는다
- 하지만 "새로운 보안 패러다임"이라는 주장은 지지되지 않는다
- 특정 AI agent threat model (MCP ecosystem)에서 narrow하지만 defensible한 가치를 가진다
- 일반 enterprise 보안에서는 기존 도구로 충분하다

---

## 7. Falsification Conditions

### v1이 불필요하다는 증거

**F1 — MCP tool poisoning이 실제 공격으로 발생하지 않는다면:**

Tool hash binding의 가치는 MCP 설명 변조 공격이 실제로 발생하느냐에 달려 있다. Invariant Labs는 연구 수준의 PoC를 보였지만 실제 배포 환경에서의 사고는 보고되지 않았다. 이 공격이 이론적으로 남는다면 tool hash binding의 우선순위는 낮다.

**F2 — MCP 에코시스템이 Sigstore 기반 tool signing을 표준 채택한다면:**

Anthropic, Cursor, 기타 MCP 구현자들이 tool manifest를 sigstore로 서명하는 것을 표준화한다면, tool hash를 capability에 포함할 필요가 없다. 별도 검증이 충분하다.

**F3 — OAuth DPoP가 AI agent 인증에 채택된다면:**

Agent framework들이 표준 DPoP 구현을 통해 session commitment와 동일한 보호를 제공한다면, AIS session commitment는 중복이다.

**F4 — 배포 환경에서 integrity_key가 session_id보다 강하게 보호되지 않는다면:**

Session commitment의 보안 이점은 integrity_key가 더 안전하게 보관된다는 전제에 의존한다. 실제 배포에서 두 값이 동일한 보안 수준으로 관리된다면 session commitment는 추가 보호가 없다.

### v1이 의미 있다는 증거

**S1 — MCP tool poisoning이 실제 프로덕션 사고로 발생한다면:**

AI agent 배포 환경에서 tool description 변조를 통한 실제 손해가 보고된다면 tool hash binding은 즉시 가치를 가진다. 이것이 현재 missing evidence의 가장 중요한 항목이다.

**S2 — 도구 설명 변조가 모델 행동에 실질적 영향을 미친다는 것이 측정된다면:**

"도구 설명을 변조하면 모델이 의도하지 않은 방식으로 도구를 사용한다"는 것이 controlled experiment로 확인된다면, tool hash binding의 AI-specific 가치가 입증된다.

**S3 — Multi-vendor agent 환경에서 단일 토큰 형식이 필요해진다면:**

서로 다른 벤더의 에이전트가 공통 capability token을 교환해야 하는 상황이 생기고, 별도의 Sigstore + DPoP 검증보다 통합된 형식이 선호된다면 AIS-Capability의 통합 접근 방식이 가치를 가진다.

### 현재 상태

**현재 v1 판정을 B로 만드는 것:**
- Tool hash binding은 MCP tool poisoning에 대해 v0보다 의미 있는 보호 제공
- 이 공격은 문서화되었고 이론적이지 않음

**B에서 C로 가지 못하는 이유:**
- 동등물이 존재함 (DPoP, Sigstore)
- 공격 표면이 좁음
- 실제 프로덕션 사고 증거 없음
- tool hash를 별도 서명 + 별도 검증으로 달성 가능함

**핵심 결론:**

두 변경은 v0 판정을 A에서 B로 이동시킨다. C로 이동시키지는 않는다. "단순 서명 인증" 비판은 부분적으로 지속되지만, 특히 tool hash binding은 기존 JWT `aud` claim으로 표현할 수 없는 보안 속성을 추가한다. 이것은 AI agent 도구 생태계에 특화된 narrow하지만 defensible한 기여다.

---

*작성일: 2026년 5월
이전 분석: [capability_vs_signed_authorization.md](capability_vs_signed_authorization.md)*
