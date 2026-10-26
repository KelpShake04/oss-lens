# 검증 기록 (2026-10-26)

데모용 프로젝트에만 맞춰지지 않았는지 확인하려고, 일부러 취약하게 만든 실제 오픈소스 프로젝트에 적용했다.
환경: MacBook Pro (M1 Pro), syft 1.55.0, grype 0.121.0, Ollama + qwen3:8b.

## 대상과 결과

| 프로젝트 | 생태계 | 패키지 | 취약점 (치명·높음) | 비고 |
|---|---|---|---|---|
| `examples/vulnerable-demo` | npm + Python | 15 | 170 (96) | GPL 라이선스 충돌 1건 |
| [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) | npm (lock v2) | 384 | 90 (61) | 다른 패키지에 묶인 의존성 포함 |
| [PyGoat](https://github.com/adeyosemanputra/pygoat) | Python (requirements 여러 개) | 61 | 356 (169) | 버전 미고정 4개 경고 |
| [DVNA](https://github.com/appsecco/dvna) | npm (lock 없음) | 0 | - | '검사하지 못함' 경고 |

GitHub URL 을 그대로 입력해 검사했다 (`oss-lens scan https://github.com/OWASP/NodeGoat --top 8`).

## 검증으로 찾아 고친 문제

| 발견 위치 | 문제 | 수정 |
|---|---|---|
| 데모 (맥 4회차) | grype `--by-cve` 가 ID 만 CVE 로 바꾸고 NVD 원문 설명을 버려, AI 가 한 줄 제목만 보고 해설함 | `--by-cve` 제거, 파서가 CVE 정리·가장 긴 설명 선택 |
| NodeGoat | 배포 주소가 없는 묶음 의존성(inBundle)을 프로젝트 자신으로 오인해 누락 | lock 파일의 자기 이름·버전으로만 판별 (패키지 350→384) |
| DVNA | lock 파일 없는 package.json 은 패키지 0개 → '취약점 0건'이 안전처럼 보임 | 리포트 맨 위 경고 |
| PyGoat | 버전 미고정 requirements 항목은 syft 가 조용히 건너뜀 | 경고에 항목·파일 표시 |
| PyGoat | 상위 8개가 3개 패키지(pyyaml·pillow·django)에 몰림 | 패키지별 1개씩 먼저 선택, '같은 패키지 N건 더' 표시 |
| PyGoat | Windows 에서만 생기는 Django DoS 인데 해설에 조건 누락 | 원문의 'on Windows' 를 모델에 전달, 빠지면 덧붙임 |
| PyGoat·NodeGoat | 원문이 exec·eval·Popen·Code Injection 인데 '코드 실행' 문장을 지움 | 실행 근거 표현 확대 |

## AI 해설 품질 (qwen3:8b)

처음엔 규칙을 프롬프트로만 줬더니 8B 모델이 지키지 못했다: 반말 섞임, 명령어 잘림, 원문에 없는
'코드 실행' 과장, 근거 없는 임시 대응, 그리고 Django SQL 주입에 "string formatting 으로 처리하라"는
**틀린 조언**(SQL 주입의 원인 그 자체). 그래서 지켜야 할 것은 코드로 보정한다 (`oss_lens/llm.py` `postprocess`).

- 원문에서 함수·옵션 이름을 뽑아 요약에 넣게 하고, 빠지면 덧붙인다 (`QuerySet.order_by`, `full_load`)
- 원문의 위험 조건(if/when/workaround)이 없거나, 조건의 함수 이름을 언급하지 않는 임시 대응은 지운다
- 원문에 실행 언급이 없는 '코드 실행' 문장은 지운다
- 실제 공격 사례(CISA KEV)는 항상 영향 첫 문장에 넣는다

최종 확인한 해설 21개 (데모 5, NodeGoat 8, PyGoat 8):
- 올릴 버전이 모두 원문 권고와 일치
- 틀린 조언 0건
- 원문 근거가 있는 임시 대응이 나온 예:
  - Django: "order_by 에 사용자 입력을 그대로 넣지 말고 허용된 필드만 사용"
  - PyYAML: "신뢰할 수 없는 YAML 을 full_load·FullLoader 로 처리하지 않기"
  - urllib3: "`preload_content=False` 사용 시 `redirect=False`"

## 남은 한계
- requirements.txt·버전 미고정 의존성은 라이선스 정보가 없다 (`--remote-licenses` 로 조회 가능)
- 역직렬화 취약점은 원문에 실행 언급이 없어도 '코드 실행'을 허용한다 (bson 처럼 다소 넓게 해석될 수 있음)
- 해설 문장의 자연스러움은 모델 한계가 남아 있다 (예: 연결어 반복, 영문 대소문자 오타)
