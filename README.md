# oss-lens

오픈소스 의존성 보안·라이선스 진단기. 프로젝트가 쓰는 오픈소스 라이브러리의 취약점(CVE)과 라이선스 위험을 찾아, 로컬 LLM이 한국어로 위험도·영향·조치 방법을 설명하는 HTML 리포트를 만든다. 코드는 외부로 전송하지 않는다.

2026 하반기 우송대 SW중심대학 오픈소스 AI·SW활용 경진대회 출품작.

## 구성 (사용 오픈소스)
- [syft](https://github.com/anchore/syft) (Apache-2.0): SBOM 생성
- [grype](https://github.com/anchore/grype) (Apache-2.0): 취약점 매칭
- [Ollama](https://github.com/ollama/ollama) (MIT) + qwen3:8b: 한국어 해설

## 흐름
폴더/GitHub URL 입력 → syft SBOM → grype 취약점 → 라이선스 규칙 검사 → 상위 위험 항목 LLM 해설 → HTML 리포트

## 설치
```bash
brew install syft grype                       # SBOM·취약점 도구
brew install ollama && ollama pull qwen3:8b   # (선택) 한국어 AI 해설

git clone https://github.com/KelpShake04/oss-lens.git
cd oss-lens                                   # 이후 명령은 모두 이 폴더에서
python3 -m venv .venv && source .venv/bin/activate
pip install -U pip                            # 맥 기본 pip(21.x)는 editable 설치를 못 함
pip install -e .                              # Python 3.9+, 외부 패키지 의존성 없음
oss-lens doctor                               # 설치 상태 확인
```
새 터미널을 열 때마다 `source .venv/bin/activate` 를 먼저 실행한다.
설치 없이 저장소 폴더에서 `python3 -m oss_lens doctor` 처럼 실행해도 된다.

## 사용
```bash
oss-lens scan examples/vulnerable-demo          # 데모용 취약 프로젝트
oss-lens scan ~/my-project --top 10             # AI 해설 10개
oss-lens scan https://github.com/owner/repo     # GitHub 저장소 (임시 폴더에 복제 후 삭제)
oss-lens show out/vulnerable-demo --source      # 저장된 AI 해설을 터미널에 출력 (--source: 원문 함께)
```
결과는 `out/<이름>/` 에 저장된다.

lock 파일 없는 `package.json`, 버전을 고정하지 않은 `requirements.txt` 항목처럼 syft 가 의존성을 찾지 못하는 경우는
리포트 맨 위에 경고로 표시한다. '취약점 0건'이 '안전'이 아니라 '검사하지 못함'일 수 있기 때문이다.

| 파일 | 내용 |
|---|---|
| `report.html` | 리포트 (파일 하나, 오프라인으로 열림) |
| `report.json` | 같은 내용의 JSON (다른 도구·UI 연동용) |
| `sbom.json`, `grype.json` | syft·grype 원본 결과 |
| `llm-cache.json` | AI 해설 캐시 (같은 항목 재실행 시 LLM 호출 생략) |

주요 옵션

| 옵션 | 설명 |
|---|---|
| `--top N` | AI 해설할 상위 위험 취약점 수 (기본 5) |
| `--no-llm` | LLM 없이 규칙 기반 한국어 설명만 사용 |
| `--model`, `--ollama-host` | Ollama 모델·서버. 기본은 `OLLAMA_HOST` 환경변수 또는 로컬 |
| `--project-license` | 프로젝트 라이선스 지정 (기본: `LICENSE` 파일에서 감지, 없으면 비공개/상용 배포 가정) |
| `--remote-licenses` | `requirements.txt` 처럼 라이선스가 안 적힌 패키지를 PyPI·npm 에서 조회 |
| `--sbom`, `--grype-json` | 저장해 둔 syft·grype 결과로 다시 리포트만 생성 |

맥에서 LLM이 느리면 GPU PC에서 `OLLAMA_HOST=0.0.0.0 ollama serve` 로 띄우고 `--ollama-host 192.168.x.x` 로 원격 호출한다. Ollama에 연결할 수 없으면 자동으로 규칙 기반 설명으로 대체한다.

## 리포트 내용
1. 요약: 패키지 수, 심각도별 취약점 수, 패치 가능 비율, 라이선스 주의 건수
2. 먼저 고칠 취약점: 위험 점수 상위 N개에 대한 AI 해설(요약·영향·조치)과 복사 가능한 업그레이드 명령
3. 업그레이드 계획: 패키지별로 한 번에 올릴 버전 (여러 CVE를 한 번에 해결하는 버전)
4. 라이선스 점검: 프로젝트 라이선스 기준 충돌 위험 (GPL·AGPL·LGPL·상업 이용 제한 등)
5. 전체 취약점 표 (심각도 필터·검색), 전체 패키지 목록(SBOM)

위험 점수 = CVSS 기본 점수(없으면 심각도별 기본값) + 실제 공격 확인(CISA KEV) 3점 + 악용 확률(EPSS) × 3 + 패치 존재 0.5

## 외부 통신
- 소스코드: 전송하지 않음. LLM 해설은 로컬(또는 직접 지정한 사내) Ollama 서버에서만 실행
- grype: 취약점 DB 를 내려받음 (업로드 없음)
- `--remote-licenses` 사용 시: 패키지 이름·버전으로 공개 저장소 조회
- GitHub URL 입력 시: `git clone`

## 개발
```bash
pip install -e ".[dev]"
pytest
```
테스트는 `tests/fixtures/` 의 syft·grype 결과를 써서 도구 설치 없이 돈다.

```
oss_lens/
  cli.py        명령행 (scan, doctor)
  scanner.py    syft·grype·git 실행
  parsers.py    syft·grype JSON 파싱
  risk.py       위험 점수·업그레이드 명령·업그레이드 계획
  licenses.py   라이선스 분류(SPDX 식 포함)·충돌 규칙
  llm.py        Ollama 클라이언트·프롬프트·규칙 기반 대체 설명
  report.py     HTML·JSON 리포트
```

## 상태
MVP 동작. 계획: [docs/plan.md](docs/plan.md)
