# oss-lens

오픈소스 의존성 보안·라이선스 진단기. 프로젝트가 쓰는 오픈소스 라이브러리의 취약점(CVE)과 라이선스 위험을 찾아, 로컬 LLM이 한국어로 **위험도·영향·조치 방법**을 설명하는 HTML 리포트를 만든다. 소스 코드는 외부로 전송하지 않는다.

2026 하반기 우송대 SW중심대학 오픈소스 AI·SW활용 경진대회 출품작.

## 특징
- 폴더 하나만 넣으면 SBOM 생성 → 취약점 매칭 → 라이선스 검사 → 한국어 해설 → HTML 리포트까지 한 번에
- 카피레프트(GPL·AGPL·LGPL·SSPL)와 라이선스 미확인 패키지를 한국어 설명과 함께 경고
- 심각도 상위 N건만 LLM 해설 (전부 넣으면 느리므로)
- LLM 서버가 없거나 꺼져 있어도 해설 없이 리포트는 정상 생성
- Python 3 표준 라이브러리만 사용 (pip 설치 불필요), 리포트는 외부 리소스 없는 단일 HTML 파일

## 설치
```bash
# 1. 스캐너 (macOS)
brew install syft grype
grype db update          # 취약점 DB 최초 다운로드 (인터넷 필요)

# 2. 로컬 LLM (선택)
# https://ollama.com 에서 Ollama 설치 후
ollama pull qwen3:8b

# 3. oss-lens
git clone https://github.com/KelpShake04/oss-lens.git
cd oss-lens              # Python 3.9+ 필요, 추가 패키지 없음
```

## 사용법
```bash
python -m osslens scan <폴더> [-o report.html] [--llm-host URL] [--model qwen3:8b] [--top 5] [--no-llm]
```

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `-o, --output` | 리포트 파일 경로 | `report.html` |
| `--llm-host` | Ollama 주소 | `OLLAMA_HOST` 환경변수, 없으면 `http://localhost:11434` |
| `--model` | Ollama 모델 | `qwen3:8b` |
| `--top` | LLM이 해설할 상위 취약점 수 | `5` |
| `--no-llm` | LLM 해설 생략 | - |

### 예시
```bash
# 데모 샘플 스캔 (LLM 포함)
python -m osslens scan demo/vulnerable-sample -o report.html

# LLM 없이 빠르게
python -m osslens scan demo/vulnerable-sample -o report.html --no-llm
```
```
[1/4] syft로 SBOM 생성: .../demo/vulnerable-sample
      패키지 7개
[2/4] grype로 취약점 검사
      취약점 N건
[3/4] 라이선스 규칙 검사
      라이선스 경고 4건
[4/4] LLM 해설: http://localhost:11434 / qwen3:8b (상위 5건)
리포트 저장: .../report.html
```
리포트에는 심각도별 요약, 심각도 순 취약점 표(수정 버전·CVSS·원문 설명), 라이선스 경고, LLM 해설, 전체 패키지 목록이 들어간다.

### 원격 Ollama (예: RTX 3070 PC)
노트북이 느리면 GPU가 있는 PC에서 Ollama를 돌리고 같은 공유기(LAN) 안에서 호출한다.
```bash
# GPU PC (Windows라면 시스템 환경변수로 설정 후 Ollama 재시작)
OLLAMA_HOST=0.0.0.0:11434 ollama serve

# 노트북
export OLLAMA_HOST=192.168.0.10:11434     # GPU PC의 LAN IP
python -m osslens scan demo/vulnerable-sample
# 또는 --llm-host http://192.168.0.10:11434
```
> ⚠️ Ollama API에는 인증이 없다. **LAN 안에서만** 쓰고 공유기 포트포워딩으로 인터넷에 열지 말 것. Windows 방화벽도 사설망(개인 네트워크)에서만 허용한다.

## 구조
```
폴더 ──▶ syft (SBOM, JSON) ──▶ grype sbom:<파일> (취약점, JSON)
                │                         │
                ▼                         ▼
        라이선스 규칙 검사          심각도 정렬 → 상위 N건
                │                         │
                │                  Ollama /api/chat (한국어 해설)
                ▼                         ▼
                └──────▶ HTML 리포트 ◀────┘
```

| 모듈 | 역할 |
|------|------|
| `osslens/cli.py` | 명령행 인자, 전체 파이프라인 |
| `osslens/scanner.py` | syft·grype 실행, JSON 파싱, 심각도 정렬 |
| `osslens/licenses.py` | 라이선스 규칙 표 (GPL/AGPL/LGPL/SSPL/미확인) |
| `osslens/llm.py` | Ollama HTTP 호출(urllib), 연결 실패 시 해설 생략 |
| `osslens/report.py` | 단일 HTML 리포트 (모든 외부 데이터 `html.escape`) |

### 개인정보·보안
- 소스 코드는 어디에도 보내지 않는다. LLM에 보내는 것은 패키지 이름·버전·취약점 ID·심각도·수정 버전·공개 취약점 설명뿐이며, 보내는 곳은 사용자가 지정한 Ollama 서버 하나다.
- 스캐너·LLM 출력은 신뢰할 수 없는 입력으로 보고 리포트에 넣을 때 모두 HTML 이스케이프한다.
- 라이선스 판단은 참고용이며 법률 자문이 아니다.

### 한계
- `requirements.txt`처럼 라이선스 정보가 없는 목록 파일은 "라이선스 미확인"으로 표시된다 (설치된 패키지 폴더나 lock 파일이 있으면 더 정확).
- npm은 `package-lock.json`이 있어야 의존성이 잡힌다.
- GitHub URL 입력, 웹 UI는 아직 없음.

## 테스트
```bash
python -m unittest
```
syft·grype·Ollama 없이 고정 JSON(tests/fixtures)과 모의 HTTP로 파싱·라이선스 규칙·정렬·HTML 이스케이프·LLM 실패 대응을 검사한다.

## 사용 오픈소스
| 이름 | 용도 | 라이선스 |
|------|------|----------|
| [syft](https://github.com/anchore/syft) | SBOM 생성 | Apache-2.0 |
| [grype](https://github.com/anchore/grype) | 취약점 매칭 | Apache-2.0 |
| [Ollama](https://github.com/ollama/ollama) | 로컬 LLM 서버 | MIT |
| [Qwen3](https://github.com/QwenLM/Qwen3) (qwen3:8b) | 한국어 해설 모델 | Apache-2.0 |
| [Python](https://www.python.org/) 표준 라이브러리 | 구현 언어 | PSF-2.0 |

syft·grype·Ollama는 별도 프로그램으로 설치해 실행만 하며, 이 저장소에 코드를 포함하지 않는다.

## 라이선스
Apache-2.0 ([LICENSE](LICENSE))

## 상태
MVP. 계획: [docs/plan.md](docs/plan.md)
