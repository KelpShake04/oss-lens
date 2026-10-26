# oss-lens

오픈소스 의존성 보안·라이선스 진단기. 프로젝트가 쓰는 오픈소스 라이브러리의 취약점(CVE)과 라이선스 위험을 찾아, 로컬 LLM이 한국어로 위험도·영향·조치 방법을 설명하는 HTML 리포트를 만든다. 코드는 외부로 전송하지 않는다.

2026 하반기 우송대 SW중심대학 오픈소스 AI·SW활용 경진대회 출품작.

## 구성 (사용 오픈소스)
- [syft](https://github.com/anchore/syft) (Apache-2.0): SBOM 생성
- [grype](https://github.com/anchore/grype) (Apache-2.0): 취약점 매칭
- [Ollama](https://github.com/ollama/ollama) (MIT) + qwen3:8b: 한국어 해설

## 흐름
폴더 입력 → syft SBOM → grype 취약점 → 라이선스 규칙 검사 → 상위 위험 항목 LLM 해설 → HTML 리포트

## 상태
MVP 개발 중. 계획: [docs/plan.md](docs/plan.md)
