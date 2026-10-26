"""명령행 진입점: python -m osslens scan <folder>"""

import argparse
import os
import sys

from osslens import __version__, licenses, llm, report, scanner


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def build_parser():
    parser = argparse.ArgumentParser(prog="osslens", description="오픈소스 의존성 보안·라이선스 진단기")
    parser.add_argument("--version", action="version", version=f"oss-lens {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="폴더를 스캔해 HTML 리포트를 만든다")
    scan.add_argument("folder", help="스캔할 프로젝트 폴더")
    scan.add_argument("-o", "--output", default="report.html", help="리포트 파일 경로 (기본: report.html)")
    scan.add_argument("--llm-host", default=None,
                      help=f"Ollama 주소 (기본: OLLAMA_HOST 환경변수 또는 {llm.DEFAULT_HOST})")
    scan.add_argument("--model", default=llm.DEFAULT_MODEL, help=f"Ollama 모델 (기본: {llm.DEFAULT_MODEL})")
    scan.add_argument("--top", type=int, default=5, help="LLM이 해설할 상위 취약점 수 (기본: 5)")
    scan.add_argument("--no-llm", action="store_true", help="LLM 해설 없이 리포트만 만든다")
    return parser


def scan(folder, output, llm_host=None, model=llm.DEFAULT_MODEL, top=5, use_llm=True):
    """전체 파이프라인. 성공 시 리포트 경로를 돌려준다. 스캐너 실패는 ScanError로 올린다."""
    target = os.path.abspath(folder)
    log(f"[1/4] syft로 SBOM 생성: {target}")
    sbom = scanner.run_syft(target)
    packages = scanner.parse_syft(sbom)
    log(f"      패키지 {len(packages)}개")

    log("[2/4] grype로 취약점 검사")
    grype_data = scanner.run_grype(sbom)
    vulns = scanner.parse_grype(grype_data)
    log(f"      취약점 {len(vulns)}건")

    log("[3/4] 라이선스 규칙 검사")
    license_findings = licenses.check_licenses(packages)
    log(f"      라이선스 경고 {len(license_findings)}건")

    explanations, llm_status = {}, None
    if not use_llm:
        llm_status = "--no-llm 옵션으로 LLM 해설을 생략했습니다."
        log("[4/4] LLM 해설 생략 (--no-llm)")
    else:
        try:
            host = llm.resolve_host(llm_host)
        except ValueError as exc:
            host, llm_status = None, f"{exc} — LLM 해설 없이 리포트를 만듭니다."
        if host:
            log(f"[4/4] LLM 해설: {host} / {model} (상위 {top}건)")
            client = llm.OllamaClient(host, model)
            explanations, llm_status = llm.explain_top(vulns, client, top, log=log)
        if llm_status:
            log("      " + llm_status)

    html_text = report.render_report(
        target=target, packages=packages, vulns=vulns, license_findings=license_findings,
        explanations=explanations, llm_status=llm_status, model=model,
        tools=f"{scanner.tool_version(sbom)}, {scanner.tool_version(grype_data)}",
    )
    out_dir = os.path.dirname(os.path.abspath(output))
    os.makedirs(out_dir, exist_ok=True)
    with open(output, "w", encoding="utf-8") as fh:
        fh.write(html_text)
    log(f"리포트 저장: {os.path.abspath(output)}")
    return output


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        try:
            scan(args.folder, args.output, args.llm_host, args.model, args.top, not args.no_llm)
        except scanner.ScanError as exc:
            log(f"오류: {exc}")
            return 2
        except OSError as exc:
            log(f"오류: 리포트를 저장할 수 없습니다: {exc}")
            return 2
    return 0
