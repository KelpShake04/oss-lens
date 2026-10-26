"""명령행 진입점: oss-lens scan | show | doctor | web."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from . import __version__, pipeline, risk, scanner
from .llm import DEFAULT_MODEL, OllamaClient
from .models import SEVERITY_KO, Vulnerability


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def cmd_scan(args: argparse.Namespace) -> int:
    opts = pipeline.ScanOptions(
        target=args.target, out=args.out, top=args.top, use_llm=not args.no_llm, model=args.model,
        ollama_host=args.ollama_host, project_license=args.project_license,
        remote_licenses=args.remote_licenses, sbom=args.sbom, grype_json=args.grype_json,
    )
    try:
        result = pipeline.run(opts, progress=lambda msg, frac: log(msg) if frac < 1 else None)
    except scanner.ScanError as e:
        log(f"오류: {e}")
        return 1
    print(result.summary())
    print(f"리포트: {result.html_path}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    ok = True
    for tool in ("syft", "grype"):
        path = shutil.which(tool)
        if path:
            print(f"✓ {tool} {scanner.tool_version(tool) or ''} ({path})")
        else:
            ok = False
            print(f"✗ {tool} 없음 — 설치: {scanner.INSTALL_HINT[tool]}")
    print(f"{'✓' if shutil.which('git') else '△'} git (GitHub URL 입력용)")
    client = OllamaClient(host=args.ollama_host, model=args.model)
    reason = client.check()
    if reason:
        print(f"△ Ollama: {reason} (없으면 규칙 기반 설명 사용)")
    else:
        print(f"✓ Ollama {client.host} · 모델 {client.model}")
    return 0 if ok else 1


def cmd_show(args: argparse.Namespace) -> int:
    """저장된 report.json 의 요약과 AI 해설을 터미널에 출력."""
    path = Path(args.path)
    if path.is_dir():
        path = path / "report.json"
    if not path.is_file():
        log(f"리포트가 없습니다: {path} (먼저 oss-lens scan 을 실행하세요)")
        return 1
    r = json.loads(path.read_text(encoding="utf-8"))
    all_vulns = [Vulnerability(**v) for v in r["vulnerabilities"]]
    by_key = {risk.vuln_key(v): v for v in all_vulns}
    print(f"{r['target']} · 패키지 {len(r['packages'])}개 · 취약점 {len(r['vulnerabilities'])}건")
    for note in r.get("notes", []):
        print(f"! {note}")
    for i, key in enumerate(r["top_keys"], 1):
        v, e = by_key[key], r["explanations"][key]
        desc = v.description
        more = risk.same_package_count(all_vulns, v)
        print(f"\n[{i}] {v.package} {v.version} · {v.id} · {SEVERITY_KO.get(v.severity, v.severity)}"
              f" · {'AI' if e['source'] == 'llm' else '규칙'}" + (f" · 같은 패키지 {more}건 더" if more else ""))
        if args.source:
            print(f"  원문: {desc[:200] + ('…' if len(desc) > 200 else '')}")
        print(f"  요약: {e['summary']}\n  영향: {e['impact']}\n  조치: {e['action']}")
    return 0


def cmd_web(args: argparse.Namespace) -> int:
    from .web import serve

    try:
        serve(out=args.out, host=args.host, port=args.port, open_browser=not args.no_browser,
              model=args.model, ollama_host=args.ollama_host)
    except OSError as e:  # 포트 사용 중 등
        log(f"웹 서버를 시작할 수 없습니다: {e} (--port 로 다른 포트를 지정하세요)")
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="oss-lens", description="오픈소스 의존성 보안·라이선스 진단기")
    p.add_argument("--version", action="version", version=f"oss-lens {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def llm_opts(sp):
        sp.add_argument("--model", default=DEFAULT_MODEL, help=f"Ollama 모델 (기본 {DEFAULT_MODEL})")
        sp.add_argument("--ollama-host", default=None, help="Ollama 서버 주소 (기본: OLLAMA_HOST 또는 127.0.0.1:11434)")

    s = sub.add_parser("scan", help="폴더 또는 GitHub 저장소를 진단해 HTML 리포트 생성")
    s.add_argument("target", help="검사할 폴더 경로 또는 https://github.com/owner/repo")
    s.add_argument("-o", "--out", default="out", help="결과 저장 폴더 (기본 out/)")
    s.add_argument("--top", type=int, default=5, help="AI 해설할 상위 위험 취약점 수 (기본 5)")
    s.add_argument("--no-llm", action="store_true", help="LLM 없이 규칙 기반 설명만 사용")
    s.add_argument("--project-license", help="프로젝트 라이선스 SPDX ID (기본: LICENSE 파일에서 감지)")
    s.add_argument("--remote-licenses", action="store_true",
                   help="패키지 이름으로 PyPI·npm 등에서 라이선스 조회 (코드는 전송하지 않음)")
    s.add_argument("--sbom", help="syft 실행 대신 기존 syft-json SBOM 사용")
    s.add_argument("--grype-json", help="grype 실행 대신 기존 grype JSON 결과 사용")
    llm_opts(s)
    s.set_defaults(func=cmd_scan)

    d = sub.add_parser("doctor", help="필요한 도구(syft·grype·Ollama) 설치 상태 확인")
    llm_opts(d)
    d.set_defaults(func=cmd_doctor)

    sh = sub.add_parser("show", help="저장된 리포트의 AI 해설을 터미널에 출력")
    sh.add_argument("path", help="결과 폴더(out/<이름>) 또는 report.json")
    sh.add_argument("--source", action="store_true", help="취약점 원문 설명(영어)도 함께 출력")
    sh.set_defaults(func=cmd_show)

    w = sub.add_parser("web", help="브라우저에서 쓰는 웹 UI 실행")
    w.add_argument("-o", "--out", default="out", help="리포트 저장 폴더 (기본 out/)")
    w.add_argument("--port", type=int, default=8765, help="포트 (기본 8765)")
    w.add_argument("--host", default="127.0.0.1",
                   help="기본 127.0.0.1(이 컴퓨터만). 0.0.0.0 이면 같은 네트워크에 공유(GitHub 주소만 검사)")
    w.add_argument("--no-browser", action="store_true", help="브라우저를 자동으로 열지 않음")
    llm_opts(w)
    w.set_defaults(func=cmd_web)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
