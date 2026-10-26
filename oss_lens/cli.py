"""명령행 진입점: oss-lens scan <폴더|GitHub URL>, oss-lens doctor."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

from . import __version__, licenses, parsers, risk, scanner
from .llm import DEFAULT_MODEL, Explainer, OllamaClient
from .models import SEVERITY_KO, Report, Vulnerability
from .report import render_html, render_json

GITHUB_URL = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+(\.git)?/?$")


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _target_name(target: str) -> str:
    name = target.rstrip("/").split("/")[-1].removesuffix(".git")
    return re.sub(r"[^\w.-]", "_", name) or "target"


def cmd_scan(args: argparse.Namespace) -> int:
    clone_root = None
    target = args.target
    try:
        if GITHUB_URL.match(target):
            log(f"GitHub 저장소 복제 중: {target}")
            src = scanner.clone_github(target)
            clone_root = src.parent
        else:
            src = Path(target).expanduser().resolve()
            if not src.is_dir():
                log(f"폴더가 아닙니다: {target}")
                return 1

        out_dir = Path(args.out) / (_target_name(target) if clone_root else _target_name(src.name))
        out_dir.mkdir(parents=True, exist_ok=True)

        # 1) SBOM
        if args.sbom:
            sbom_path = Path(args.sbom)
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
        else:
            sbom_path = out_dir / "sbom.json"
            log("1/4 SBOM 생성 중 (syft)...")
            sbom = scanner.run_syft(src, sbom_path, remote_licenses=args.remote_licenses)
        packages = parsers.parse_syft(sbom, first_party=scanner.first_party_packages(src))

        # 검사에서 조용히 빠지는 의존성을 알린다 ('취약점 0건'이 '안전'으로 읽히지 않게)
        notes = scanner.coverage_gaps(src)
        if not packages:
            notes.insert(0, "오픈소스 패키지를 하나도 찾지 못했습니다. 취약점 0건은 '안전'이 아니라 "
                            "'검사하지 못함'일 수 있습니다. lock 파일(package-lock.json, poetry.lock 등)이나 "
                            "버전이 고정된 requirements.txt 가 있는지 확인하세요.")
        for note in notes:
            log(f"  ! {note}")

        # 2) 취약점
        if args.grype_json:
            vuln_data = json.loads(Path(args.grype_json).read_text(encoding="utf-8"))
        else:
            log(f"2/4 취약점 검사 중 (grype, 패키지 {len(packages)}개)...")
            vuln_data = scanner.run_grype(sbom_path, out_dir / "grype.json")
        vulns = risk.rank(parsers.parse_grype(vuln_data))

        # 3) 라이선스
        log("3/4 라이선스 점검 중...")
        project_license = args.project_license or licenses.detect_project_license(src)
        license_findings = licenses.evaluate(packages, project_license)

        # 4) 해설
        client = None
        if not args.no_llm:
            client = OllamaClient(host=args.ollama_host, model=args.model)
            reason = client.check()
            if reason:
                notes.append(f"{reason} → 규칙 기반 설명으로 대체했습니다.")
                log(f"  ! {reason} (규칙 기반 설명으로 대체)")
                client = None
        explainer = Explainer(client, cache_path=out_dir / "llm-cache.json")
        top = vulns[: args.top]
        explanations = {}
        for i, v in enumerate(top, 1):
            log(f"4/4 해설 생성 중 [{i}/{len(top)}] {v.package} {v.id}")
            explanations[risk.vuln_key(v)] = explainer.explain(v)
        if explainer.errors:
            notes.append(f"LLM 해설 실패 {len(explainer.errors)}건은 규칙 기반 설명으로 대체했습니다.")

        report = Report(
            target=target,
            project_license=project_license,
            packages=packages,
            vulnerabilities=vulns,
            license_findings=license_findings,
            explanations=explanations,
            top_keys=[risk.vuln_key(v) for v in top],
            generated_at=datetime.now().astimezone().strftime("%Y-%m-%d %H:%M"),
            tool_versions={
                "syft": parsers.descriptor_version(sbom) or "?",
                "grype": parsers.descriptor_version(vuln_data) or "?",
            },
            llm_model=client.model if client else None,
            notes=notes,
        )
        html_path = out_dir / "report.html"
        html_path.write_text(render_html(report), encoding="utf-8")
        (out_dir / "report.json").write_text(render_json(report), encoding="utf-8")

        crit_high = sum(1 for v in vulns if v.severity in ("Critical", "High"))
        lic_high = sum(1 for f in license_findings if f.level == "high")
        print(f"패키지 {len(packages)}개 · 취약점 {len(vulns)}건 (치명·높음 {crit_high}건) · 라이선스 위험 {lic_high}건")
        print(f"리포트: {html_path}")
        return 0
    except scanner.ScanError as e:
        log(f"오류: {e}")
        return 1
    finally:
        if clone_root:
            shutil.rmtree(clone_root, ignore_errors=True)


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
    vulns = {risk.vuln_key(Vulnerability(**v)): v for v in r["vulnerabilities"]}
    print(f"{r['target']} · 패키지 {len(r['packages'])}개 · 취약점 {len(r['vulnerabilities'])}건")
    for note in r.get("notes", []):
        print(f"! {note}")
    for i, key in enumerate(r["top_keys"], 1):
        v, e = vulns[key], r["explanations"][key]
        desc = v["description"]
        print(f"\n[{i}] {v['package']} {v['version']} · {v['id']} · {SEVERITY_KO.get(v['severity'], v['severity'])}"
              f" · {'AI' if e['source'] == 'llm' else '규칙'}")
        if args.source:
            print(f"  원문: {desc[:200] + ('…' if len(desc) > 200 else '')}")
        print(f"  요약: {e['summary']}\n  영향: {e['impact']}\n  조치: {e['action']}")
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
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
