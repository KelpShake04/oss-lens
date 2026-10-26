"""검사 한 번의 전체 흐름. CLI(scan)와 웹 UI가 함께 쓴다."""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from . import licenses, parsers, risk, scanner
from .llm import DEFAULT_MODEL, Explainer, OllamaClient
from .models import Report
from .report import render_html, render_json

GITHUB_URL = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+(\.git)?/?$")

# (메시지, 진행률 0~1)
Progress = Callable[[str, float], None]


@dataclass
class ScanOptions:
    target: str  # 폴더 경로 또는 GitHub URL
    out: str = "out"
    top: int = 5
    use_llm: bool = True
    model: str = DEFAULT_MODEL
    ollama_host: Optional[str] = None
    project_license: Optional[str] = None
    remote_licenses: bool = False
    sbom: Optional[str] = None  # 저장해 둔 syft 결과
    grype_json: Optional[str] = None  # 저장해 둔 grype 결과


@dataclass
class ScanResult:
    out_dir: Path
    report: Report

    @property
    def html_path(self) -> Path:
        return self.out_dir / "report.html"

    def summary(self) -> str:
        r = self.report
        crit_high = sum(1 for v in r.vulnerabilities if v.severity in ("Critical", "High"))
        lic_high = sum(1 for f in r.license_findings if f.level == "high")
        return (f"패키지 {len(r.packages)}개 · 취약점 {len(r.vulnerabilities)}건 (치명·높음 {crit_high}건)"
                f" · 라이선스 위험 {lic_high}건")


def target_name(target: str) -> str:
    """결과 폴더 이름. GitHub URL 은 저장소 이름, 폴더는 폴더 이름."""
    name = target.rstrip("/").split("/")[-1].removesuffix(".git")
    return re.sub(r"[^\w.-]", "_", name) or "target"


def is_github_url(target: str) -> bool:
    return bool(GITHUB_URL.match(target.strip()))


def run(opts: ScanOptions, progress: Progress = lambda msg, frac: None) -> ScanResult:
    """검사하고 out/<이름>/ 에 report.html·report.json 을 쓴다. 실패하면 ScanError."""
    target = opts.target.strip()
    clone_root = None
    try:
        if is_github_url(target):
            progress(f"GitHub 저장소 복제 중: {target}", 0.02)
            src = scanner.clone_github(target)
            clone_root = src.parent
            name = target_name(target)
        else:
            src = Path(target).expanduser().resolve()
            if not src.is_dir():
                raise scanner.ScanError(f"폴더가 아닙니다: {target}")
            name = target_name(src.name)

        out_dir = Path(opts.out) / name
        out_dir.mkdir(parents=True, exist_ok=True)

        # 1) SBOM
        if opts.sbom:
            sbom_path = Path(opts.sbom)
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
        else:
            sbom_path = out_dir / "sbom.json"
            progress("1/4 SBOM 생성 중 (syft)...", 0.05)
            sbom = scanner.run_syft(src, sbom_path, remote_licenses=opts.remote_licenses)
        packages = parsers.parse_syft(sbom, first_party=scanner.first_party_packages(src))

        # 검사에서 조용히 빠지는 의존성을 알린다 ('취약점 0건'이 '안전'으로 읽히지 않게)
        notes = scanner.coverage_gaps(src)
        if not packages:
            notes.insert(0, "오픈소스 패키지를 하나도 찾지 못했습니다. 취약점 0건은 '안전'이 아니라 "
                            "'검사하지 못함'일 수 있습니다. lock 파일(package-lock.json, poetry.lock 등)이나 "
                            "버전이 고정된 requirements.txt 가 있는지 확인하세요.")
        for note in notes:
            progress(f"  ! {note}", 0.2)

        # 2) 취약점
        if opts.grype_json:
            vuln_data = json.loads(Path(opts.grype_json).read_text(encoding="utf-8"))
        else:
            progress(f"2/4 취약점 검사 중 (grype, 패키지 {len(packages)}개)...", 0.25)
            vuln_data = scanner.run_grype(sbom_path, out_dir / "grype.json")
        vulns = risk.rank(parsers.parse_grype(vuln_data))

        # 3) 라이선스
        progress("3/4 라이선스 점검 중...", 0.45)
        project_license = opts.project_license or licenses.detect_project_license(src)
        license_findings = licenses.evaluate(packages, project_license)

        # 4) 해설
        client = None
        if opts.use_llm:
            client = OllamaClient(host=opts.ollama_host, model=opts.model)
            reason = client.check()
            if reason:
                notes.append(f"{reason} → 규칙 기반 설명으로 대체했습니다.")
                progress(f"  ! {reason} (규칙 기반 설명으로 대체)", 0.5)
                client = None
        explainer = Explainer(client, cache_path=out_dir / "llm-cache.json")
        top = risk.pick_top(vulns, opts.top)
        explanations = {}
        for i, v in enumerate(top, 1):
            progress(f"4/4 해설 생성 중 [{i}/{len(top)}] {v.package} {v.id}", 0.5 + 0.48 * (i - 1) / len(top))
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
        (out_dir / "report.html").write_text(render_html(report), encoding="utf-8")
        (out_dir / "report.json").write_text(render_json(report), encoding="utf-8")
        result = ScanResult(out_dir=out_dir, report=report)
        progress(result.summary(), 1.0)
        return result
    finally:
        if clone_root:
            shutil.rmtree(clone_root, ignore_errors=True)
