import json
from pathlib import Path

from oss_lens.cli import main
from oss_lens.models import Explanation, Package, Report, Vulnerability
from oss_lens.report import render_html

ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
DEMO = ROOT / "examples" / "vulnerable-demo"


def _scan(tmp_path, *extra):
    return main([
        "scan", str(DEMO), "-o", str(tmp_path),
        "--sbom", str(FIXTURES / "syft-demo.json"),
        "--grype-json", str(FIXTURES / "grype-demo.json"),
        "--no-llm", *extra,
    ])


def test_scan_writes_reports(tmp_path, capsys):
    assert _scan(tmp_path) == 0
    out = tmp_path / "vulnerable-demo"
    html = (out / "report.html").read_text(encoding="utf-8")
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))

    assert "패키지 15개 · 취약점 7건 (치명·높음 5건) · 라이선스 위험 1건" in capsys.readouterr().out
    assert len(data["packages"]) == 15
    assert len(data["top_keys"]) == 5
    assert all(e["source"] == "rule" for e in data["explanations"].values())
    assert data["llm_model"] is None
    assert data["tool_versions"] == {"syft": "1.55.0", "grype": "0.121.0"}

    assert "CVE-2021-44906" in html
    assert "npm install lodash@^4.17.21" in html  # 업그레이드 계획
    assert "@ckeditor/ckeditor5-build-classic" in html  # GPL 경고
    assert "규칙 기반 설명" in html


def test_scan_top_and_project_license(tmp_path):
    assert _scan(tmp_path, "--top", "2", "--project-license", "GPL-3.0-or-later") == 0
    data = json.loads((tmp_path / "vulnerable-demo" / "report.json").read_text(encoding="utf-8"))
    assert len(data["top_keys"]) == 2
    assert data["project_license"] == "GPL-3.0-or-later"
    gpl = next(f for f in data["license_findings"] if f["package"] == "@ckeditor/ckeditor5-build-classic")
    assert gpl["level"] == "low"


def test_scan_names_output_after_resolved_folder(tmp_path, monkeypatch):
    monkeypatch.chdir(DEMO)
    assert main(["scan", ".", "-o", str(tmp_path), "--no-llm",
                 "--sbom", str(FIXTURES / "syft-demo.json"),
                 "--grype-json", str(FIXTURES / "grype-demo.json")]) == 0
    assert (tmp_path / "vulnerable-demo" / "report.html").is_file()


def test_scan_rejects_missing_folder(tmp_path):
    assert main(["scan", str(tmp_path / "nope"), "-o", str(tmp_path), "--no-llm"]) == 1


def _report_with_vulns(n):
    vulns = [Vulnerability(id=f"CVE-{i}", severity="High", package="p", version="1", pkg_type="npm")
             for i in range(n)]
    return Report(target="t", project_license=None, packages=[], vulnerabilities=vulns,
                  license_findings=[], explanations={}, top_keys=[], generated_at="now")


def test_long_vuln_table_is_collapsed():
    assert "<details open><summary>목록 보기" in render_html(_report_with_vulns(7))
    html = render_html(_report_with_vulns(25))
    assert "<details><summary>목록 보기" in html
    assert html.count('<tr data-sev="High"') == 25


def test_html_escapes_untrusted_text():
    evil = "<script>alert(1)</script>"
    v = Vulnerability(id="CVE-1", severity="High", package=evil, version="1", pkg_type="npm",
                      description=evil, urls=["javascript:alert(1)"])
    r = Report(
        target=evil, project_license=None,
        packages=[Package(evil, "1", "npm", licenses=[evil])],
        vulnerabilities=[v], license_findings=[],
        explanations={"CVE-1|" + evil + "|1": Explanation(evil, evil, evil, "llm")},
        top_keys=["CVE-1|" + evil + "|1"], generated_at="now",
    )
    html = render_html(r)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert 'href="javascript:' not in html
