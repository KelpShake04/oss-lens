"""자체 완결형 HTML 리포트 생성.

스캐너·LLM에서 온 모든 문자열은 신뢰할 수 없는 입력이므로 반드시 esc()를 거쳐 넣는다.
"""

import html
from datetime import datetime

from osslens import __version__
from osslens.llm import vuln_key
from osslens.scanner import SEVERITY_ORDER, severity_counts

SEVERITY_KO = {
    "Critical": "긴급", "High": "높음", "Medium": "중간",
    "Low": "낮음", "Negligible": "무시 가능", "Unknown": "알 수 없음",
}
RISK_KO = {"high": "높음", "medium": "중간", "low": "확인 필요"}

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1d2129;--muted:#5b6270;--line:#e3e6eb;
--critical:#b00020;--high:#e05a00;--medium:#c99a00;--low:#2f7d32;--negligible:#607d8b;--unknown:#757575}
@media (prefers-color-scheme:dark){:root{--bg:#15171b;--card:#1f2228;--text:#e8eaed;--muted:#a0a7b4;--line:#333842}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 -apple-system,"Apple SD Gothic Neo","Malgun Gothic","Noto Sans KR",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
h1{margin:0 0 4px;font-size:26px}h2{margin:32px 0 12px;font-size:20px}
.meta{color:var(--muted);font-size:13px;word-break:break-all}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-top:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;border-top:4px solid var(--c,var(--line))}
.card b{display:block;font-size:26px}.card span{color:var(--muted);font-size:13px}
.notice{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--medium);border-radius:8px;padding:10px 14px;margin:12px 0}
.table-wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--bg);white-space:nowrap}
td.desc{min-width:260px;color:var(--muted)}
td.nowrap{white-space:nowrap}
.sev{display:inline-block;padding:1px 8px;border-radius:999px;color:#fff;font-size:12px;white-space:nowrap;background:var(--c)}
.explain{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--c);border-radius:10px;padding:12px 16px;margin-bottom:12px}
.explain h3{margin:0 0 6px;font-size:16px}
.explain pre{white-space:pre-wrap;font:inherit;margin:0}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
details{margin-top:12px}summary{cursor:pointer}
footer{margin-top:40px;color:var(--muted);font-size:13px}
"""


def esc(value):
    return html.escape("" if value is None else str(value), quote=True)


def _sev_var(severity):
    return f"var(--{esc(severity).lower()})"


def _risk_var(risk):
    return {"high": "var(--high)", "medium": "var(--medium)", "low": "var(--unknown)"}.get(risk, "var(--unknown)")


def _badge(severity):
    return f'<span class="sev" style="--c:{_sev_var(severity)}">{esc(SEVERITY_KO.get(severity, severity))}</span>'


def _link(url, text):
    url = (url or "").strip()
    if url.lower().startswith(("https://", "http://")):
        return f'<a href="{esc(url)}" target="_blank" rel="noopener noreferrer">{esc(text)}</a>'
    return esc(text)


def _vuln_rows(vulns):
    if not vulns:
        return '<p>발견된 취약점이 없습니다.</p>'
    rows = []
    for v in vulns:
        ids = _link(v.url, v.id)
        if v.aliases:
            ids += "<br><small>" + esc(", ".join(v.aliases)) + "</small>"
        fixed = f"<code>{esc(', '.join(v.fixed_in))}</code>" if v.fixed_in else "<em>수정 버전 없음</em>"
        desc = v.description if len(v.description) <= 300 else v.description[:300] + "…"
        cvss = f"{v.cvss:.1f}" if v.cvss else "-"
        rows.append(
            f"<tr><td>{_badge(v.severity)}</td><td><code>{ids}</code></td>"
            f"<td>{esc(v.package)}</td><td><code>{esc(v.version)}</code></td>"
            f"<td>{esc(v.package_type)}</td><td>{esc(cvss)}</td><td>{fixed}</td>"
            f'<td class="desc">{esc(desc)}</td></tr>'
        )
    return (
        '<div class="table-wrap"><table><thead><tr><th>심각도</th><th>ID</th><th>패키지</th>'
        "<th>버전</th><th>종류</th><th>CVSS</th><th>수정 버전</th><th>설명</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table></div>"
    )


def _license_rows(findings):
    if not findings:
        return "<p>검토가 필요한 라이선스가 없습니다.</p>"
    rows = []
    for f in findings:
        rows.append(
            f'<tr><td><span class="sev" style="--c:{_risk_var(f.risk)}">{esc(RISK_KO.get(f.risk, f.risk))}</span></td>'
            f"<td>{esc(f.package)}</td><td><code>{esc(f.version)}</code></td>"
            f'<td><code>{esc(f.license)}</code></td><td class="nowrap">{esc(f.category)}</td>'
            f'<td class="desc">{esc(f.note)}</td></tr>'
        )
    return (
        '<div class="table-wrap"><table><thead><tr><th>위험</th><th>패키지</th><th>버전</th>'
        "<th>라이선스</th><th>분류</th><th>설명</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table></div>"
    )


def _explanations(vulns, explanations, llm_status):
    parts = []
    if llm_status:
        parts.append(f'<div class="notice">{esc(llm_status)}</div>')
    for v in vulns:
        text = explanations.get(vuln_key(v))
        if not text:
            continue
        parts.append(
            f'<div class="explain" style="--c:{_sev_var(v.severity)}">'
            f"<h3>{_badge(v.severity)} {esc(v.id)} · {esc(v.package)} {esc(v.version)}</h3>"
            f"<pre>{esc(text)}</pre></div>"
        )
    if not parts:
        parts.append("<p>해설할 취약점이 없습니다.</p>")
    return "".join(parts)


def _package_rows(packages):
    rows = "".join(
        f"<tr><td>{esc(p.name)}</td><td><code>{esc(p.version)}</code></td><td>{esc(p.type)}</td>"
        f"<td><code>{esc(', '.join(p.licenses) or '-')}</code></td>"
        f"<td><code>{esc(', '.join(p.locations))}</code></td></tr>"
        for p in packages
    )
    return (
        f"<details><summary>전체 패키지 {len(packages)}개 보기</summary>"
        '<div class="table-wrap"><table><thead><tr><th>이름</th><th>버전</th><th>종류</th>'
        f"<th>라이선스</th><th>위치</th></tr></thead><tbody>{rows}</tbody></table></div></details>"
    )


def render_report(*, target, packages, vulns, license_findings, explanations,
                  llm_status, model=None, tools="", generated_at=None):
    generated_at = generated_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = severity_counts(vulns)
    cards = "".join(
        f'<div class="card" style="--c:{_sev_var(name)}"><b>{counts[name]}</b>'
        f"<span>{esc(SEVERITY_KO[name])} ({esc(name)})</span></div>"
        for name in SEVERITY_ORDER
    )
    cards += (
        f'<div class="card"><b>{len(packages)}</b><span>패키지</span></div>'
        f'<div class="card" style="--c:var(--high)"><b>{len(license_findings)}</b><span>라이선스 경고</span></div>'
    )
    llm_title = f"LLM 해설 ({esc(model)})" if explanations and model else "LLM 해설"
    return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>oss-lens 진단 리포트</title>
<style>{CSS}</style>
</head>
<body>
<main>
<h1>oss-lens 진단 리포트</h1>
<div class="meta">대상: <code>{esc(target)}</code> · 생성: {esc(generated_at)} · 도구: {esc(tools)}</div>

<h2>요약</h2>
<div class="cards">{cards}</div>

<h2>{llm_title}</h2>
{_explanations(vulns, explanations, llm_status)}

<h2>취약점 ({len(vulns)}건, 심각도 순)</h2>
{_vuln_rows(vulns)}

<h2>라이선스 경고 ({len(license_findings)}건)</h2>
{_license_rows(license_findings)}

<h2>패키지 목록</h2>
{_package_rows(packages)}

<footer>
oss-lens {esc(__version__)} · 취약점 데이터: grype DB · SBOM: syft · 해설: Ollama(로컬/LAN).
소스 코드는 외부로 전송하지 않으며, LLM에는 패키지 이름·버전·취약점 ID·공개 설명만 보냅니다.
라이선스 판단은 참고용이며 법률 자문이 아닙니다.
</footer>
</main>
</body>
</html>
"""
