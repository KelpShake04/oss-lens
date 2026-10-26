"""HTML / JSON 리포트 생성. 외부 리소스 없이 파일 하나로 열리도록 CSS·JS 를 내장한다."""

from __future__ import annotations

import dataclasses
import json
import re
from html import escape
from pathlib import Path

from . import __version__
from .licenses import CATEGORIES, category_counts
from .models import SEVERITY_KO, SEVERITY_ORDER, Report, Vulnerability
from .risk import fix_command, min_fix_version, upgrade_plan, vuln_key

SEVERITY_CSS = {
    "Critical": "crit",
    "High": "high",
    "Medium": "med",
    "Low": "low",
    "Negligible": "neg",
    "Unknown": "neg",
}
LEVEL_CSS = {"high": "high", "medium": "med", "low": "low", "info": "neg"}
VULN_TABLE_OPEN_MAX = 20  # 이보다 많으면 전체 취약점 표를 접어서 보여준다


def _e(s) -> str:
    return escape(str(s), quote=True)


def _steps(text: str) -> str:
    """'1) ... 2) ...' 형태의 조치 단계를 줄바꿈해서 보여준다."""
    return re.sub(r"\s+(?=[2-9]\)\s)", "<br>", _e(text))


def _sev_badge(sev: str) -> str:
    return f'<span class="badge {SEVERITY_CSS.get(sev, "neg")}">{_e(SEVERITY_KO.get(sev, sev))}</span>'


def _link(url: str, text: str) -> str:
    if not url.startswith(("https://", "http://")):
        return _e(text)
    return f'<a href="{_e(url)}" target="_blank" rel="noopener noreferrer">{_e(text)}</a>'


def _vuln_link(v: Vulnerability) -> str:
    if v.id.startswith("CVE-"):
        return _link(f"https://nvd.nist.gov/vuln/detail/{v.id}", v.id)
    if v.id.startswith("GHSA-"):
        return _link(f"https://github.com/advisories/{v.id}", v.id)
    return _link(v.urls[0], v.id) if v.urls else _e(v.id)


def _severity_counts(vulns: list[Vulnerability]) -> dict[str, int]:
    counts = {s: 0 for s in reversed(SEVERITY_ORDER)}
    for v in vulns:
        counts[v.severity if v.severity in counts else "Unknown"] += 1
    return counts


def _summary_cards(r: Report) -> str:
    sev = _severity_counts(r.vulnerabilities)
    vuln_pkgs = len({(v.package, v.version) for v in r.vulnerabilities})
    fixable = sum(1 for v in r.vulnerabilities if v.fix_versions)
    lic_high = sum(1 for f in r.license_findings if f.level == "high")
    lic_med = sum(1 for f in r.license_findings if f.level == "medium")
    total = len(r.vulnerabilities)
    fix_pct = f"{fixable / total:.0%}" if total else "-"
    sev_line = " · ".join(
        f'<span class="dot {SEVERITY_CSS[s]}"></span>{_e(SEVERITY_KO[s])} {n}'
        for s, n in sev.items() if n and s not in ("Negligible", "Unknown")
    )
    return f"""
<section class="cards">
  <div class="card"><div class="num">{len(r.packages)}</div><div class="lbl">오픈소스 패키지</div></div>
  <div class="card {'alert' if sev['Critical'] or sev['High'] else ''}">
    <div class="num">{total}</div><div class="lbl">취약점 ({vuln_pkgs}개 패키지)</div>
    <div class="sub">{sev_line or '발견 없음'}</div></div>
  <div class="card"><div class="num">{fix_pct}</div><div class="lbl">패치 버전 있음</div>
    <div class="sub">{fixable}건은 업그레이드로 해결</div></div>
  <div class="card {'alert' if lic_high else ''}"><div class="num">{lic_high + lic_med}</div>
    <div class="lbl">라이선스 주의</div><div class="sub">높음 {lic_high} · 중간 {lic_med}</div></div>
</section>"""


def _top_section(r: Report) -> str:
    by_key = {vuln_key(v): v for v in r.vulnerabilities}
    items = []
    for i, key in enumerate(r.top_keys, 1):
        v = by_key[key]
        ex = r.explanations.get(key)
        cmd = fix_command(v)
        meta = [_sev_badge(v.severity)]
        if v.cvss_score is not None:
            meta.append(f'<span class="chip">CVSS {v.cvss_score:.1f}</span>')
        if v.epss is not None:
            meta.append(f'<span class="chip">악용 확률 {v.epss:.1%}</span>')
        if v.known_exploited:
            meta.append('<span class="chip kev">실제 공격 확인(KEV)</span>')
        src = ""
        if ex:
            src = ('<span class="src ai">AI 해설</span>' if ex.source == "llm"
                   else '<span class="src">규칙 기반 설명</span>')
        body = ""
        if ex:
            body = f"""
    <p class="summary">{_e(ex.summary)}</p>
    <dl>
      <dt>영향</dt><dd>{_e(ex.impact)}</dd>
      <dt>조치</dt><dd>{_steps(ex.action)}</dd>
    </dl>"""
        fix = ""
        if cmd:
            fix = f"""
    <div class="fix"><code>{_e(cmd)}</code><button type="button" class="copy" data-copy="{_e(cmd)}">복사</button></div>"""
        else:
            fix = '<div class="fix none">아직 패치 버전이 없습니다</div>'
        items.append(f"""
  <article class="top">
    <header>
      <span class="rank">{i}</span>
      <h3>{_e(v.package)} <small>{_e(v.version)}</small></h3>
      <span class="vid">{_vuln_link(v)}</span>
      {src}
    </header>
    <div class="meta">{' '.join(meta)} <span class="loc">{_e(', '.join(v.locations))}</span></div>{body}{fix}
  </article>""")
    if not items:
        return '<section><h2>먼저 고칠 취약점</h2><p class="empty">발견된 취약점이 없습니다.</p></section>'
    return f"""
<section>
  <h2>먼저 고칠 취약점 <small>위험 점수 상위 {len(items)}개</small></h2>
  {''.join(items)}
</section>"""


def _upgrade_section(r: Report) -> str:
    plans = upgrade_plan(r.vulnerabilities)
    if not plans:
        return ""
    rows = []
    for p in plans:
        cmd = (f'<code>{_e(p["command"])}</code> <button type="button" class="copy" data-copy="{_e(p["command"])}">복사</button>'
               if p["command"] else '<span class="empty">패치 없음</span>')
        left = f'<span class="warn">{p["unfixed"]}건 남음</span>' if p["unfixed"] else "-"
        rows.append(
            f"<tr><td>{_sev_badge(p['max_severity'])}</td><td>{_e(p['package'])}</td><td>{_e(p['version'])}</td>"
            f"<td><b>{_e(p['target'] or '-')}</b></td><td class='n'>{p['fixed']}건</td><td>{left}</td>"
            f"<td class='cmd'>{cmd}</td></tr>"
        )
    return f"""
<section>
  <h2>업그레이드 계획 <small>패키지별로 한 번에 올릴 버전</small></h2>
  <div class="tw"><table>
    <tr><th>최고 심각도</th><th>패키지</th><th>현재</th><th>올릴 버전</th><th>해결</th><th>패치 없음</th><th>명령</th></tr>
    {''.join(rows)}
  </table></div>
  <p class="hint">메이저 버전이 바뀌면 코드 수정이 필요할 수 있습니다. 업그레이드 후 테스트를 실행하세요.</p>
</section>"""


def _license_section(r: Report) -> str:
    counts = category_counts(r.packages)
    total = sum(counts.values()) or 1
    bar = "".join(
        f'<span class="seg {cat}" style="width:{n / total * 100:.2f}%" title="{_e(CATEGORIES[cat][0])} {n}"></span>'
        for cat, n in counts.items() if n
    )
    legend = " ".join(
        f'<span class="lg"><span class="dot {cat}"></span>{_e(CATEGORIES[cat][0])} {n}</span>'
        for cat, n in counts.items() if n
    )

    def rows(findings):
        return "".join(
            f"<tr><td>{_e(f.package)}</td><td>{_e(f.version)}</td><td><code>{_e(f.license)}</code></td>"
            f'<td><span class="badge {LEVEL_CSS[f.level]}">{_e(f.level_ko)}</span></td>'
            f"<td>{_e(f.reason)}</td><td>{_e(f.action)}</td></tr>"
            for f in findings
        )

    head = "<tr><th>패키지</th><th>버전</th><th>라이선스</th><th>위험</th><th>이유</th><th>조치</th></tr>"
    main = [f for f in r.license_findings if f.level != "info"]
    info = [f for f in r.license_findings if f.level == "info"]
    table = (f'<div class="tw"><table>{head}{rows(main)}</table></div>' if main
             else '<p class="empty">주의가 필요한 라이선스가 없습니다.</p>')
    info_block = ""
    if info:
        info_block = f"""
  <details><summary>라이선스 정보를 찾지 못한 패키지 {len(info)}개</summary>
  <p class="hint">requirements.txt 처럼 라이선스가 적혀 있지 않은 파일에서 찾은 패키지입니다.
  <code>--remote-licenses</code> 옵션을 쓰면 패키지 이름으로 공개 저장소(PyPI·npm)에서 라이선스를 조회합니다.</p>
  <div class="tw"><table>{head}{rows(info)}</table></div></details>"""
    return f"""
<section>
  <h2>라이선스 점검 <small>프로젝트 라이선스: {_e(r.project_license or '미확인 (비공개/상용 배포 가정)')}</small></h2>
  <div class="bar">{bar}</div>
  <div class="legend">{legend}</div>
  {table}{info_block}
</section>"""


def _vuln_table(r: Report) -> str:
    rows = []
    for v in r.vulnerabilities:
        fix = _e(min_fix_version(v) or "-")
        rows.append(
            f'<tr data-sev="{_e(v.severity)}" data-text="{_e((v.id + " " + v.package + " " + " ".join(v.aliases)).lower())}">'
            f"<td>{_sev_badge(v.severity)}</td><td>{_vuln_link(v)}</td>"
            f"<td>{_e(v.package)}</td><td>{_e(v.version)}</td><td>{fix}</td>"
            f"<td class='n'>{'' if v.cvss_score is None else f'{v.cvss_score:.1f}'}</td>"
            f"<td class='n'>{'' if v.epss is None else f'{v.epss:.1%}'}</td>"
            f"<td class='n'>{v.score:.1f}</td><td class='loc'>{_e(', '.join(v.locations))}</td></tr>"
        )
    if not rows:
        return ""
    sev_opts = "".join(
        f'<option value="{s}">{_e(SEVERITY_KO[s])}</option>' for s in reversed(SEVERITY_ORDER)
    )
    # 건수가 많으면 접어 둬서 요약·먼저 고칠 취약점이 묻히지 않게 한다
    open_attr = " open" if len(rows) <= VULN_TABLE_OPEN_MAX else ""
    return f"""
<section>
  <h2>전체 취약점 <small>{len(rows)}건</small></h2>
  <details{open_attr}><summary>목록 보기 (심각도 필터·검색)</summary>
  <div class="filters">
    <select id="sev"><option value="">모든 심각도</option>{sev_opts}</select>
    <input id="q" type="search" placeholder="패키지·CVE 검색">
  </div>
  <div class="tw"><table id="vt">
    <tr><th>심각도</th><th>취약점</th><th>패키지</th><th>현재</th><th>패치</th><th>CVSS</th><th>EPSS</th><th>점수</th><th>위치</th></tr>
    {''.join(rows)}
  </table></div>
  </details>
</section>"""


def _sbom_section(r: Report) -> str:
    rows = "".join(
        f"<tr><td>{_e(p.name)}</td><td>{_e(p.version)}</td><td>{_e(p.type)}</td>"
        f"<td>{_e(' / '.join(p.licenses) or '-')}</td><td class='loc'>{_e(', '.join(p.locations))}</td></tr>"
        for p in r.packages
    )
    return f"""
<section>
  <details><summary>전체 패키지 목록 (SBOM) {len(r.packages)}개</summary>
  <div class="tw"><table><tr><th>이름</th><th>버전</th><th>종류</th><th>라이선스</th><th>위치</th></tr>{rows}</table></div>
  </details>
</section>"""


def _footer(r: Report) -> str:
    tv = r.tool_versions
    llm = f"Ollama + {_e(r.llm_model)}" if r.llm_model else "사용 안 함 (규칙 기반 설명)"
    notes = "".join(f"<li>{_e(n)}</li>" for n in r.notes)
    return f"""
<footer>
  {f'<ul class="notes">{notes}</ul>' if notes else ''}
  <p>사용 오픈소스: syft {_e(tv.get('syft', '?'))} (Apache-2.0, SBOM 생성) ·
  grype {_e(tv.get('grype', '?'))} (Apache-2.0, 취약점 매칭) · 해설: {llm}</p>
  <p>AI 해설은 참고용입니다. 조치 전 원문 권고(링크)를 확인하세요. 라이선스 판단은 법률 자문이 아닙니다.</p>
  <p>oss-lens {_e(__version__)} · 소스코드는 외부로 전송되지 않습니다.</p>
</footer>"""


CSS = """
:root{--bg:#f7f7f8;--fg:#1c1c1e;--muted:#6b6b73;--card:#fff;--line:#e4e4e7;--code:#f1f1f3;
--crit:#b42318;--high:#dc6803;--med:#b98900;--low:#2e6bd6;--neg:#8a8a93;--ok:#1f8a4c}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--fg:#ececee;--muted:#9a9aa3;--card:#1d1d20;
--line:#2e2e33;--code:#26262b;--crit:#f97066;--high:#fd853a;--med:#eaaa08;--low:#6aa2ff;--neg:#8a8a93;--ok:#47cd89}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 -apple-system,BlinkMacSystemFont,
"Apple SD Gothic Neo","Malgun Gothic","Noto Sans KR",system-ui,sans-serif}
main{max-width:1080px;margin:0 auto;padding:32px 16px 48px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 12px}
h2 small,h3 small{color:var(--muted);font-weight:400;font-size:14px;margin-left:6px}
.target{color:var(--muted);font-size:14px;word-break:break-all}
a{color:var(--low)}
code{background:var(--code);padding:1px 6px;border-radius:4px;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.card.alert{border-color:var(--crit)}
.num{font-size:30px;font-weight:700;line-height:1.2}.lbl{color:var(--muted)}.sub{font-size:13px;margin-top:4px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin:0 4px 0 2px;vertical-align:0}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;color:#fff;white-space:nowrap}
.crit{background:var(--crit)}.high{background:var(--high)}.med{background:var(--med)}.low{background:var(--low)}.neg{background:var(--neg)}
.chip{display:inline-block;padding:1px 8px;border:1px solid var(--line);border-radius:999px;font-size:12px}
.chip.kev{border-color:var(--crit);color:var(--crit);font-weight:600}
.top{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin-bottom:12px}
.top header{display:flex;flex-wrap:wrap;align-items:baseline;gap:8px}
.top h3{margin:0;font-size:17px}.vid{font-size:14px}
.rank{display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:50%;
background:var(--fg);color:var(--bg);font-size:13px;font-weight:700}
.src{margin-left:auto;font-size:12px;color:var(--muted)}.src.ai{color:var(--ok);font-weight:600}
.meta{margin:8px 0;display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.loc{color:var(--muted);font-size:12px;word-break:break-all}
.summary{font-weight:600;margin:10px 0 6px}
dl{display:grid;grid-template-columns:44px 1fr;gap:4px 10px;margin:0}dt{color:var(--muted)}dd{margin:0}
.fix{display:flex;gap:8px;align-items:center;margin-top:10px;flex-wrap:wrap}.fix code{flex:1;min-width:0;overflow-x:auto;white-space:nowrap;padding:6px 10px}
.fix.none{color:var(--muted);font-size:13px}
button.copy{border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:6px;padding:4px 10px;cursor:pointer}
.tw{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{position:sticky;top:0;background:var(--card);font-weight:600;white-space:nowrap}
tr:last-child td{border-bottom:0}td.n{text-align:right;white-space:nowrap}
.bar{display:flex;height:12px;border-radius:6px;overflow:hidden;background:var(--line);margin-bottom:8px}
.seg.permissive,.dot.permissive{background:var(--ok)}.seg.weak-copyleft,.dot.weak-copyleft{background:var(--med)}
.seg.strong-copyleft,.dot.strong-copyleft{background:var(--high)}.seg.network-copyleft,.dot.network-copyleft{background:var(--crit)}
.seg.restricted,.dot.restricted{background:#7a2e9e}.seg.unknown,.dot.unknown{background:var(--neg)}
.legend{font-size:13px;margin-bottom:12px;display:flex;flex-wrap:wrap;gap:12px}
details{margin-top:12px}summary{cursor:pointer;color:var(--muted)}details>.filters{margin-top:10px}.hint{font-size:13px;color:var(--muted)}
.filters{display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap}
.filters select,.filters input{font:inherit;padding:5px 8px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg)}
.filters input{flex:1;min-width:160px}
.empty{color:var(--muted)}.warn{color:var(--high);font-weight:600}
td.cmd{white-space:nowrap}td.cmd code{font-size:12px}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:13px}
footer .notes{color:var(--high)}
@media print{.filters,button.copy{display:none}details{display:block}.top{break-inside:avoid}}
"""

JS = """
document.querySelectorAll('button.copy').forEach(b=>b.addEventListener('click',()=>{
  navigator.clipboard&&navigator.clipboard.writeText(b.dataset.copy).then(()=>{b.textContent='복사됨';
  setTimeout(()=>b.textContent='복사',1200)})}));
const sev=document.getElementById('sev'),q=document.getElementById('q');
function filt(){const s=sev.value,t=q.value.trim().toLowerCase();
  document.querySelectorAll('#vt tr[data-sev]').forEach(r=>{
    r.style.display=(!s||r.dataset.sev===s)&&(!t||r.dataset.text.includes(t))?'':'none'})}
if(sev){sev.addEventListener('change',filt);q.addEventListener('input',filt)}
"""


def render_html(r: Report) -> str:
    return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>oss-lens 리포트 · {_e(Path(r.target).name or r.target)}</title>
<style>{CSS}</style>
</head>
<body>
<main>
  <h1>오픈소스 의존성 진단 리포트</h1>
  <div class="target">{_e(r.target)} · {_e(r.generated_at)}</div>
  {_summary_cards(r)}
  {_top_section(r)}
  {_upgrade_section(r)}
  {_license_section(r)}
  {_vuln_table(r)}
  {_sbom_section(r)}
  {_footer(r)}
</main>
<script>{JS}</script>
</body>
</html>
"""


def render_json(r: Report) -> str:
    return json.dumps(dataclasses.asdict(r), ensure_ascii=False, indent=1)
