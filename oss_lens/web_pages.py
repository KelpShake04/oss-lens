"""웹 UI 페이지 (외부 리소스 없이 CSS·JS 내장). 색상·글꼴은 리포트와 맞춘다."""

from __future__ import annotations

from html import escape

BASE_CSS = """
:root{--bg:#f7f7f8;--fg:#1c1c1e;--muted:#6b6b73;--card:#fff;--line:#e4e4e7;--code:#f1f1f3;
--accent:#2e6bd6;--accent-fg:#fff;--crit:#b42318;--high:#dc6803;--ok:#1f8a4c}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--fg:#ececee;--muted:#9a9aa3;--card:#1d1d20;
--line:#2e2e33;--code:#26262b;--accent:#6aa2ff;--accent-fg:#0b1220;--crit:#f97066;--high:#fd853a;--ok:#47cd89}}
*{box-sizing:border-box}
[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 -apple-system,BlinkMacSystemFont,
"Apple SD Gothic Neo","Malgun Gothic","Noto Sans KR",system-ui,sans-serif}
a{color:var(--accent)}
code{background:var(--code);padding:1px 6px;border-radius:4px;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
"""

INDEX_HTML = """<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>oss-lens</title>
<style>""" + BASE_CSS + """
main{max-width:980px;margin:0 auto;padding:40px 16px 56px}
.brand{font-weight:800;letter-spacing:-.02em;font-size:18px;display:flex;align-items:center;gap:8px}
.brand i{display:inline-block;width:22px;height:22px;border-radius:50%;border:4px solid var(--accent)}
h1{font-size:30px;line-height:1.3;margin:18px 0 8px;letter-spacing:-.02em}
.lead{color:var(--muted);margin:0 0 16px;max-width:680px}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border:1px solid var(--line);
border-radius:999px;font-size:13px;background:var(--card)}
.chip::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--muted)}
.chip.ok::before{background:var(--ok)}.chip.bad::before{background:var(--crit)}.chip.warn::before{background:var(--high)}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px;margin-top:24px}
label.big{display:block;font-weight:700;margin-bottom:8px}
.row{display:flex;gap:8px}
.row input{flex:1;min-width:0;font:inherit;font-size:16px;padding:12px 14px;border:1px solid var(--line);
border-radius:10px;background:var(--bg);color:var(--fg)}
.row input:focus{outline:2px solid var(--accent);outline-offset:1px}
button.primary{font:inherit;font-weight:700;font-size:16px;padding:12px 20px;border:0;border-radius:10px;
background:var(--accent);color:var(--accent-fg);cursor:pointer;white-space:nowrap}
button.primary:disabled{opacity:.5;cursor:default}
.samples{margin-top:12px;display:flex;flex-wrap:wrap;gap:8px;align-items:center;color:var(--muted);font-size:14px}
.samples button{font:inherit;font-size:14px;padding:5px 12px;border:1px solid var(--line);border-radius:999px;
background:var(--bg);color:var(--fg);cursor:pointer}
.samples button small{color:var(--muted);margin-left:4px}
.opts{margin-top:14px;display:flex;flex-wrap:wrap;gap:8px 20px;font-size:14px;color:var(--muted)}
.opts label{display:flex;align-items:center;gap:6px}
.opts select{font:inherit;padding:2px 6px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
.hint{font-size:13px;color:var(--muted);margin:10px 0 0}
.err{color:var(--crit);font-weight:600;margin:10px 0 0}
.job h2{margin:0;font-size:17px;word-break:break-all}
.progress{height:10px;background:var(--line);border-radius:999px;overflow:hidden;margin:14px 0}
.progress span{display:block;height:100%;width:0;background:var(--accent);transition:width .4s}
.steps{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;padding:0;margin:0;list-style:none;font-size:13px}
.steps li{padding:8px 10px;border:1px solid var(--line);border-radius:8px;color:var(--muted)}
.steps li.active{border-color:var(--accent);color:var(--fg);font-weight:600}
.steps li.done{color:var(--ok)}.steps li.done::before{content:"✓ "}
pre.log{background:var(--code);border-radius:8px;padding:10px 12px;font-size:12px;max-height:180px;overflow:auto;
white-space:pre-wrap;word-break:break-all;margin:14px 0 0}
.job .actions{margin-top:14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
a.btn{display:inline-block;font-weight:700;padding:10px 18px;border-radius:10px;background:var(--accent);
color:var(--accent-fg);text-decoration:none}
h2.sec{font-size:19px;margin:40px 0 12px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
a.rcard{display:block;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;
color:inherit;text-decoration:none;transition:border-color .15s,transform .15s}
a.rcard:hover{border-color:var(--accent);transform:translateY(-1px)}
.rname{font-weight:800;font-size:17px;word-break:break-all}
.rtarget{color:var(--muted);font-size:12px;margin-bottom:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:4px;text-align:center}
.metrics b{display:block;font-size:20px;line-height:1.2}.metrics span{font-size:12px;color:var(--muted)}
.metrics .bad b{color:var(--crit)}
.rfoot{margin-top:10px;font-size:12px;color:var(--muted);display:flex;flex-wrap:wrap;gap:4px 10px}
.rfoot .warn{color:var(--high);font-weight:600}
.empty{color:var(--muted);background:var(--card);border:1px dashed var(--line);border-radius:12px;padding:24px;text-align:center}
footer{margin-top:48px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:13px}
@media (max-width:600px){h1{font-size:24px}.row{flex-direction:column}.steps{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<main>
  <div class="brand"><i></i>oss-lens</div>
  <h1>내 프로젝트가 쓰는 오픈소스,<br>안전한가요?</h1>
  <p class="lead">폴더나 GitHub 주소를 넣으면 오픈소스 의존성의 취약점(CVE)과 라이선스 위험을 찾아
  한국어로 위험도·영향·고치는 법을 알려 드립니다. 소스코드는 이 컴퓨터 밖으로 나가지 않습니다.</p>
  <div class="chips" id="status"><span class="chip">도구 확인 중…</span></div>

  <section class="card">
    <form id="scan">
      <label class="big" for="target">검사할 폴더 경로 또는 GitHub 주소</label>
      <div class="row">
        <input id="target" autocomplete="off" spellcheck="false"
               placeholder="/Users/me/my-project 또는 https://github.com/owner/repo">
        <button class="primary" id="go" type="submit">검사 시작</button>
      </div>
      <div class="samples" id="samples"></div>
      <div class="opts">
        <label>AI 해설 <select id="top"><option>3</option><option selected>5</option><option>8</option><option>10</option></select>개</label>
        <label><input type="checkbox" id="use_llm" checked> AI 해설 사용</label>
        <label><input type="checkbox" id="remote_licenses"> 라이선스 온라인 조회 (패키지 이름만 전송)</label>
      </div>
      <p class="hint" id="hint"></p>
      <p class="err" id="err" hidden></p>
    </form>
  </section>

  <section class="card job" id="job" hidden>
    <h2 id="job-target"></h2>
    <div class="progress"><span id="job-bar"></span></div>
    <ol class="steps" id="job-steps">
      <li>SBOM 생성 (syft)</li><li>취약점 검사 (grype)</li><li>라이선스 점검</li><li>AI 해설</li>
    </ol>
    <pre class="log" id="job-log"></pre>
    <div class="actions"><a class="btn" id="job-open" hidden>리포트 열기 →</a><span id="job-msg"></span></div>
  </section>

  <h2 class="sec">리포트</h2>
  <div class="grid" id="reports"></div>

  <footer>사용 오픈소스: syft (SBOM 생성) · grype (취약점 매칭) · Ollama (로컬 AI 해설) — 모두 Apache-2.0/MIT ·
  <span id="ver"></span></footer>
</main>
<script>
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
async function api(path, opts) {
  const r = await fetch(path, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

async function loadStatus() {
  const s = await api("/api/status");
  const chip = (ok, text, cls) => `<span class="chip ${cls || (ok ? "ok" : "bad")}">${esc(text)}</span>`;
  $("#status").innerHTML =
    chip(s.syft, s.syft ? "syft 준비됨" : "syft 없음") +
    chip(s.grype, s.grype ? "grype 준비됨" : "grype 없음") +
    chip(s.llm.ok, s.llm.ok ? `AI 해설 ${s.llm.model}` : "AI 없음 · 규칙 기반 설명", s.llm.ok ? "ok" : "warn") +
    (s.allow_local ? "" : chip(true, "공유 모드 · GitHub 주소만", "warn"));
  $("#samples").innerHTML = "예시:" + s.samples.map(x =>
    `<button type="button" data-target="${esc(x.target)}">${esc(x.label)}<small>${esc(x.note)}</small></button>`).join("");
  $("#samples").querySelectorAll("button").forEach(b => b.onclick = () => { $("#target").value = b.dataset.target; $("#target").focus(); });
  if (!s.allow_local) $("#target").placeholder = "https://github.com/owner/repo";
  const hints = [];
  if (!s.syft || !s.grype) hints.push("syft·grype 가 필요합니다: brew install syft grype");
  if (!s.llm.ok) { $("#use_llm").checked = false; hints.push(s.llm.reason + " (없어도 규칙 기반 한국어 설명으로 리포트를 만듭니다)"); }
  $("#hint").textContent = hints.join(" · ");
  $("#ver").textContent = "oss-lens " + s.version;
}

async function loadReports() {
  const list = await api("/api/reports");
  $("#reports").innerHTML = list.length ? list.map(r => `
    <a class="rcard" href="/view/${encodeURIComponent(r.name)}">
      <div class="rname">${esc(r.name)}</div>
      <div class="rtarget" title="${esc(r.target)}">${esc(r.target)}</div>
      <div class="metrics">
        <div><b>${r.packages}</b><span>패키지</span></div>
        <div><b>${r.vulns}</b><span>취약점</span></div>
        <div class="${r.crit_high ? "bad" : ""}" title="치명·높음 등급 취약점"><b>${r.crit_high}</b><span>치명·높음</span></div>
        <div class="${r.license_high ? "bad" : ""}" title="위험도 높음인 라이선스"><b>${r.license_high}</b><span>라이선스</span></div>
      </div>
      <div class="rfoot"><span>${esc(r.generated_at)}</span><span>${r.llm ? "AI 해설 " + esc(r.llm) : "규칙 기반 설명"}</span>
        ${r.notes ? `<span class="warn">확인 필요 ${r.notes}건</span>` : ""}</div>
    </a>`).join("") : `<div class="empty">아직 리포트가 없습니다. 위에서 검사를 시작하거나 예시를 눌러 보세요.</div>`;
}

const STEP_END = [0.25, 0.45, 0.5, 1.0];
let polling = null;
function showJob(j) {
  $("#job").hidden = false;
  $("#job-target").textContent = j.target;
  $("#job-bar").style.width = Math.round(j.progress * 100) + "%";
  $("#job-steps").querySelectorAll("li").forEach((li, i) => {
    const done = j.status === "done" || j.progress >= STEP_END[i];
    const active = !done && j.status === "running" && (i === 0 || j.progress >= STEP_END[i - 1]);
    li.className = done ? "done" : active ? "active" : "";
  });
  const log = $("#job-log");
  log.textContent = j.log.join("\\n") || (j.status === "queued" ? "앞선 검사가 끝나기를 기다리는 중…" : "");
  log.scrollTop = log.scrollHeight;
  const busy = j.status === "queued" || j.status === "running";
  $("#go").disabled = busy;
  $("#go").textContent = busy ? "검사 중…" : "검사 시작";
  $("#job-open").hidden = j.status !== "done";
  $("#job-msg").textContent = j.status === "error" ? "실패: " + j.error : (j.summary || "");
  $("#job-msg").className = j.status === "error" ? "err" : "";
  if (j.status === "done") {
    const href = "/view/" + encodeURIComponent(j.report);
    $("#job-open").href = href;
    loadReports();
    setTimeout(() => { location.href = href; }, 1200);
  }
}
function poll(id) {
  clearInterval(polling);
  polling = setInterval(async () => {
    try {
      const j = await api("/api/jobs/" + id);
      showJob(j);
      if (j.status === "done" || j.status === "error") clearInterval(polling);
    } catch (e) { clearInterval(polling); }
  }, 1000);
}

$("#scan").onsubmit = async ev => {
  ev.preventDefault();
  $("#err").hidden = true;
  try {
    const j = await api("/api/scan", {method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({target: $("#target").value, top: +$("#top").value,
        use_llm: $("#use_llm").checked, remote_licenses: $("#remote_licenses").checked})});
    showJob(j); poll(j.id);
    $("#job").scrollIntoView({behavior: "smooth", block: "center"});
  } catch (e) { $("#err").textContent = e.message; $("#err").hidden = false; }
};

loadStatus().catch(e => { $("#status").innerHTML = `<span class="chip bad">${esc(e.message)}</span>`; });
loadReports();
api("/api/jobs").then(jobs => { if (jobs.length) { showJob(jobs[jobs.length - 1]); poll(jobs[jobs.length - 1].id); } });
</script>
</body>
</html>
"""


def view_html(info: dict) -> str:
    """리포트 보기: 위에 도구 막대, 아래에 리포트(iframe)."""
    name = escape(info["name"], quote=True)
    target = escape(info.get("target", ""), quote=True)
    src = f"/reports/{name}/report.html"
    return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{name} · oss-lens</title>
<style>{BASE_CSS}
html,body{{height:100%}}
body{{display:flex;flex-direction:column}}
nav{{display:flex;align-items:center;gap:14px;padding:10px 16px;background:var(--card);
border-bottom:1px solid var(--line);font-size:14px;flex-wrap:wrap}}
nav a{{text-decoration:none;font-weight:600;white-space:nowrap}}
nav .t{{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
nav .t span{{color:var(--muted);margin-left:8px;font-size:13px}}
iframe{{flex:1;width:100%;border:0;background:var(--bg)}}
</style>
</head>
<body>
<nav>
  <a href="/">← 리포트 목록</a>
  <div class="t"><b>{name}</b><span>{target}</span></div>
  <a href="{src}" target="_blank" rel="noopener">새 탭에서 열기</a>
  <a href="{src}" download="oss-lens-{name}.html">HTML 저장</a>
</nav>
<iframe src="{src}" title="{name} 리포트"></iframe>
</body>
</html>
"""
