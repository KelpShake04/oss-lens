import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from oss_lens import pipeline, scanner
from oss_lens.web import App, is_loopback, make_server

ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
DEMO = ROOT / "examples" / "vulnerable-demo"


class FixtureApp(App):
    """grype DB·Ollama·네트워크 없이 돌도록 저장된 결과로 검사한다."""

    def run_scan(self, opts, progress):
        if pipeline.is_github_url(opts.target):
            raise scanner.ScanError("테스트에서는 저장소를 복제하지 않습니다")
        opts.sbom = str(FIXTURES / "syft-demo.json")
        opts.grype_json = str(FIXTURES / "grype-demo.json")
        opts.use_llm = False
        return pipeline.run(opts, progress)


def _start(tmp_path, allow_local=True):
    app = FixtureApp(tmp_path / "out", allow_local=allow_local, ollama_host="127.0.0.1:1")
    server = make_server(app, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


@pytest.fixture
def web(tmp_path):
    server, base = _start(tmp_path)
    yield base
    server.shutdown()


@pytest.fixture
def shared_web(tmp_path):
    server, base = _start(tmp_path, allow_local=False)
    yield base
    server.shutdown()


def _req(url, data=None, headers=None, method=None):
    """(상태 코드, 헤더, 본문) 을 돌려준다. 오류 응답도 예외 대신 그대로."""
    body = json.dumps(data).encode() if isinstance(data, dict) else data
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=10) as r:
            return r.status, r.headers, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode()


def _scan(base, target, **extra):
    return _req(f"{base}/api/scan", {"target": target, **extra}, {"Content-Type": "application/json"})


def _wait(base, job_id):
    for _ in range(100):
        job = json.loads(_req(f"{base}/api/jobs/{job_id}")[2])
        if job["status"] in ("done", "error"):
            return job
        time.sleep(0.1)
    raise AssertionError("검사가 끝나지 않았습니다")


def test_index_and_status(web):
    status, headers, body = _req(f"{web}/")
    assert status == 200 and "oss-lens" in body
    assert "frame-ancestors 'self'" in headers["Content-Security-Policy"]
    s = json.loads(_req(f"{web}/api/status")[2])
    assert s["allow_local"] is True
    assert s["llm"]["ok"] is False and "연결할 수 없습니다" in s["llm"]["reason"]
    assert s["samples"][0]["label"] == "데모 프로젝트"
    assert json.loads(_req(f"{web}/api/reports")[2]) == []


def test_scan_flow_and_report_pages(web):
    status, _, body = _scan(web, str(DEMO), top=3)
    assert status == 202
    job = _wait(web, json.loads(body)["id"])
    assert job["status"] == "done", job
    assert job["report"] == "vulnerable-demo"
    assert "패키지 15개 · 취약점 7건" in job["summary"]
    assert any("3/4 라이선스 점검" in line for line in job["log"])

    reports = json.loads(_req(f"{web}/api/reports")[2])
    assert [(r["name"], r["packages"], r["vulns"], r["crit_high"]) for r in reports] == [
        ("vulnerable-demo", 15, 7, 5)]

    status, _, body = _req(f"{web}/view/vulnerable-demo")
    assert status == 200 and 'src="/reports/vulnerable-demo/report.html"' in body
    status, headers, body = _req(f"{web}/reports/vulnerable-demo/report.html")
    assert status == 200 and "오픈소스 의존성 진단 리포트" in body
    assert headers["Content-Type"].startswith("text/html")
    assert _req(f"{web}/reports/vulnerable-demo/report.json")[0] == 200


@pytest.mark.parametrize("path", [
    "/reports/vulnerable-demo/sbom.json",  # 리포트 두 파일만 내보낸다
    "/reports/..%2F..%2Fetc/report.html",
    "/reports/../report.html",
    "/view/nope",
    "/api/jobs/nope",
])
def test_rejects_unknown_paths(web, path):
    assert _req(web + path)[0] == 404


def test_rejects_requests_from_other_sites(web):
    # DNS rebinding: 다른 도메인 이름으로 들어온 요청
    assert _req(f"{web}/", headers={"Host": "evil.example"})[0] == 403
    # 폼 전송(JSON 아님)
    assert _req(f"{web}/api/scan", b"target=/", {"Content-Type": "application/x-www-form-urlencoded"})[0] == 415
    # 다른 사이트의 Origin
    status, _, body = _req(f"{web}/api/scan", {"target": str(DEMO)},
                           {"Content-Type": "application/json", "Origin": "http://evil.example"})
    assert status == 403 and "다른 사이트" in body


def test_rejects_bad_scan_requests(web):
    assert "입력하세요" in _scan(web, "  ")[2]
    status, _, body = _scan(web, "/no/such/dir")
    assert status == 400 and "폴더를 찾을 수 없습니다" in body
    assert _scan(web, str(DEMO), top="많이")[0] == 400
    assert _req(f"{web}/api/scan", b"{broken", {"Content-Type": "application/json"})[0] == 400


def test_failed_scan_is_reported(web):
    job = _wait(web, json.loads(_scan(web, "https://github.com/owner/repo")[2])["id"])
    assert job["status"] == "error"
    assert "복제하지 않습니다" in job["error"]


def test_shared_mode_only_accepts_github(shared_web):
    s = json.loads(_req(f"{shared_web}/api/status")[2])
    assert s["allow_local"] is False
    assert all(x["target"].startswith("https://github.com/") for x in s["samples"])
    status, _, body = _scan(shared_web, str(DEMO))
    assert status == 400 and "공유 모드" in body
    assert _scan(shared_web, "https://github.com/owner/repo")[0] == 202
    # 공유 모드는 다른 기기가 IP 로 접속하므로 Host 를 막지 않는다
    assert _req(f"{shared_web}/", headers={"Host": "192.168.0.10:8765"})[0] == 200


def test_view_only_mode(tmp_path):
    # 맥에서 만든 리포트를 그대로 복사해 둔 상태 (scripts/push-reports.sh 결과)
    assert pipeline.run(pipeline.ScanOptions(
        target=str(DEMO), out=str(tmp_path / "out"), use_llm=False,
        sbom=str(FIXTURES / "syft-demo.json"), grype_json=str(FIXTURES / "grype-demo.json")))
    app = App(tmp_path / "out", allow_local=False, allow_scan=False, ollama_host="127.0.0.1:1")
    server = make_server(app, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        s = json.loads(_req(f"{base}/api/status")[2])
        assert s["allow_scan"] is False and s["samples"] == []
        status, _, body = _scan(base, "https://github.com/owner/repo")
        assert status == 403 and "보기 전용" in body
        assert [r["name"] for r in json.loads(_req(f"{base}/api/reports")[2])] == ["vulnerable-demo"]
        assert _req(f"{base}/reports/vulnerable-demo/report.html")[0] == 200
        assert _req(f"{base}/view/vulnerable-demo")[0] == 200
    finally:
        server.shutdown()


@pytest.mark.parametrize("host,expected", [
    ("127.0.0.1", True), ("localhost", True), ("::1", True), ("127.0.0.2", True),
    ("0.0.0.0", False), ("192.168.0.10", False), ("evil.example", False),
])
def test_is_loopback(host, expected):
    assert is_loopback(host) is expected
