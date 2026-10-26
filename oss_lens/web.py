"""로컬 웹 UI: `oss-lens web` → 브라우저에서 검사 시작·진행 확인·리포트 보기.

표준 라이브러리 http.server 로 만든다 (설치할 것이 늘지 않게).
기본은 이 컴퓨터(127.0.0.1)에서만 접속한다. --host 0.0.0.0 으로 발표장 등에서 공유하면
다른 사람이 이 컴퓨터의 폴더를 검사하지 못하도록 GitHub 주소만 받는다.
"""

from __future__ import annotations

import ipaddress
import json
import queue
import re
import shutil
import socket
import threading
import uuid
import webbrowser
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from . import __version__, pipeline, scanner
from .llm import DEFAULT_MODEL, OllamaClient
from .web_pages import INDEX_HTML, view_html

DEMO_DIR = Path(__file__).resolve().parent.parent / "examples" / "vulnerable-demo"
SAMPLES = [
    {"label": "OWASP NodeGoat", "target": "https://github.com/OWASP/NodeGoat", "note": "npm · 패키지 380여 개"},
    {"label": "PyGoat", "target": "https://github.com/adeyosemanputra/pygoat", "note": "Python · Django"},
]
REPORT_FILES = {"report.html": "text/html; charset=utf-8", "report.json": "application/json; charset=utf-8"}
MAX_PENDING = 5  # 공유 모드에서 검사 요청이 쌓이지 않게
_NAME = re.compile(r"^[\w.-]+$")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def is_loopback(host: str) -> bool:
    if host in _LOCAL_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass
class Job:
    id: str
    target: str
    status: str = "queued"  # queued / running / done / error
    progress: float = 0.0
    log: list = field(default_factory=list)
    report: Optional[str] = None  # 결과 폴더 이름 (out/<report>)
    summary: Optional[str] = None
    error: Optional[str] = None


class App:
    def __init__(self, out_dir: Path, allow_local: bool, model: str = DEFAULT_MODEL,
                 ollama_host: Optional[str] = None):
        self.out_dir = Path(out_dir)
        self.allow_local = allow_local
        self.model = model
        self.ollama_host = ollama_host
        self.jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._queue: queue.Queue = queue.Queue()
        self._report_cache: dict[Path, tuple[float, dict]] = {}
        self._tools: dict[str, Optional[str]] = {}
        threading.Thread(target=self._worker, daemon=True).start()

    # --- 검사 작업 ---------------------------------------------------------

    def submit(self, data: dict) -> Job:
        """요청을 검사 작업으로 만든다. 받을 수 없는 요청이면 ValueError (메시지는 화면에 보인다)."""
        target = str(data.get("target") or "").strip()
        if not target:
            raise ValueError("검사할 폴더 경로나 GitHub 주소를 입력하세요.")
        if not pipeline.is_github_url(target):
            if not self.allow_local:
                raise ValueError("공유 모드에서는 GitHub 주소(https://github.com/owner/repo)만 검사할 수 있습니다.")
            if not Path(target).expanduser().is_dir():
                raise ValueError(f"폴더를 찾을 수 없습니다: {target}")
        try:
            top = min(max(int(data.get("top", 5)), 1), 20)
        except (TypeError, ValueError):
            raise ValueError("AI 해설 개수는 숫자여야 합니다.") from None
        opts = pipeline.ScanOptions(
            target=target, out=str(self.out_dir), top=top, use_llm=bool(data.get("use_llm", True)),
            model=self.model, ollama_host=self.ollama_host, remote_licenses=bool(data.get("remote_licenses")),
        )
        with self._lock:
            pending = sum(1 for j in self.jobs.values() if j.status in ("queued", "running"))
            if pending >= MAX_PENDING:
                raise ValueError("진행 중인 검사가 너무 많습니다. 잠시 후 다시 시도하세요.")
            job = Job(id=uuid.uuid4().hex[:12], target=target)
            self.jobs[job.id] = job
        self._queue.put((job, opts))
        return job

    def run_scan(self, opts: pipeline.ScanOptions, progress) -> pipeline.ScanResult:
        return pipeline.run(opts, progress)

    def _worker(self) -> None:
        # LLM 이 무거우므로 한 번에 하나씩
        while True:
            job, opts = self._queue.get()

            def progress(msg: str, frac: float, job=job) -> None:
                with self._lock:
                    job.log.append(msg)
                    job.progress = max(job.progress, frac)

            with self._lock:
                job.status = "running"
            try:
                result = self.run_scan(opts, progress)
            except scanner.ScanError as e:
                self._finish(job, error=str(e))
            except Exception as e:  # 웹 UI 가 멈추지 않도록 예기치 못한 오류도 작업 실패로 보여준다
                self._finish(job, error=f"예기치 못한 오류: {e}")
            else:
                self._finish(job, report=result.out_dir.name, summary=result.summary())

    def _finish(self, job: Job, report=None, summary=None, error=None) -> None:
        with self._lock:
            job.status = "error" if error else "done"
            job.progress = 1.0
            job.report, job.summary, job.error = report, summary, error

    def job_dict(self, job_id: str) -> Optional[dict]:
        with self._lock:
            job = self.jobs.get(job_id)
            return asdict(job) if job else None

    def active_jobs(self) -> list[dict]:
        with self._lock:
            return [asdict(j) for j in self.jobs.values() if j.status in ("queued", "running")]

    # --- 리포트 ----------------------------------------------------------

    def report_dir(self, name: str) -> Optional[Path]:
        if not _NAME.match(name or ""):
            return None
        d = (self.out_dir / name).resolve()
        if d.parent != self.out_dir.resolve() or not (d / "report.json").is_file():
            return None
        return d

    def summary_of(self, d: Path) -> Optional[dict]:
        f = d / "report.json"
        mtime = f.stat().st_mtime
        cached = self._report_cache.get(f)
        if cached and cached[0] == mtime:
            return cached[1]
        try:
            r = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        vulns = r.get("vulnerabilities", [])
        info = {
            "name": d.name,
            "target": r.get("target", ""),
            "generated_at": r.get("generated_at", ""),
            "packages": len(r.get("packages", [])),
            "vulns": len(vulns),
            "crit_high": sum(1 for v in vulns if v.get("severity") in ("Critical", "High")),
            "license_high": sum(1 for x in r.get("license_findings", []) if x.get("level") == "high"),
            "llm": r.get("llm_model"),
            "notes": len(r.get("notes", [])),
            "mtime": mtime,
        }
        self._report_cache[f] = (mtime, info)
        return info

    def reports(self) -> list[dict]:
        if not self.out_dir.is_dir():
            return []
        items = [self.summary_of(d) for d in self.out_dir.iterdir() if self.report_dir(d.name)]
        return sorted((i for i in items if i), key=lambda i: -i["mtime"])

    def _tool(self, name: str) -> Optional[str]:
        """syft·grype 버전. 실행 파일을 띄워야 해서 처음 한 번만 확인한다."""
        if name not in self._tools:
            self._tools[name] = (scanner.tool_version(name) or "?") if shutil.which(name) else None
        return self._tools[name]

    def status(self) -> dict:
        client = OllamaClient(host=self.ollama_host, model=self.model)
        reason = client.check()  # Ollama 는 도중에 켜고 끌 수 있으니 매번 확인
        samples = list(SAMPLES)
        if self.allow_local and DEMO_DIR.is_dir():
            samples.insert(0, {"label": "데모 프로젝트", "target": str(DEMO_DIR), "note": "npm + Python · 일부러 취약"})
        return {
            "version": __version__,
            "syft": self._tool("syft"),
            "grype": self._tool("grype"),
            "llm": {"ok": reason is None, "model": self.model, "host": client.host, "reason": reason},
            "allow_local": self.allow_local,
            "samples": samples,
        }


class Handler(BaseHTTPRequestHandler):
    server_version = f"oss-lens/{__version__}"
    app: App  # make_server 가 채운다

    def log_message(self, format, *args):  # 터미널을 조용히
        pass

    # --- 공통 --------------------------------------------------------------

    def _send(self, status: int, body: bytes, content_type: str, cache: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if content_type.startswith("text/html"):
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                             "style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'self'")
        if not cache:
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj) -> None:
        self._send(status, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def _host_ok(self) -> bool:
        """이 컴퓨터 전용 모드에서는 다른 사이트가 DNS 를 바꿔 접근하는 것(DNS rebinding)을 막는다."""
        if not self.app.allow_local:
            return True
        host = urlsplit("//" + (self.headers.get("Host") or "")).hostname or ""
        return is_loopback(host)

    # --- 라우팅 ------------------------------------------------------------

    def do_GET(self):
        if not self._host_ok():
            return self._json(403, {"error": "허용되지 않은 주소입니다."})
        path = urlsplit(self.path).path
        parts = [p for p in path.split("/") if p]
        if path == "/":
            return self._send(200, INDEX_HTML.encode(), "text/html; charset=utf-8")
        if path == "/api/status":
            return self._json(200, self.app.status())
        if path == "/api/reports":
            return self._json(200, self.app.reports())
        if path == "/api/jobs":
            return self._json(200, self.app.active_jobs())
        if len(parts) == 3 and parts[:2] == ["api", "jobs"]:
            job = self.app.job_dict(parts[2])
            return self._json(200, job) if job else self._json(404, {"error": "작업을 찾을 수 없습니다."})
        if len(parts) == 2 and parts[0] == "view" and self.app.report_dir(parts[1]):
            info = self.app.summary_of(self.app.report_dir(parts[1])) or {"name": parts[1], "target": ""}
            return self._send(200, view_html(info).encode(), "text/html; charset=utf-8")
        if len(parts) == 3 and parts[0] == "reports" and parts[2] in REPORT_FILES:
            d = self.app.report_dir(parts[1])
            if d and (d / parts[2]).is_file():
                return self._send(200, (d / parts[2]).read_bytes(), REPORT_FILES[parts[2]])
        if path == "/favicon.ico":
            return self._send(204, b"", "image/x-icon", cache=True)
        return self._json(404, {"error": "페이지를 찾을 수 없습니다."})

    def do_POST(self):
        if not self._host_ok():
            return self._json(403, {"error": "허용되지 않은 주소입니다."})
        if urlsplit(self.path).path != "/api/scan":
            return self._json(404, {"error": "페이지를 찾을 수 없습니다."})
        # JSON 만 받는다: 다른 사이트의 폼 전송은 브라우저가 사전 확인(preflight) 없이 못 보낸다
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            return self._json(415, {"error": "JSON 요청만 받습니다."})
        origin = self.headers.get("Origin")
        if origin and urlsplit(origin).netloc != self.headers.get("Host"):
            return self._json(403, {"error": "다른 사이트에서 보낸 요청은 받지 않습니다."})
        length = int(self.headers.get("Content-Length") or 0)
        if length > 10_000:
            return self._json(413, {"error": "요청이 너무 큽니다."})
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
            job = self.app.submit(data if isinstance(data, dict) else {})
        except ValueError as e:  # json 오류도 ValueError
            return self._json(400, {"error": str(e) if str(e) else "잘못된 요청입니다."})
        return self._json(202, asdict(job))


def lan_ip() -> str:
    """같은 네트워크의 다른 기기가 접속할 이 컴퓨터의 주소 (UDP connect 는 패킷을 보내지 않는다)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return "<이 컴퓨터의 IP>"


def make_server(app: App, host: str, port: int) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"app": app})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def serve(out: str = "out", host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True,
          model: str = DEFAULT_MODEL, ollama_host: Optional[str] = None) -> None:
    app = App(Path(out), allow_local=is_loopback(host), model=model, ollama_host=ollama_host)
    server = make_server(app, host, port)
    port = server.server_address[1]
    url = f"http://localhost:{port}/"
    print(f"oss-lens 웹 UI: {url}  (끄려면 Ctrl+C)")
    if not app.allow_local:
        shared = host if host not in ("0.0.0.0", "::") else lan_ip()
        print(f"다른 기기에서 접속: http://{shared}:{port}/")
        print("! 공유 모드: 같은 네트워크의 누구나 접속할 수 있습니다. 이 컴퓨터의 폴더 검사는 꺼지고 GitHub 주소만 받습니다.")
    if open_browser:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n종료합니다.")
    finally:
        server.server_close()
