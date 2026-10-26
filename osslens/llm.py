"""Ollama HTTP API로 취약점 한국어 해설 생성.

소스 코드는 절대 보내지 않는다. 보내는 정보는 패키지 이름·버전·취약점 ID·심각도·
수정 버전·공개 취약점 설명뿐이다.
"""

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_HOST = "http://localhost:11434"
DEFAULT_MODEL = "qwen3:8b"
PING_TIMEOUT = 3
CHAT_TIMEOUT = 180
MAX_DESCRIPTION = 1500

SYSTEM_PROMPT = (
    "당신은 소프트웨어 보안 전문가입니다. 개발 경험이 적은 학생도 이해할 수 있도록 "
    "쉬운 한국어로 설명하세요. 주어진 정보에 없는 사실은 지어내지 말고, 모르면 모른다고 하세요."
)

USER_TEMPLATE = """다음 오픈소스 취약점을 설명해 주세요.

- 패키지: {package} {version} ({package_type})
- 취약점 ID: {ids}
- 심각도: {severity}
- 수정된 버전: {fixed}
- 원문 설명: {description}

아래 세 항목 제목을 그대로 쓰고, 각 항목은 2~3문장으로 답하세요.
위험도:
영향:
조치 방법:"""


class LLMUnavailable(Exception):
    pass


def resolve_host(cli_host=None):
    """--llm-host > OLLAMA_HOST > 기본값 순. 'host:port'처럼 스킴이 없으면 http://를 붙인다."""
    host = (cli_host or os.environ.get("OLLAMA_HOST") or DEFAULT_HOST).strip()
    if "://" not in host:
        host = "http://" + host
    parsed = urllib.parse.urlsplit(host)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"올바르지 않은 LLM 주소입니다: {host}")
    hostname = parsed.hostname
    if hostname in ("0.0.0.0", "::"):
        # 서버 바인드 주소로 설정된 OLLAMA_HOST를 클라이언트에서 쓸 때
        hostname = "localhost"
    if ":" in hostname:
        hostname = f"[{hostname}]"
    port = parsed.port or 11434
    return f"{parsed.scheme}://{hostname}:{port}{parsed.path.rstrip('/')}"


def build_prompt(vuln):
    description = (vuln.description or "(설명 없음)").replace("\r", " ")
    if len(description) > MAX_DESCRIPTION:
        description = description[:MAX_DESCRIPTION] + "..."
    return USER_TEMPLATE.format(
        package=vuln.package,
        version=vuln.version,
        package_type=vuln.package_type or "?",
        ids=", ".join([vuln.id] + list(vuln.aliases)),
        severity=vuln.severity,
        fixed=", ".join(vuln.fixed_in) if vuln.fixed_in else "아직 없음",
        description=description,
    )


def _strip_thinking(text):
    return re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()


class OllamaClient:
    def __init__(self, host, model=DEFAULT_MODEL):
        self.host = host
        self.model = model

    def ping(self):
        try:
            with urllib.request.urlopen(self.host + "/api/tags", timeout=PING_TIMEOUT) as resp:
                resp.read()
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise LLMUnavailable(f"Ollama 서버({self.host})에 연결할 수 없습니다: {exc}") from exc

    def chat(self, prompt):
        body = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "think": False,
            "options": {"temperature": 0.2},
        }).encode("utf-8")
        req = urllib.request.Request(
            self.host + "/api/chat", data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=CHAT_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:200]
            raise LLMUnavailable(f"Ollama 오류 {exc.code}: {detail}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise LLMUnavailable(f"Ollama 호출 실패: {exc}") from exc
        content = ((data.get("message") or {}).get("content") or "").strip()
        content = _strip_thinking(content)
        if not content:
            raise LLMUnavailable("Ollama가 빈 응답을 돌려주었습니다.")
        return content


def explain_top(vulns, client, top, log=lambda msg: None):
    """심각도 상위 top개 취약점 해설. 반환: ({취약점 키: 해설}, 경고 메시지 또는 None)."""
    targets = vulns[:max(top, 0)]
    if not targets:
        return {}, None
    try:
        client.ping()
    except LLMUnavailable as exc:
        return {}, f"{exc} — LLM 해설 없이 리포트를 만듭니다."
    explanations = {}
    for i, vuln in enumerate(targets, 1):
        log(f"  LLM 해설 {i}/{len(targets)}: {vuln.id} ({vuln.package} {vuln.version})")
        try:
            explanations[vuln_key(vuln)] = client.chat(build_prompt(vuln))
        except LLMUnavailable as exc:
            return explanations, f"{exc} — 나머지 항목은 해설 없이 리포트를 만듭니다."
    return explanations, None


def vuln_key(vuln):
    return (vuln.id, vuln.package, vuln.version)
