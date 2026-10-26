"""로컬 LLM(Ollama) 한국어 해설. Ollama가 없으면 규칙 기반 설명으로 대체한다."""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from .models import Explanation, Vulnerability
from .risk import fix_command, min_fix_version

DEFAULT_MODEL = "qwen3:8b"
DEFAULT_HOST = "http://127.0.0.1:11434"

SYSTEM_PROMPT = """너는 오픈소스 보안 전문가다. 보안 지식이 많지 않은 학생·스타트업 개발자에게 취약점을 설명한다.

규칙:
1. 한국어 존댓말(~합니다, ~하세요)로만 쓴다. 반말(~다, ~해라)은 쓰지 않는다.
2. 원문 설명과 주어진 정보에 있는 사실만 쓴다. 원문에 없는 피해(코드 실행, 데이터 유출 등)나 버전·수치를 추측해 덧붙이지 않는다.
3. 전문용어는 처음 나올 때 괄호로 짧게 풀어 쓴다.
4. 업그레이드 명령어는 리포트에 따로 표시되므로 쓰지 않는다. 버전 번호만 쓴다.
5. JSON 으로만 답한다.

항목:
- summary: 어떤 기능에서 무엇이 문제인지 한 문장.
- impact: 공격자가 할 수 있는 일과 그 결과를 2문장으로.
- action: 번호를 붙여 2~3단계. 1) 올릴 버전 2) 업그레이드 전 임시 대응(원문에 근거가 있을 때만) 3) 업그레이드 후 확인할 점."""

# 말투·길이를 맞추기 위한 예시 한 쌍 (데모 프로젝트에 없는 취약점)
EXAMPLE_VULN = Vulnerability(
    id="CVE-2021-3807", severity="High", package="ansi-regex", version="5.0.0", pkg_type="npm",
    cvss_score=7.5, fix_versions=["5.0.1"], aliases=["GHSA-93q8-gq69-wqmw"],
    locations=["/package-lock.json"],
    description="ansi-regex is vulnerable to Inefficient Regular Expression Complexity",
)
EXAMPLE_ANSWER = {
    "summary": "ansi-regex 의 정규식이 특정 문자열에서 매우 느리게 동작하는 문제(ReDoS, 정규식 서비스 거부)가 있습니다.",
    "impact": "공격자가 조작한 문자열을 넣으면 정규식 처리에 CPU 를 오래 쓰게 만들 수 있습니다. "
              "그 결과 서버나 CLI 도구의 응답이 느려지거나 멈출 수 있습니다.",
    "action": "1) ansi-regex 를 5.0.1 이상으로 올리세요. 다른 패키지가 끌어온 간접 의존성이면 그 상위 패키지를 업데이트하세요. "
              "2) 업그레이드 후 터미널 출력 관련 기능이 정상인지 테스트하세요.",
}

KEV_SENTENCE = "실제 공격에 악용된 적이 있는 취약점입니다(CISA KEV)."

RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "impact": {"type": "string"},
        "action": {"type": "string"},
    },
    "required": ["summary", "impact", "action"],
}

# 취약점 유형 키워드 -> 한국어 (규칙 기반 설명과 LLM 힌트에 사용)
VULN_TYPES = [
    (r"prototype pollution", "프로토타입 오염(객체 기본 속성을 조작해 동작을 바꾸는 공격)"),
    (r"template injection|ssti", "템플릿 주입(템플릿 엔진을 통한 코드 실행)"),
    (r"remote code execution|arbitrary code|code execution|\brce\b", "임의 코드 실행(공격자가 원하는 코드를 실행)"),
    (r"command injection|os command", "명령어 주입(시스템 명령을 끼워 넣어 실행)"),
    (r"sql injection", "SQL 주입(데이터베이스 쿼리 조작)"),
    (r"cross[- ]site scripting|\bxss\b", "크로스사이트 스크립팅(XSS, 웹페이지에 악성 스크립트 삽입)"),
    (r"server[- ]side request forgery|\bssrf\b", "서버 측 요청 위조(SSRF, 서버가 내부망에 요청하도록 유도)"),
    (r"path traversal|directory traversal", "경로 조작(허용되지 않은 파일 접근)"),
    (r"regular expression denial|inefficient regular expression|redos","정규식 서비스 거부(ReDoS, 느린 정규식으로 서버를 멈춤)"),
    (r"denial of service|\bdos\b|resource exhaustion|uncontrolled resource", "서비스 거부(DoS, 서버를 느리게 하거나 멈춤)"),
    (r"open redirect", "오픈 리다이렉트(악성 사이트로 이동 유도)"),
    (r"crlf injection|header injection", "헤더 주입(HTTP 응답·요청 조작)"),
    (r"deserializ", "안전하지 않은 역직렬화(데이터를 읽다가 코드가 실행됨)"),
    (r"authentication bypass|improper authentication|signature verification", "인증 우회(로그인·서명 검증을 건너뜀)"),
    (r"information (disclosure|exposure)|sensitive information|leak", "정보 노출(민감한 데이터 유출)"),
    (r"buffer overflow|out-of-bounds|heap overflow|use[- ]after[- ]free", "메모리 손상(버퍼 오버플로 등, 크래시·코드 실행 가능)"),
]


def vuln_type_ko(description: str) -> str | None:
    low = (description or "").lower()
    for pattern, ko in VULN_TYPES:
        if re.search(pattern, low):
            return ko
    return None


def normalize_host(host: str | None) -> str:
    """OLLAMA_HOST 형식(예: '0.0.0.0', '192.168.0.5:11434', 'http://pc:11434')을 URL 로."""
    host = (host or "").strip().rstrip("/")
    if not host:
        return DEFAULT_HOST
    if "://" not in host:
        host = "http://" + host
    u = urlsplit(host)
    hostname = u.hostname or "127.0.0.1"
    if hostname == "0.0.0.0":  # 서버 바인드 주소 -> 클라이언트는 로컬로 접속
        hostname = "127.0.0.1"
    if ":" in hostname:  # IPv6
        hostname = f"[{hostname}]"
    port = u.port or (11434 if u.scheme == "http" else 443)
    return f"{u.scheme}://{hostname}:{port}{u.path}"


class OllamaClient:
    def __init__(self, host: str | None = None, model: str = DEFAULT_MODEL, timeout: int = 300):
        self.host = normalize_host(host if host is not None else os.environ.get("OLLAMA_HOST"))
        self.model = model
        self.timeout = timeout
        # Ollama 는 로컬/사내망 서버이므로 시스템 프록시를 거치지 않는다
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _request(self, path: str, payload: dict | None = None, timeout: int | None = None) -> dict:
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            self.host + path, data=data, headers={"Content-Type": "application/json"}
        )
        with self._opener.open(req, timeout=timeout or self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def available_models(self) -> list[str]:
        return [m.get("name", "") for m in self._request("/api/tags", timeout=5).get("models", [])]

    def check(self) -> str | None:
        """사용 불가 사유를 반환. 사용 가능하면 None."""
        try:
            models = self.available_models()
        except (urllib.error.URLError, OSError, ValueError) as e:
            return f"Ollama 서버({self.host})에 연결할 수 없습니다: {e}"
        names = set(models) | {m.removesuffix(":latest") for m in models}
        if self.model not in names:
            return f"모델 '{self.model}' 이(가) 없습니다. 설치: ollama pull {self.model}"
        return None

    def chat(self, messages: list[dict]) -> str:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "format": RESPONSE_SCHEMA,
            "think": False,  # qwen3 생각 모드 끔 (속도)
            "options": {"temperature": 0.2},
        }
        return self._request("/api/chat", payload).get("message", {}).get("content", "")


def build_prompt(v: Vulnerability) -> str:
    lines = [
        f"패키지: {v.package} {v.version} ({v.pkg_type})",
        f"발견 위치: {', '.join(v.locations) or '확인 필요'}",
        f"취약점: {v.id}" + (f" (별칭: {', '.join(v.aliases)})" if v.aliases else ""),
        f"심각도: {v.severity}" + (f" (CVSS {v.cvss_score})" if v.cvss_score is not None else ""),
    ]
    if v.epss is not None:
        lines.append(f"30일 내 악용 확률(EPSS): {v.epss:.1%}")
    if v.known_exploited:
        lines.append(f"실제 공격 사례(CISA KEV): 있음 — impact 첫 문장에 '{KEV_SENTENCE}' 를 쓴다")
    else:
        lines.append("실제 공격 사례(CISA KEV): 없음")
    fix = min_fix_version(v)
    lines.append(f"패치 버전: {fix} 이상" if fix else "패치 버전: 없음 (action 1 에 패치가 없다고 쓴다)")
    vtype = vuln_type_ko(v.description)
    if vtype:
        lines.append(f"취약점 유형(참고): {vtype}")
    lines.append(f"원문 설명(영어): {v.description[:1500] or '없음'}")
    return "\n".join(lines)


def build_messages(v: Vulnerability) -> list[dict]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": build_prompt(EXAMPLE_VULN)},
        {"role": "assistant", "content": json.dumps(EXAMPLE_ANSWER, ensure_ascii=False)},
        {"role": "user", "content": build_prompt(v)},
    ]


def _ensure_kev(v: Vulnerability, parsed: dict) -> dict:
    """KEV 등재 사실은 모델이 빠뜨려도 반드시 보이게 한다."""
    if v.known_exploited and "실제 공격" not in parsed["impact"]:
        parsed = {**parsed, "impact": f"{KEV_SENTENCE} {parsed['impact']}"}
    return parsed


def parse_response(content: str) -> dict | None:
    content = re.sub(r"<think>.*?</think>", "", content or "", flags=re.DOTALL).strip()
    candidates = [content]
    m = re.search(r"\{.*\}", content, re.DOTALL)
    if m:
        candidates.append(m.group(0))
    for c in candidates:
        try:
            data = json.loads(c)
        except ValueError:
            continue
        if isinstance(data, dict) and all(isinstance(data.get(k), str) for k in ("summary", "impact", "action")):
            return {k: data[k].strip() for k in ("summary", "impact", "action")}
    return None


def rule_explanation(v: Vulnerability) -> Explanation:
    """LLM 없이 만드는 기본 한국어 설명."""
    vtype = vuln_type_ko(v.description)
    summary = f"{v.package} {v.version} 에 {v.severity_ko} 등급 보안 취약점({v.id})이 있습니다."
    if vtype:
        summary += f" 유형: {vtype}."

    impact = []
    if v.known_exploited:
        impact.append(KEV_SENTENCE)
    if v.epss is not None:
        impact.append(f"30일 내 악용 가능성 추정치는 {v.epss:.1%} 입니다(EPSS).")
    if v.cvss_score is not None and v.cvss_score >= 9.0:
        impact.append("원격에서 큰 피해(코드 실행·데이터 유출 등)로 이어질 수 있는 수준입니다.")
    if v.description:
        desc = v.description if len(v.description) <= 300 else v.description[:300] + "…"
        impact.append(f"원문 설명: {desc}")

    cmd = fix_command(v)
    if cmd:
        action = f"{min_fix_version(v)} 이상으로 업그레이드하세요: {cmd}"
    else:
        action = "아직 패치 버전이 없습니다. 해당 기능을 쓰는지 확인하고 대체 라이브러리를 검토하세요."
    return Explanation(summary=summary, impact=" ".join(impact) or "확인 필요", action=action, source="rule")


class Explainer:
    """상위 위험 항목을 LLM 으로 설명. 결과는 캐시 파일에 저장해 재실행 시 재사용한다."""

    def __init__(self, client: OllamaClient | None, cache_path: Path | None = None):
        self.client = client
        self.cache_path = cache_path
        self.cache: dict[str, dict] = {}
        self.errors: list[str] = []
        if cache_path and cache_path.is_file():
            try:
                self.cache = json.loads(cache_path.read_text(encoding="utf-8"))
            except ValueError:
                self.cache = {}

    def _cache_key(self, messages: list[dict]) -> str:
        # 프롬프트·예시가 바뀌면 키도 바뀌어 자동으로 다시 생성된다
        model = self.client.model if self.client else ""
        return hashlib.sha256(f"{model}\n{json.dumps(messages, ensure_ascii=False)}".encode()).hexdigest()

    def explain(self, v: Vulnerability) -> Explanation:
        if self.client is None:
            return rule_explanation(v)
        messages = build_messages(v)
        key = self._cache_key(messages)
        if key in self.cache:
            return Explanation(**self.cache[key], source="llm")
        try:
            parsed = parse_response(self.client.chat(messages))
        except (urllib.error.URLError, OSError, ValueError) as e:
            self.errors.append(f"{v.id}: {e}")
            return rule_explanation(v)
        if parsed is None:
            self.errors.append(f"{v.id}: LLM 응답을 해석하지 못했습니다")
            return rule_explanation(v)
        parsed = _ensure_kev(v, parsed)
        self.cache[key] = parsed
        self._save()
        return Explanation(**parsed, source="llm")

    def _save(self) -> None:
        if not self.cache_path:
            return
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps(self.cache, ensure_ascii=False, indent=1), encoding="utf-8")
