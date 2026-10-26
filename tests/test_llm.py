import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from oss_lens.llm import (
    EXAMPLE_ANSWER,
    KEV_SENTENCE,
    SYSTEM_PROMPT,
    Explainer,
    OllamaClient,
    build_messages,
    build_prompt,
    normalize_host,
    parse_response,
    rule_explanation,
    vuln_type_ko,
)
from oss_lens.models import Vulnerability


def _v(**kw):
    base = dict(id="CVE-2021-44906", severity="Critical", package="minimist", version="1.2.5",
                pkg_type="npm", cvss_score=9.8, fix_versions=["1.2.6"],
                description="Minimist <=1.2.5 is vulnerable to Prototype Pollution via file index.js")
    base.update(kw)
    return Vulnerability(**base)


@pytest.mark.parametrize("raw,expected", [
    (None, "http://127.0.0.1:11434"),
    ("", "http://127.0.0.1:11434"),
    ("0.0.0.0", "http://127.0.0.1:11434"),
    ("192.168.0.5", "http://192.168.0.5:11434"),
    ("192.168.0.5:9000", "http://192.168.0.5:9000"),
    ("http://gpu-pc:11434/", "http://gpu-pc:11434"),
    ("https://llm.example", "https://llm.example:443"),
    ("[::1]:11434", "http://[::1]:11434"),
])
def test_normalize_host(raw, expected):
    assert normalize_host(raw) == expected


def test_vuln_type_ko():
    assert vuln_type_ko("Prototype Pollution in x").startswith("프로토타입 오염")
    assert vuln_type_ko("allows server-side template injection ... arbitrary OS command").startswith("템플릿 주입")
    assert vuln_type_ko("Inefficient Regular Expression Complexity").startswith("정규식 서비스 거부")
    assert vuln_type_ko("nothing here") is None


def test_parse_response():
    good = {"summary": " s ", "impact": "i", "action": "a"}
    assert parse_response(json.dumps(good)) == {"summary": "s", "impact": "i", "action": "a"}
    assert parse_response("<think>hmm</think>\n앞말 " + json.dumps(good) + " 뒷말")["action"] == "a"
    assert parse_response('{"summary": "only"}') is None
    assert parse_response("그냥 텍스트") is None


def test_build_prompt_includes_facts():
    p = build_prompt(_v(epss=0.0123, aliases=["GHSA-xvch-5gv4-984h"], locations=["/package-lock.json"]))
    assert "minimist 1.2.5 (npm)" in p
    assert "GHSA-xvch-5gv4-984h" in p
    assert "CVSS 9.8" in p
    assert "1.2%" in p
    assert "패치 버전: 1.2.6 이상" in p
    assert "npm install" not in p  # 명령어는 리포트가 따로 보여준다 (모델이 잘라먹던 문제)
    assert "/package-lock.json" in p
    assert "CISA KEV): 없음" in p
    assert KEV_SENTENCE in build_prompt(_v(known_exploited=True))
    assert "패치 버전: 없음" in build_prompt(_v(fix_versions=[]))


def test_build_messages_has_example_turn():
    msgs = build_messages(_v())
    assert [m["role"] for m in msgs] == ["system", "user", "assistant", "user"]
    assert msgs[0]["content"] == SYSTEM_PROMPT
    assert "ansi-regex" in msgs[1]["content"]
    assert json.loads(msgs[2]["content"]) == EXAMPLE_ANSWER
    assert "minimist" in msgs[3]["content"]


def test_example_answer_follows_own_rules():
    text = " ".join(EXAMPLE_ANSWER.values())
    assert "npm install" not in text
    # 존댓말만 사용 (문장 끝이 '다.' 이면 '니다.' 여야 함)
    for sentence in re.findall(r"[^.]*다\.", text):
        assert sentence.endswith("니다."), sentence


def test_rule_explanation():
    ex = rule_explanation(_v(known_exploited=True))
    assert ex.source == "rule"
    assert "치명" in ex.summary and "프로토타입 오염" in ex.summary
    assert "CISA KEV" in ex.impact
    assert "npm install minimist@^1.2.6" in ex.action
    no_fix = rule_explanation(_v(fix_versions=[]))
    assert "패치 버전이 없습니다" in no_fix.action


class FakeClient:
    model = "fake"

    def __init__(self, reply):
        self.reply = reply
        self.calls = 0

    def chat(self, messages):
        self.calls += 1
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


def test_explainer_uses_llm_and_cache(tmp_path):
    cache = tmp_path / "cache.json"
    reply = json.dumps({"summary": "요약", "impact": "영향", "action": "조치"})
    client = FakeClient(reply)
    ex = Explainer(client, cache).explain(_v())
    assert (ex.source, ex.summary) == ("llm", "요약")
    assert client.calls == 1

    client2 = FakeClient(OSError("down"))
    ex2 = Explainer(client2, cache).explain(_v())
    assert ex2.summary == "요약" and client2.calls == 0  # 캐시 적중


def test_explainer_adds_kev_sentence_when_model_omits_it():
    reply = json.dumps({"summary": "요약", "impact": "메모리가 손상됩니다.", "action": "조치"})
    ex = Explainer(FakeClient(reply)).explain(_v(known_exploited=True))
    assert ex.impact == f"{KEV_SENTENCE} 메모리가 손상됩니다."
    # 모델이 이미 언급했으면 중복으로 붙이지 않는다
    reply = json.dumps({"summary": "요약", "impact": "실제 공격에 쓰였습니다.", "action": "조치"})
    assert Explainer(FakeClient(reply)).explain(_v(known_exploited=True)).impact == "실제 공격에 쓰였습니다."
    assert Explainer(FakeClient(reply)).explain(_v()).impact == "실제 공격에 쓰였습니다."


def test_explainer_falls_back_on_error_or_bad_reply():
    for reply in (OSError("connection refused"), "JSON 아님"):
        explainer = Explainer(FakeClient(reply))
        assert explainer.explain(_v()).source == "rule"
        assert len(explainer.errors) == 1


def test_explainer_without_client():
    assert Explainer(None).explain(_v()).source == "rule"


@pytest.fixture
def ollama_server():
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, obj):
            body = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._send({"models": [{"name": "qwen3:8b"}, {"name": "llama3:latest"}]})

        def do_POST(self):
            seen.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self._send({"message": {"content": json.dumps({"summary": "s", "impact": "i", "action": "a"})}})

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"127.0.0.1:{server.server_port}", seen
    server.shutdown()


def test_ollama_client_roundtrip(ollama_server):
    host, seen = ollama_server
    client = OllamaClient(host=host)
    assert client.check() is None
    assert OllamaClient(host=host, model="llama3").check() is None  # ':latest' 생략 허용
    assert "ollama pull" in OllamaClient(host=host, model="missing:1b").check()

    ex = Explainer(client).explain(_v())
    assert ex.source == "llm"
    req = seen[0]
    assert req["model"] == "qwen3:8b"
    assert req["stream"] is False and req["think"] is False
    assert req["format"]["required"] == ["summary", "impact", "action"]
    assert [m["role"] for m in req["messages"]] == ["system", "user", "assistant", "user"]


def test_ollama_client_unreachable():
    assert "연결할 수 없습니다" in OllamaClient(host="127.0.0.1:1").check()
