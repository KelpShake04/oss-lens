import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from oss_lens.llm import (
    EXAMPLES,
    KEV_SENTENCE,
    SYSTEM_PROMPT,
    Explainer,
    OllamaClient,
    build_messages,
    build_prompt,
    key_terms,
    normalize_host,
    parse_response,
    postprocess,
    risk_conditions,
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


def test_build_messages_has_example_turns():
    msgs = build_messages(_v())
    assert [m["role"] for m in msgs] == ["system"] + ["user", "assistant"] * len(EXAMPLES) + ["user"]
    assert msgs[0]["content"] == SYSTEM_PROMPT
    assert "ansi-regex" in msgs[1]["content"]
    assert json.loads(msgs[2]["content"]) == EXAMPLES[0][1]
    assert "moment" in msgs[3]["content"]
    assert "minimist" in msgs[-1]["content"]


@pytest.mark.parametrize("vuln,answer", EXAMPLES, ids=[v.package for v, _ in EXAMPLES])
def test_examples_follow_own_rules(vuln, answer):
    text = " ".join(answer.values())
    assert "npm install" not in text
    # 존댓말만 사용 (문장 끝이 '다.' 이면 '니다.' 여야 함)
    for sentence in re.findall(r"[^.]*다\.", text):
        assert sentence.endswith("니다."), sentence
    # 원문에 없는 '코드 실행'을 예시가 먼저 쓰면 모델도 따라 한다
    if "execut" not in vuln.description.lower():
        assert "코드 실행" not in text
    assert answer["action"].startswith(f"1) {vuln.package}를 {vuln.fix_versions[0]} 이상으로 올리세요.")


def test_examples_cover_with_and_without_workaround():
    steps = [len(re.findall(r"\d\) ", answer["action"])) for _, answer in EXAMPLES]
    assert sorted(steps) == [2, 3]
    # 예시의 단계 수가 '위험 조건' 유무와 맞아야 모델이 규칙을 제대로 배운다
    for vuln, answer in EXAMPLES:
        assert postprocess(vuln, answer) == answer


# 데모 프로젝트 실제 grype 설명 (NVD)
DJANGO = ("Django 3.1.x before 3.1.13 and 3.2.x before 3.2.5 allows QuerySet.order_by SQL injection "
          "if order_by is untrusted input from a client of a web application.")
PYYAML = ("A vulnerability was discovered in the PyYAML library in versions before 5.4, where it is susceptible "
          "to arbitrary code execution when it processes untrusted YAML files through the full_load method or "
          "with the FullLoader loader. Applications that use the library to process untrusted input may be "
          "vulnerable to this flaw.")
EJS = ("The ejs (aka Embedded JavaScript templates) package 3.1.6 for Node.js allows server-side template "
       "injection in settings[view options][outputFunctionName]. This is parsed as an internal option, and "
       "overwrites the outputFunctionName option with an arbitrary OS command (which will be executed upon "
       "template compilation).")
PILLOW = ("Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 and libwebp 1.3.2 allowed "
          "a remote attacker to perform an out of bounds memory write via a crafted HTML page.")


@pytest.mark.parametrize("desc,pkg,expected", [
    (DJANGO, "django", ["QuerySet.order_by"]),
    (PYYAML, "pyyaml", ["full_load", "FullLoader"]),  # 'PyYAML' 은 패키지 이름이라 제외
    (EJS, "ejs", ["outputFunctionName"]),  # 'JavaScript', 'Node.js' 제외
    ("Prototype Pollution via file index.js, function setKey() (lines 69-95).", "minimist", ["setKey()"]),
    ("The Jinja `xmlattr` filter can be abused", "jinja2", ["xmlattr"]),
    ("Prototype pollution attack when using _.zipObjectDeep in lodash", "lodash", ["_.zipObjectDeep"]),
    (PILLOW, "pillow", []),
])
def test_key_terms(desc, pkg, expected):
    assert key_terms(desc, pkg) == expected


def test_risk_conditions():
    assert risk_conditions(DJANGO) == ["if order_by is untrusted input from a client of a web application"]
    assert risk_conditions(PYYAML)[0].startswith("when it processes untrusted YAML files through the full_load")
    assert risk_conditions(EJS) == []
    assert risk_conditions(PILLOW) == []
    assert risk_conditions("Bad bug. There are no known workarounds for this issue.") == []
    moment = EXAMPLES[1][0].description
    assert [c.split()[0] for c in risk_conditions(moment)] == ["especially", "As"]


def _answer(action="1) 올리세요. 2) 업로드 파일을 검사하세요. 3) 테스트하세요.", summary="요약입니다."):
    return {"summary": summary, "impact": "영향입니다.", "action": action}


def test_postprocess_drops_invented_workaround():
    # pillow 실제 사례: 원문에 위험 조건이 없는데 임시 대응을 지어냄
    out = postprocess(_v(description=PILLOW), _answer())
    assert out["action"] == "1) 올리세요. 2) 테스트하세요."


def test_postprocess_keeps_grounded_workaround():
    action = "1) 3.1.13 이상으로 올리세요. 2) order_by에 사용자 입력을 넣지 마세요. 3) 테스트하세요."
    assert postprocess(_v(description=DJANGO), _answer(action))["action"] == action
    action = "1) 5.4 이상으로 올리세요. 2) full_load 대신 safe_load 를 쓰세요. 3) 테스트하세요."
    assert postprocess(_v(description=PYYAML), _answer(action))["action"] == action


def test_postprocess_drops_workaround_that_ignores_condition():
    # django 실제 사례: 조건(order_by)과 무관하고 틀린 조언 ('string formatting')
    action = ("1) django를 3.1.13 이상으로 올리세요. 2) 사용자 입력을 SQL 쿼리에 그대로 사용하지 않고, "
              "ORM이나 파이썬의 string formatting 방식으로 처리하세요. 3) 접근 로그를 점검하세요.")
    out = postprocess(_v(description=DJANGO), _answer(action))
    assert out["action"] == "1) django를 3.1.13 이상으로 올리세요. 2) 접근 로그를 점검하세요."


def test_postprocess_keeps_workaround_when_condition_has_no_names():
    # moment: 조건에 함수 이름이 없어 언급 여부를 검사할 수 없으면 모델 답을 믿는다
    vuln, answer = EXAMPLES[1]
    assert postprocess(vuln, answer)["action"] == answer["action"]


def test_postprocess_step_split_edge_cases():
    no_cond = _v(description=PILLOW)
    # 'CVSS 9.8)' 같은 숫자는 단계 구분이 아니다
    action = "1) 10.0.1 이상(CVSS 9.8) 으로 올리세요. 2) 테스트하세요."
    assert postprocess(no_cond, _answer(action))["action"] == action
    # 번호 없는 답은 그대로
    assert postprocess(no_cond, _answer("올리세요."))["action"] == "올리세요."
    # 머리말은 남기고 가운데 단계만 지운다
    out = postprocess(no_cond, _answer("다음을 하세요: 1) 올리세요. 2) 검사하세요. 3) 테스트하세요."))
    assert out["action"] == "다음을 하세요: 1) 올리세요. 2) 테스트하세요."


def test_postprocess_adds_missing_key_term():
    out = postprocess(_v(description=DJANGO), _answer(summary="SQL 주입 취약점이 있습니다."))
    assert out["summary"] == "SQL 주입 취약점이 있습니다. 관련 기능: QuerySet.order_by."
    for summary in ("QuerySet.order_by 에서 SQL 주입이 있습니다.", "order_by 에 SQL 주입이 있습니다."):
        assert "관련 기능" not in postprocess(_v(description=DJANGO), _answer(summary=summary))["summary"]
    setkey = "Prototype Pollution via file index.js, function setKey() (lines 69-95)."
    assert "관련 기능" not in postprocess(_v(description=setkey), _answer(summary="setKey 함수 문제"))["summary"]


def test_build_prompt_gives_terms_and_conditions():
    p = build_prompt(_v(description=DJANGO))
    assert "원문 핵심 용어(summary 에 그대로 쓴다): QuerySet.order_by" in p
    assert "위험 조건(원문): if order_by is untrusted input" in p
    assert "위험 조건: 없음" in build_prompt(_v(description=PILLOW))


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
    assert req["messages"] == build_messages(_v())


def test_ollama_client_unreachable():
    assert "연결할 수 없습니다" in OllamaClient(host="127.0.0.1:1").check()
