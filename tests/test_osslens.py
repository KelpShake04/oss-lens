import io
import json
import os
import tempfile
import unittest
import urllib.error
from unittest import mock

from osslens import cli, licenses, llm, report, scanner

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class ParseTests(unittest.TestCase):
    def test_parse_syft_packages_and_licenses(self):
        pkgs = {p.name: p for p in scanner.parse_syft(load("syft.json"))}
        self.assertEqual(len(pkgs), 6)
        self.assertEqual(pkgs["lodash"].version, "4.17.4")
        self.assertEqual(pkgs["lodash"].licenses, ["MIT"])
        self.assertEqual(pkgs["tinymce"].licenses, ["GPL-2.0-or-later"])
        self.assertEqual(pkgs["django"].licenses, [])
        self.assertEqual(pkgs["old-style"].licenses, ["LGPL-3.0-only"])  # 문자열 형태 라이선스
        self.assertEqual(pkgs["django"].locations, ["/requirements.txt"])

    def test_parse_grype(self):
        vulns = scanner.parse_grype(load("grype.json"))
        self.assertEqual(len(vulns), 5)  # 중복 매치 1건 제거
        top = vulns[0]
        self.assertEqual(top.id, "GHSA-jf85-cpcp-j695")
        self.assertEqual(top.package, "lodash")
        self.assertEqual(top.fixed_in, ["4.17.12"])
        self.assertEqual(top.aliases, ["CVE-2019-10744"])
        # 설명이 비어 있으면 relatedVulnerabilities에서 가져온다
        self.assertIn("lower than 4.17.12", top.description)
        medium = next(v for v in vulns if v.id == "GHSA-x8x9-2x9w-8w4w")
        self.assertEqual(medium.severity, "Medium")  # 소문자 심각도 정규화
        self.assertEqual(medium.fixed_in, [])

    def test_empty_inputs(self):
        self.assertEqual(scanner.parse_syft({}), [])
        self.assertEqual(scanner.parse_grype({"matches": None}), [])


class SeverityTests(unittest.TestCase):
    def test_sorted_by_severity_then_cvss(self):
        vulns = scanner.parse_grype(load("grype.json"))
        self.assertEqual(
            [(v.severity, v.id) for v in vulns],
            [("Critical", "GHSA-jf85-cpcp-j695"), ("Critical", "CVE-2099-0002"),
             ("High", "GHSA-p6mc-m468-83gw"), ("Medium", "GHSA-x8x9-2x9w-8w4w"),
             ("Low", "CVE-2099-0001")],
        )

    def test_unknown_severity_sorts_last(self):
        a = scanner.Vulnerability("X", "p", "1", "npm", scanner.normalize_severity("weird"))
        b = scanner.Vulnerability("Y", "p", "1", "npm", "Negligible")
        self.assertEqual([v.id for v in scanner.sort_vulnerabilities([a, b])], ["Y", "X"])
        self.assertEqual(a.severity, "Unknown")

    def test_counts(self):
        counts = scanner.severity_counts(scanner.parse_grype(load("grype.json")))
        self.assertEqual(counts["Critical"], 2)
        self.assertEqual(counts["High"], 1)
        self.assertEqual(counts["Negligible"], 0)


class LicenseTests(unittest.TestCase):
    def test_classify(self):
        self.assertIsNone(licenses.classify_license("MIT"))
        self.assertIsNone(licenses.classify_license("Apache-2.0"))
        self.assertEqual(licenses.classify_license("GPL-2.0-or-later")[0], "high")
        self.assertEqual(licenses.classify_license("GNU General Public License v3")[0], "high")
        self.assertEqual(licenses.classify_license("AGPL-3.0-only")[1], "강한 카피레프트 (네트워크)")
        self.assertEqual(licenses.classify_license("LGPL-2.1-or-later")[0], "medium")
        self.assertEqual(licenses.classify_license("SSPL-1.0")[0], "high")
        self.assertEqual(licenses.classify_license("UNKNOWN")[1], "라이선스 미확인")
        self.assertEqual(licenses.classify_license("")[1], "라이선스 미확인")

    def test_dual_license_downgraded(self):
        risk, category, note = licenses.classify_license("MIT OR GPL-3.0-only")
        self.assertEqual(risk, "low")
        self.assertIn("이중 라이선스", category)
        self.assertEqual(licenses.classify_license("GPL-2.0-only OR AGPL-3.0-only")[0], "high")

    def test_check_licenses(self):
        findings = {f.package: f for f in licenses.check_licenses(scanner.parse_syft(load("syft.json")))}
        self.assertNotIn("lodash", findings)
        self.assertEqual(findings["tinymce"].risk, "high")
        self.assertEqual(findings["django"].category, "라이선스 미확인")
        self.assertEqual(findings["old-style"].risk, "medium")
        self.assertEqual(findings["dual-pkg"].risk, "low")
        ordered = licenses.check_licenses(scanner.parse_syft(load("syft.json")))
        self.assertEqual(ordered[0].risk, "high")
        self.assertEqual(ordered[-1].risk, "low")

    def test_known_license_beats_unknown(self):
        pkg = scanner.Package("x", "1", "npm", licenses=["MIT", "UNKNOWN"])
        self.assertEqual(licenses.check_licenses([pkg]), [])


class HtmlEscapeTests(unittest.TestCase):
    def render(self, explanations=None):
        packages = scanner.parse_syft(load("syft.json"))
        vulns = scanner.parse_grype(load("grype.json"))
        return report.render_report(
            target="/tmp/<b>evil</b>", packages=packages, vulns=vulns,
            license_findings=licenses.check_licenses(packages),
            explanations=explanations or {}, llm_status="상태 <i>x</i>", model="m<1>",
            tools="syft 1, grype 1", generated_at="2026-10-26 00:00:00",
        )

    def test_scanner_data_escaped(self):
        out = self.render()
        self.assertNotIn("<script>", out)
        self.assertNotIn("<img src=x", out)
        self.assertNotIn("<b>evil</b>", out)
        self.assertNotIn("<i>x</i>", out)
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", out)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", out)
        # javascript: URL은 링크로 만들지 않는다
        self.assertNotIn('href="javascript:', out)
        self.assertIn('href="https://github.com/advisories/GHSA-jf85-cpcp-j695"', out)

    def test_llm_text_escaped(self):
        vuln = scanner.parse_grype(load("grype.json"))[0]
        out = self.render({llm.vuln_key(vuln): "위험도: <script>steal()</script>"})
        self.assertNotIn("<script>steal()", out)
        self.assertIn("위험도: &lt;script&gt;steal()&lt;/script&gt;", out)
        self.assertIn("LLM 해설 (m&lt;1&gt;)", out)

    def test_summary_counts(self):
        out = self.render()
        self.assertIn('<b>2</b><span>긴급 (Critical)</span>', out)
        self.assertIn('<b>6</b><span>패키지</span>', out)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = os.path.join(self.tmp.name, "sub", "report.html")
        patches = [
            mock.patch.object(scanner, "run_syft", return_value=load("syft.json")),
            mock.patch.object(scanner, "run_grype", return_value=load("grype.json")),
            mock.patch.object(cli, "log"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def read(self):
        with open(self.out, encoding="utf-8") as fh:
            return fh.read()

    def test_no_llm_never_calls_network(self):
        with mock.patch("urllib.request.urlopen") as urlopen:
            cli.scan(self.tmp.name, self.out, use_llm=False)
        urlopen.assert_not_called()
        html_text = self.read()
        self.assertIn("--no-llm 옵션으로 LLM 해설을 생략했습니다.", html_text)
        self.assertIn("GHSA-jf85-cpcp-j695", html_text)
        self.assertIn("tinymce", html_text)

    def test_llm_unreachable_fallback(self):
        err = urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))
        with mock.patch("urllib.request.urlopen", side_effect=err) as urlopen:
            cli.scan(self.tmp.name, self.out, llm_host="http://192.168.0.10:11434", top=3)
        self.assertEqual(urlopen.call_count, 1)  # ping 실패 후 더 이상 호출하지 않음
        html_text = self.read()
        self.assertIn("연결할 수 없습니다", html_text)
        self.assertNotIn('class="explain"', html_text)
        self.assertIn("GHSA-jf85-cpcp-j695", html_text)

    def test_llm_success_sends_only_metadata(self):
        sent = []

        def fake_urlopen(req, timeout=None):
            if isinstance(req, str):
                return FakeResponse(b'{"models": []}')
            sent.append((req.full_url, json.loads(req.data.decode("utf-8"))))
            reply = {"message": {"content": "<think>생각</think>위험도: 높음\n영향: ...\n조치 방법: 업데이트"}}
            return FakeResponse(json.dumps(reply).encode("utf-8"))

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen), \
                mock.patch.dict(os.environ, {"OLLAMA_HOST": "10.0.0.5:11434"}):
            cli.scan(self.tmp.name, self.out, top=2, model="qwen3:8b")
        self.assertEqual(len(sent), 2)
        url, body = sent[0]
        self.assertEqual(url, "http://10.0.0.5:11434/api/chat")
        self.assertEqual(body["model"], "qwen3:8b")
        self.assertFalse(body["stream"])
        prompt = body["messages"][1]["content"]
        self.assertIn("lodash 4.17.4", prompt)
        self.assertIn("GHSA-jf85-cpcp-j695, CVE-2019-10744", prompt)
        self.assertIn("4.17.12", prompt)
        self.assertNotIn("/package-lock.json", json.dumps(body, ensure_ascii=False))
        html_text = self.read()
        self.assertEqual(html_text.count('class="explain"'), 2)
        self.assertIn("조치 방법: 업데이트", html_text)
        self.assertNotIn("생각", html_text)

    def test_llm_fails_midway_keeps_partial(self):
        calls = {"n": 0}

        def fake_urlopen(req, timeout=None):
            if isinstance(req, str):
                return FakeResponse(b"{}")
            calls["n"] += 1
            if calls["n"] == 2:
                raise TimeoutError("timed out")
            return FakeResponse(json.dumps({"message": {"content": "위험도: 높음"}}).encode())

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            cli.scan(self.tmp.name, self.out, llm_host="localhost", top=5)
        self.assertEqual(calls["n"], 2)
        html_text = self.read()
        self.assertEqual(html_text.count('class="explain"'), 1)
        self.assertIn("나머지 항목은 해설 없이", html_text)


class HostTests(unittest.TestCase):
    def test_resolve_host(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(llm.resolve_host(), "http://localhost:11434")
            self.assertEqual(llm.resolve_host("192.168.0.10"), "http://192.168.0.10:11434")
            self.assertEqual(llm.resolve_host("http://pc.local:8080/"), "http://pc.local:8080")
            self.assertEqual(llm.resolve_host("0.0.0.0"), "http://localhost:11434")
        with mock.patch.dict(os.environ, {"OLLAMA_HOST": "192.168.0.20:11434"}):
            self.assertEqual(llm.resolve_host(), "http://192.168.0.20:11434")
            self.assertEqual(llm.resolve_host("localhost:1"), "http://localhost:1")

    def test_invalid_host(self):
        with self.assertRaises(ValueError):
            llm.resolve_host("ftp://x")


class ToolMissingTests(unittest.TestCase):
    def test_missing_syft_message(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch("shutil.which", return_value=None):
            with self.assertRaises(scanner.ScanError) as ctx:
                scanner.run_syft(tmp)
        self.assertIn("brew install syft", str(ctx.exception))

    def test_main_returns_error_code(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch("shutil.which", return_value=None), \
                mock.patch.object(cli, "log") as log:
            code = cli.main(["scan", tmp, "-o", os.path.join(tmp, "r.html")])
        self.assertEqual(code, 2)
        self.assertIn("syft", log.call_args[0][0])

    def test_missing_folder(self):
        with self.assertRaises(scanner.ScanError):
            scanner.run_syft("/nonexistent/osslens-test")


if __name__ == "__main__":
    unittest.main()
