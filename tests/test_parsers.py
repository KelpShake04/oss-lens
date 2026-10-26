from oss_lens.parsers import descriptor_version, parse_grype, parse_syft


def test_parse_syft_packages_and_licenses(syft_data):
    pkgs = {p.name: p for p in parse_syft(syft_data)}
    assert pkgs["lodash"].version == "4.17.15"
    assert pkgs["lodash"].licenses == ["MIT"]
    assert pkgs["node-forge"].licenses == ["(BSD-3-Clause OR GPL-2.0)"]
    assert pkgs["pyyaml"].type == "python"
    assert pkgs["pyyaml"].licenses == []
    assert pkgs["pyyaml"].locations == ["/requirements.txt"]


def test_parse_syft_skips_project_root(syft_data):
    names = {p.name for p in parse_syft(syft_data, first_party={("vulnerable-demo", "1.0.0")})}
    assert "vulnerable-demo" not in names
    assert len(names) == 15
    assert "vulnerable-demo" in {p.name for p in parse_syft(syft_data)}


def test_parse_syft_keeps_bundled_deps_without_resolved():
    # NodeGoat 실제 사례: inBundle 의존성은 resolved 가 비어 있지만 프로젝트 자신이 아니다
    data = {"artifacts": [{"name": "abbrev", "version": "1.1.1", "type": "npm",
                           "metadataType": "javascript-npm-package-lock-entry",
                           "metadata": {"resolved": "", "integrity": ""}, "licenses": [{"value": "ISC"}]}]}
    assert [p.name for p in parse_syft(data, first_party={("app", "1.0.0")})] == ["abbrev"]


def test_parse_syft_accepts_string_licenses():
    data = {"artifacts": [{"name": "a", "version": "1", "type": "npm", "licenses": ["MIT", "MIT", " "]}]}
    assert parse_syft(data)[0].licenses == ["MIT"]


def test_parse_grype_merges_duplicate_matches(grype_data):
    vulns = parse_grype(grype_data)
    assert len(grype_data["matches"]) == 8
    assert len(vulns) == 7
    ids = [v.id for v in vulns if v.package == "minimist"]
    assert ids == ["CVE-2021-44906"]


def test_parse_grype_fields(grype_data):
    v = next(v for v in parse_grype(grype_data) if v.id == "CVE-2021-44906")
    assert v.severity == "Critical"
    assert v.cvss_score == 9.8
    assert v.epss == 0.0123
    assert v.fix_versions == ["1.2.6"]
    assert v.fix_state == "fixed"
    assert v.aliases == ["GHSA-xvch-5gv4-984h"]
    assert v.locations == ["/package-lock.json"]
    # GHSA 제목('Prototype Pollution in minimist')이 아니라 NVD 원문을 써야 함수 이름이 남는다
    assert "function setKey()" in v.description


def test_parse_grype_prefers_cve_id_and_longest_description():
    data = {"matches": [{
        "vulnerability": {"id": "GHSA-x", "severity": "High", "description": "SQL Injection in Django",
                          "fix": {"versions": [], "state": "not-fixed"}},
        "relatedVulnerabilities": [{"id": "CVE-1", "description": "allows QuerySet.order_by SQL injection if ...",
                                    "cvss": [{"metrics": {"baseScore": 8.1}}], "knownExploited": [{"cve": "CVE-1"}]}],
        "artifact": {"name": "p", "version": "1", "type": "npm"},
    }]}
    v = parse_grype(data)[0]
    assert v.id == "CVE-1"
    assert v.aliases == ["GHSA-x"]
    assert v.description == "allows QuerySet.order_by SQL injection if ..."
    assert v.cvss_score == 8.1
    assert v.known_exploited is True
    assert v.fix_state == "not-fixed"


def test_parse_grype_legacy_by_cve_output():
    # 예전 --by-cve 결과: ID 는 CVE 지만 설명은 GHSA 제목뿐 (최선을 다해 읽는다)
    data = {"matches": [{
        "vulnerability": {"id": "CVE-1", "severity": "High", "description": "Prototype Pollution in minimist"},
        "relatedVulnerabilities": [{"id": "GHSA-x", "description": "Prototype Pollution in minimist"}],
        "artifact": {"name": "minimist", "version": "1.2.5", "type": "npm"},
    }]}
    v = parse_grype(data)[0]
    assert (v.id, v.aliases, v.description) == ("CVE-1", ["GHSA-x"], "Prototype Pollution in minimist")


def test_parse_grype_merges_ghsa_and_cve_matches_of_same_issue():
    art = {"name": "p", "version": "1", "type": "npm"}
    data = {"matches": [
        {"vulnerability": {"id": "GHSA-x", "severity": "High"},
         "relatedVulnerabilities": [{"id": "CVE-1"}], "artifact": art},
        {"vulnerability": {"id": "CVE-1", "severity": "Critical", "namespace": "nvd:cpe"},
         "relatedVulnerabilities": [], "artifact": art},
    ]}
    vulns = parse_grype(data)
    assert len(vulns) == 1
    assert vulns[0].id == "CVE-1" and vulns[0].severity == "Critical"


def test_descriptor_version(syft_data, grype_data):
    assert descriptor_version(syft_data) == "1.55.0"
    assert descriptor_version(grype_data) == "0.121.0"
    assert descriptor_version({}) is None
