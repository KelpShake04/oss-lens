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
    names = {p.name for p in parse_syft(syft_data)}
    assert "vulnerable-demo" not in names
    assert len(names) == 15


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
    assert "Prototype Pollution" in v.description


def test_parse_grype_uses_related_description_and_cvss():
    data = {"matches": [{
        "vulnerability": {"id": "GHSA-x", "severity": "High", "fix": {"versions": [], "state": "not-fixed"}},
        "relatedVulnerabilities": [{"id": "CVE-1", "description": "from nvd",
                                    "cvss": [{"metrics": {"baseScore": 8.1}}]}],
        "artifact": {"name": "p", "version": "1", "type": "npm"},
    }]}
    v = parse_grype(data)[0]
    assert v.description == "from nvd"
    assert v.cvss_score == 8.1
    assert v.fix_state == "not-fixed"
    assert v.aliases == ["CVE-1"]


def test_descriptor_version(syft_data, grype_data):
    assert descriptor_version(syft_data) == "1.55.0"
    assert descriptor_version(grype_data) == "0.121.0"
    assert descriptor_version({}) is None
