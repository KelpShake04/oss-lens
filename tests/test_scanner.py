import json

from oss_lens.scanner import coverage_gaps, first_party_packages


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")


def test_first_party_packages_root_and_workspaces(tmp_path):
    _write(tmp_path / "package-lock.json", {
        "name": "app", "version": "1.0.0", "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "packages/ui": {"name": "@app/ui", "version": "0.1.0"},
            "node_modules/lodash": {"version": "4.17.15", "resolved": "https://registry.npmjs.org/..."},
            "node_modules/fsevents/node_modules/abbrev": {"version": "1.1.1", "inBundle": True},
        },
    })
    assert first_party_packages(tmp_path) == {("app", "1.0.0"), ("@app/ui", "0.1.0")}


def test_first_party_packages_skips_node_modules_and_bad_json(tmp_path):
    _write(tmp_path / "node_modules" / "x" / "package-lock.json", {"name": "x", "version": "1"})
    _write(tmp_path / "sub" / "package-lock.json", "{ broken")
    assert first_party_packages(tmp_path) == set()


def test_coverage_gaps_package_json_without_lock(tmp_path):
    # DVNA 실제 사례: package.json 만 있으면 syft 가 의존성을 하나도 찾지 못한다
    _write(tmp_path / "package.json", {"dependencies": {"express": "^4.16.2"}})
    _write(tmp_path / "web" / "package.json", {})
    _write(tmp_path / "web" / "yarn.lock", "")
    _write(tmp_path / "node_modules" / "a" / "package.json", {})
    notes = coverage_gaps(tmp_path)
    assert len(notes) == 1
    assert "lock 파일이 없는 package.json 1개" in notes[0]
    assert "/package.json" in notes[0] and "/web/" not in notes[0]


def test_coverage_gaps_unpinned_requirements(tmp_path):
    _write(tmp_path / "requirements.txt", "\n".join([
        "# comment", "Django==4.2", "requests>=2.0", "flask", "-r base.txt", "-e .",
        "pkg @ https://example.com/pkg.whl", "yaml==5.1 ; python_version < '3.8'", "",
    ]))
    _write(tmp_path / "labs" / "requirements-dev.txt", "pytest~=8.0\n")
    notes = coverage_gaps(tmp_path)
    assert len(notes) == 1
    assert "requirements 항목 3개" in notes[0]
    assert "requests>=2.0 (/requirements.txt)" in notes[0]
    assert "pytest~=8.0 (/labs/requirements-dev.txt)" in notes[0]


def test_coverage_gaps_clean_project(tmp_path):
    _write(tmp_path / "package.json", {})
    _write(tmp_path / "package-lock.json", {})
    _write(tmp_path / "requirements.txt", "Django==4.2\n")
    assert coverage_gaps(tmp_path) == []
