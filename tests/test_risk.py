from oss_lens.models import Vulnerability
from oss_lens.parsers import parse_grype
from oss_lens.risk import (
    fix_command,
    min_fix_version,
    pick_top,
    rank,
    same_package_count,
    score,
    upgrade_plan,
)


def _v(**kw):
    base = dict(id="CVE-1", severity="High", package="p", version="1.0.0", pkg_type="npm")
    base.update(kw)
    return Vulnerability(**base)


def test_score_uses_cvss_then_severity():
    assert score(_v(cvss_score=7.0)) == 7.0
    assert score(_v(severity="Critical")) == 9.5
    assert score(_v(severity="Unknown")) == 0.0


def test_score_bonuses():
    assert score(_v(cvss_score=5.0, known_exploited=True)) == 8.0
    assert score(_v(cvss_score=5.0, epss=0.5)) == 6.5
    assert score(_v(cvss_score=5.0, fix_versions=["1.0.1"])) == 5.5


def test_rank_puts_known_exploited_first():
    ranked = rank([_v(id="A", cvss_score=9.0), _v(id="B", cvss_score=7.0, known_exploited=True)])
    assert [v.id for v in ranked] == ["B", "A"]


def test_rank_demo_fixture(grype_data):
    ranked = rank(parse_grype(grype_data))
    assert ranked[0].id == "CVE-2021-44906"  # 9.8 + EPSS
    assert [v.severity for v in ranked[:3]] == ["Critical"] * 3
    assert ranked[-1].severity == "Medium"


def test_pick_top_spreads_across_packages():
    # PyGoat 실제 사례: 점수순 상위 8개가 pyyaml·pillow·django 3종류뿐이었다
    ranked = rank([
        _v(id="Y1", package="pyyaml", cvss_score=9.9), _v(id="Y2", package="pyyaml", cvss_score=9.8),
        _v(id="P1", package="pillow", cvss_score=9.7), _v(id="Y3", package="pyyaml", cvss_score=9.6),
        _v(id="P2", package="pillow", cvss_score=9.5), _v(id="W1", package="werkzeug", cvss_score=7.5),
        _v(id="J1", package="pyjwt", cvss_score=7.4),
    ])
    assert [v.id for v in pick_top(ranked, 4)] == ["Y1", "P1", "W1", "J1"]
    # 패키지가 모자라면 남은 자리를 점수순으로 채우고, 결과는 점수순을 유지한다
    assert [v.id for v in pick_top(ranked, 6)] == ["Y1", "Y2", "P1", "Y3", "W1", "J1"]
    assert pick_top(ranked, 0) == []


def test_same_package_count():
    a, b = _v(id="A", package="pyyaml", version="5.1"), _v(id="B", package="pyyaml", version="5.1")
    c = _v(id="C", package="pyyaml", version="6.0")
    assert same_package_count([a, b, c], a) == 1
    assert same_package_count([a, b, c], c) == 0


def test_min_fix_version_picks_current_release_line():
    v = _v(version="3.2.0", fix_versions=["4.0.4", "2.2.28", "3.2.13"])
    assert min_fix_version(v) == "3.2.13"
    assert min_fix_version(_v(version="1.0", fix_versions=[])) is None
    # 현재보다 높은 패치가 없으면 가장 높은 버전
    assert min_fix_version(_v(version="9.0", fix_versions=["1.0", "2.0"])) == "2.0"


def test_min_fix_version_handles_mixed_versions():
    v = _v(version="1.0.0", fix_versions=["1.0.0-rc1", "1.0.1", "v1.2"])
    assert min_fix_version(v) == "1.0.1"


def test_fix_command_by_ecosystem():
    assert fix_command(_v(fix_versions=["4.17.21"], package="lodash")) == "npm install lodash@^4.17.21"
    assert fix_command(_v(pkg_type="python", package="pyyaml", fix_versions=["5.4"])).startswith(
        'pip install "pyyaml>=5.4"')
    assert fix_command(_v(pkg_type="go-module", package="golang.org/x/net", fix_versions=["0.23.0"])) == \
        "go get golang.org/x/net@v0.23.0"
    assert fix_command(_v(fix_versions=[])) is None


def test_upgrade_plan_groups_by_package():
    vulns = rank([
        _v(id="A", package="lodash", version="4.17.15", severity="High", cvss_score=7.4, fix_versions=["4.17.19"]),
        _v(id="B", package="lodash", version="4.17.15", severity="High", cvss_score=7.2, fix_versions=["4.17.21"]),
        _v(id="C", package="minimist", version="1.2.5", severity="Critical", cvss_score=9.8, fix_versions=["1.2.6"]),
        _v(id="D", package="nofix", version="1.0", severity="Medium", cvss_score=5.0),
    ])
    plans = upgrade_plan(vulns)
    assert [p["package"] for p in plans] == ["minimist", "lodash", "nofix"]
    lodash = plans[1]
    assert lodash["target"] == "4.17.21"
    assert lodash["fixed"] == 2
    assert lodash["command"] == "npm install lodash@^4.17.21"
    assert plans[2]["target"] is None and plans[2]["unfixed"] == 1 and plans[2]["command"] is None
