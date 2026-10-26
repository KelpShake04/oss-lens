"""취약점 위험 점수 계산·정렬, 생태계별 업그레이드 명령 생성."""

from __future__ import annotations

import re

from .models import Vulnerability, severity_rank

# CVSS 점수가 없을 때 쓰는 심각도별 기본 점수
SEVERITY_BASE = {
    "Critical": 9.5,
    "High": 7.5,
    "Medium": 5.0,
    "Low": 2.5,
    "Negligible": 0.5,
    "Unknown": 0.0,
}

KEV_BONUS = 3.0  # 실제 공격에 쓰인 취약점(CISA KEV)
EPSS_WEIGHT = 3.0  # 악용 확률(0~1)에 곱하는 가중치
FIX_BONUS = 0.5  # 패치 버전이 있으면 바로 조치 가능하므로 우선


def vuln_key(v: Vulnerability) -> str:
    return f"{v.id}|{v.package}|{v.version}"


def score(v: Vulnerability) -> float:
    base = v.cvss_score if v.cvss_score is not None else SEVERITY_BASE.get(v.severity, 0.0)
    s = base
    if v.known_exploited:
        s += KEV_BONUS
    if v.epss:
        s += EPSS_WEIGHT * v.epss
    if v.fix_versions:
        s += FIX_BONUS
    return round(s, 2)


def rank(vulns: list[Vulnerability]) -> list[Vulnerability]:
    for v in vulns:
        v.score = score(v)
    return sorted(
        vulns,
        key=lambda v: (-v.score, -severity_rank(v.severity), v.package.lower(), v.id),
    )


def _version_key(ver: str) -> tuple:
    """대략적인 버전 비교 키. 1.0.0-rc1 / 1.0.0rc1 같은 사전 릴리스는 1.0.0 보다 앞선다."""
    m = re.match(r"^([\d.]*\d)?(.*)$", ver.lstrip("v").split("+")[0])
    release = [int(p) for p in (m.group(1) or "").split(".") if p]
    # 숫자/문자 조각에 태그를 붙여 서로 비교 가능하게 한다
    pre = [(0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[.\-]", m.group(2)) if p]
    return (release, 0 if pre else 1, pre)


def min_fix_version(v: Vulnerability) -> str | None:
    """현재 버전보다 높은 패치 버전 중 가장 낮은 것. 여러 릴리스 라인이 있어도 현재 라인을 고른다."""
    if not v.fix_versions:
        return None
    current = _version_key(v.version)
    cands = sorted(v.fix_versions, key=_version_key)
    newer = [c for c in cands if _version_key(c) > current]
    return newer[0] if newer else cands[-1]


def upgrade_plan(vulns: list[Vulnerability]) -> list[dict]:
    """패키지별로 한 번에 올릴 버전(각 취약점 최소 패치 버전 중 가장 높은 것)과 해결 건수.

    패치가 없는 취약점은 unfixed 로 따로 센다. 최고 심각도, 위험 점수 합 순으로 정렬.
    """
    plans: dict[tuple, dict] = {}
    for v in vulns:
        p = plans.setdefault((v.package, v.version, v.pkg_type), {
            "package": v.package, "version": v.version, "pkg_type": v.pkg_type,
            "target": None, "fixed": 0, "unfixed": 0, "score": 0.0, "max_severity": v.severity,
        })
        p["score"] += v.score
        if severity_rank(v.severity) > severity_rank(p["max_severity"]):
            p["max_severity"] = v.severity
        ver = min_fix_version(v)
        if ver is None:
            p["unfixed"] += 1
            continue
        p["fixed"] += 1
        if p["target"] is None or _version_key(ver) > _version_key(p["target"]):
            p["target"] = ver
    for p in plans.values():
        p["command"] = _command(p["package"], p["pkg_type"], p["target"]) if p["target"] else None
    return sorted(
        plans.values(),
        key=lambda p: (-severity_rank(p["max_severity"]), -p["score"], p["package"].lower()),
    )


def fix_command(v: Vulnerability) -> str | None:
    """생태계에 맞는 업그레이드 명령. 패치 버전이 없으면 None."""
    ver = min_fix_version(v)
    if not ver:
        return None
    return _command(v.package, v.pkg_type, ver)


def _command(name: str, t: str, ver: str) -> str:
    if t == "npm":
        return f"npm install {name}@^{ver}"
    if t == "python":
        return f'pip install "{name}>={ver}"  # requirements.txt 도 {name}>={ver} 로 수정'
    if t == "go-module":
        return f"go get {name}@v{ver.lstrip('v')}"
    if t == "gem":
        return f"bundle update {name}  # Gemfile: gem '{name}', '>= {ver}'"
    if t == "rust-crate":
        return f"cargo update -p {name} --precise {ver}"
    if t == "java-archive":
        return f"pom.xml / build.gradle 에서 {name} 버전을 {ver} 이상으로 변경"
    if t == "php-composer":
        return f"composer require {name}:^{ver}"
    if t == "dotnet":
        return f"dotnet add package {name} --version {ver}"
    return f"{name} 을(를) {ver} 이상으로 업그레이드"
