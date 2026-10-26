"""syft / grype JSON 출력 파싱."""

from __future__ import annotations

from .models import Package, Vulnerability, severity_rank


def _license_values(raw) -> list[str]:
    """syft 라이선스 항목(문자열 또는 객체 목록)을 표기 문자열 목록으로."""
    values = []
    for lic in raw or []:
        if isinstance(lic, str):
            v = lic
        elif isinstance(lic, dict):
            v = lic.get("spdxExpression") or lic.get("value") or ""
        else:
            continue
        v = v.strip()
        if v and v not in values:
            values.append(v)
    return values


def _location_paths(raw) -> list[str]:
    paths = []
    for loc in raw or []:
        p = loc.get("path") if isinstance(loc, dict) else loc
        if p and p not in paths:
            paths.append(p)
    return paths


def _is_first_party(artifact: dict) -> bool:
    """package-lock.json 의 루트/워크스페이스 항목(배포 주소가 없음)은 프로젝트 자신이다."""
    return (
        artifact.get("metadataType") == "javascript-npm-package-lock-entry"
        and not (artifact.get("metadata") or {}).get("resolved")
    )


def parse_syft(data: dict) -> list[Package]:
    packages = []
    seen = set()
    for a in data.get("artifacts", []):
        if _is_first_party(a):
            continue
        key = (a.get("name"), a.get("version"), a.get("type"))
        if key in seen:
            continue
        seen.add(key)
        packages.append(
            Package(
                name=a.get("name", ""),
                version=a.get("version", ""),
                type=a.get("type", ""),
                purl=a.get("purl", ""),
                licenses=_license_values(a.get("licenses")),
                locations=_location_paths(a.get("locations")),
            )
        )
    packages.sort(key=lambda p: (p.type, p.name.lower(), p.version))
    return packages


def _best_cvss(records) -> float | None:
    scores = []
    for c in records or []:
        s = (c.get("metrics") or {}).get("baseScore")
        if isinstance(s, (int, float)):
            scores.append(float(s))
    return max(scores) if scores else None


def _epss(vuln: dict) -> float | None:
    vals = [e.get("epss") for e in vuln.get("epss") or [] if isinstance(e.get("epss"), (int, float))]
    return max(vals) if vals else None


def parse_grype(data: dict) -> list[Vulnerability]:
    """grype matches -> Vulnerability 목록. 같은 (취약점, 패키지, 버전)은 하나로 합친다."""
    merged: dict[tuple, Vulnerability] = {}
    for m in data.get("matches", []):
        v = m.get("vulnerability", {})
        art = m.get("artifact", {})
        related = m.get("relatedVulnerabilities") or []

        description = v.get("description") or next(
            (r.get("description") for r in related if r.get("description")), ""
        )
        cvss = _best_cvss(v.get("cvss"))
        if cvss is None:
            cvss = _best_cvss([c for r in related for c in r.get("cvss") or []])
        fix = v.get("fix") or {}

        vuln = Vulnerability(
            id=v.get("id", ""),
            severity=v.get("severity") or "Unknown",
            package=art.get("name", ""),
            version=art.get("version", ""),
            pkg_type=art.get("type", ""),
            description=(description or "").strip(),
            cvss_score=cvss,
            epss=_epss(v),
            known_exploited=bool(v.get("knownExploited")),
            fix_versions=list(fix.get("versions") or []),
            fix_state=fix.get("state") or "unknown",
            urls=list(v.get("urls") or []),
            aliases=[r.get("id") for r in related if r.get("id") and r.get("id") != v.get("id")],
            locations=_location_paths(art.get("locations")),
        )

        key = (vuln.id, vuln.package, vuln.version)
        prev = merged.get(key)
        if prev is None:
            merged[key] = vuln
            continue
        # 중복 매치: 더 높은 심각도·정보를 유지하고 위치/별칭은 합친다
        if severity_rank(vuln.severity) > severity_rank(prev.severity):
            prev.severity = vuln.severity
        for attr in ("locations", "aliases", "fix_versions", "urls"):
            items = getattr(prev, attr)
            items.extend(x for x in getattr(vuln, attr) if x not in items)
        prev.cvss_score = max(filter(None, [prev.cvss_score, vuln.cvss_score]), default=None)
        prev.epss = max(filter(None, [prev.epss, vuln.epss]), default=None)
        prev.known_exploited = prev.known_exploited or vuln.known_exploited
        if vuln.fix_state == "fixed":
            prev.fix_state = "fixed"
        if not prev.description:
            prev.description = vuln.description
    return list(merged.values())


def descriptor_version(data: dict) -> str | None:
    return (data.get("descriptor") or {}).get("version")
