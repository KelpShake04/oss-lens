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
    """grype matches -> Vulnerability 목록. 같은 (취약점, 패키지, 버전)은 하나로 합친다.

    언어 패키지는 보통 GHSA 레코드로 매치되고, 그 설명은 한 줄 제목뿐이다
    ('Prototype Pollution in minimist'). 자세한 NVD 원문은 relatedVulnerabilities 의
    CVE 레코드에 있으므로 ID 는 CVE 로, 설명은 가장 긴 것으로 고른다.
    (grype --by-cve 는 ID 만 바꾸고 NVD 원문을 버리므로 쓰지 않는다.)
    """
    merged: dict[tuple, Vulnerability] = {}
    for m in data.get("matches", []):
        v = m.get("vulnerability", {})
        art = m.get("artifact", {})
        records = [v] + list(m.get("relatedVulnerabilities") or [])

        ids = [r.get("id") for r in records if r.get("id")]
        main_id = next((i for i in ids if i.startswith("CVE-")), ids[0] if ids else "")
        description = max((r.get("description") or "" for r in records), key=len)
        fix = v.get("fix") or {}
        urls = []
        for r in records:
            urls.extend(u for u in r.get("urls") or [] if u not in urls)

        vuln = Vulnerability(
            id=main_id,
            severity=v.get("severity") or "Unknown",
            package=art.get("name", ""),
            version=art.get("version", ""),
            pkg_type=art.get("type", ""),
            description=description.strip(),
            cvss_score=_best_cvss([c for r in records for c in r.get("cvss") or []]),
            epss=max(filter(None, (_epss(r) for r in records)), default=None),
            known_exploited=any(r.get("knownExploited") for r in records),
            fix_versions=list(fix.get("versions") or []),
            fix_state=fix.get("state") or "unknown",
            urls=urls,
            aliases=[i for i in dict.fromkeys(ids) if i != main_id],
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
