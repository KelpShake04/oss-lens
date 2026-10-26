"""syft/grype 실행과 JSON 결과 파싱."""

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
_SEVERITY_RANK = {name.lower(): i for i, name in enumerate(SEVERITY_ORDER)}

INSTALL_HINT = {
    "syft": "설치: brew install syft  (또는 https://github.com/anchore/syft 릴리스)",
    "grype": "설치: brew install grype  (또는 https://github.com/anchore/grype 릴리스)",
}


class ScanError(Exception):
    """스캐너 실행 실패. 메시지는 사용자에게 그대로 보여준다."""


@dataclass
class Package:
    name: str
    version: str
    type: str
    licenses: list = field(default_factory=list)
    locations: list = field(default_factory=list)
    purl: str = ""


@dataclass
class Vulnerability:
    id: str
    package: str
    version: str
    package_type: str
    severity: str
    fixed_in: list = field(default_factory=list)
    description: str = ""
    aliases: list = field(default_factory=list)
    url: str = ""
    cvss: float = 0.0


def normalize_severity(value):
    if not value:
        return "Unknown"
    for name in SEVERITY_ORDER:
        if name.lower() == str(value).strip().lower():
            return name
    return "Unknown"


def severity_rank(value):
    return _SEVERITY_RANK.get(normalize_severity(value).lower(), len(SEVERITY_ORDER))


def sort_vulnerabilities(vulns):
    """심각도 높은 순, 같은 심각도면 CVSS 높은 순, 그다음 패키지·ID 순."""
    return sorted(vulns, key=lambda v: (severity_rank(v.severity), -v.cvss, v.package.lower(), v.id))


def _find_tool(name):
    path = shutil.which(name)
    if not path:
        raise ScanError(f"'{name}' 명령을 찾을 수 없습니다. {INSTALL_HINT[name]}")
    return path


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _run(cmd, tool):
    # 앱 업데이트 확인(외부 접속)은 끈다. grype 취약점 DB 갱신은 그대로 둔다.
    env = dict(os.environ, SYFT_CHECK_FOR_APP_UPDATE="false", GRYPE_CHECK_FOR_APP_UPDATE="false")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", env=env)
    except OSError as exc:
        raise ScanError(f"{tool} 실행 실패: {exc}") from exc
    if proc.returncode != 0:
        stderr = _ANSI.sub("", proc.stderr).strip().splitlines()
        tail = "\n".join(stderr[-5:]) if stderr else "(출력 없음)"
        hint = ""
        if tool == "grype" and "db" in tail.lower():
            hint = "\n힌트: 'grype db update'로 취약점 DB를 먼저 내려받으세요 (인터넷 연결 필요)."
        raise ScanError(f"{tool} 실행이 실패했습니다 (종료 코드 {proc.returncode}).\n{tail}{hint}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ScanError(f"{tool} 출력이 올바른 JSON이 아닙니다: {exc}") from exc


def run_syft(target):
    """폴더를 syft로 스캔해 SBOM(JSON dict)을 돌려준다."""
    if not os.path.isdir(target):
        raise ScanError(f"스캔 대상 폴더가 없습니다: {target}")
    syft = _find_tool("syft")
    return _run([syft, f"dir:{target}", "-o", "json", "-q"], "syft")


def run_grype(sbom):
    """syft SBOM을 임시 파일로 저장해 grype로 취약점을 찾는다."""
    grype = _find_tool("grype")
    fd, path = tempfile.mkstemp(prefix="osslens-sbom-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(sbom, fh)
        return _run([grype, f"sbom:{path}", "-o", "json"], "grype")
    finally:
        os.unlink(path)


def _license_values(raw):
    values = []
    for lic in raw or []:
        if isinstance(lic, str):
            value = lic
        elif isinstance(lic, dict):
            value = lic.get("spdxExpression") or lic.get("value") or ""
        else:
            continue
        value = value.strip()
        if value and value not in values:
            values.append(value)
    return values


def parse_syft(data):
    packages = []
    for art in data.get("artifacts") or []:
        packages.append(Package(
            name=str(art.get("name", "")),
            version=str(art.get("version", "")),
            type=str(art.get("type", "")),
            licenses=_license_values(art.get("licenses")),
            locations=[loc.get("path", "") for loc in art.get("locations") or [] if isinstance(loc, dict)],
            purl=str(art.get("purl", "")),
        ))
    packages.sort(key=lambda p: (p.name.lower(), p.version))
    return packages


def _max_cvss(*vuln_dicts):
    best = 0.0
    for vd in vuln_dicts:
        for c in vd.get("cvss") or []:
            try:
                best = max(best, float((c.get("metrics") or {}).get("baseScore") or 0))
            except (TypeError, ValueError):
                pass
    return best


def parse_grype(data):
    """grype JSON → Vulnerability 목록 (같은 ID·패키지·버전은 하나로 합침, 심각도 순 정렬)."""
    seen = {}
    for match in data.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        art = match.get("artifact") or {}
        related = [r for r in match.get("relatedVulnerabilities") or [] if isinstance(r, dict)]
        vid = str(vuln.get("id", "")).strip()
        if not vid:
            continue
        key = (vid, art.get("name"), art.get("version"))
        if key in seen:
            continue
        description = (vuln.get("description") or "").strip()
        if not description:
            description = next((r["description"].strip() for r in related if r.get("description")), "")
        aliases = []
        for r in related:
            rid = r.get("id")
            if rid and rid != vid and rid not in aliases:
                aliases.append(rid)
        fix = vuln.get("fix") or {}
        url = vuln.get("dataSource") or next(iter(vuln.get("urls") or []), "")
        seen[key] = Vulnerability(
            id=vid,
            package=str(art.get("name", "")),
            version=str(art.get("version", "")),
            package_type=str(art.get("type", "")),
            severity=normalize_severity(vuln.get("severity")),
            fixed_in=[str(v) for v in fix.get("versions") or []],
            description=description,
            aliases=aliases,
            url=str(url or ""),
            cvss=_max_cvss(vuln, *related),
        )
    return sort_vulnerabilities(seen.values())


def severity_counts(vulns):
    counts = {name: 0 for name in SEVERITY_ORDER}
    for v in vulns:
        counts[normalize_severity(v.severity)] += 1
    return counts


def tool_version(data):
    desc = data.get("descriptor") or {}
    return f"{desc.get('name', '?')} {desc.get('version', '?')}"
