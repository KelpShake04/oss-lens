"""라이선스 분류와 프로젝트 라이선스 대비 위험 규칙.

법률 자문이 아니라 '확인이 필요한 의존성'을 골라내기 위한 단순 규칙이다.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import LicenseFinding, Package

# 제약이 강한 순서. OR 는 가장 약한 쪽, AND 는 가장 강한 쪽을 택한다.
CATEGORIES = {
    "permissive": ("허용형", 0),
    "weak-copyleft": ("약한 카피레프트", 2),
    "strong-copyleft": ("강한 카피레프트", 3),
    "network-copyleft": ("네트워크 카피레프트", 4),
    "restricted": ("상업 이용 제한", 5),
    "unknown": ("확인 필요", 1),
}

PERMISSIVE_IDS = {
    "MIT", "MIT-0", "ISC", "0BSD", "Zlib", "Unlicense", "CC0-1.0", "BSL-1.0",
    "PSF-2.0", "Python-2.0", "Python-2.0.1", "X11", "WTFPL", "BlueOak-1.0.0",
    "Artistic-2.0", "PostgreSQL", "NCSA", "HPND", "OpenSSL", "CC-BY-3.0",
    "CC-BY-4.0", "Unicode-DFS-2016", "Unicode-3.0", "Public-Domain", "BSD",
}

# 흔한 비 SPDX 표기 (소문자 기준)
ALIASES = {
    "mit license": "MIT",
    "the mit license": "MIT",
    "mit/x11": "MIT",
    "expat": "MIT",
    "apache": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache license version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "asl 2.0": "Apache-2.0",
    "bsd license": "BSD",
    "new bsd license": "BSD-3-Clause",
    "modified bsd license": "BSD-3-Clause",
    "3-clause bsd license": "BSD-3-Clause",
    "simplified bsd license": "BSD-2-Clause",
    "isc license": "ISC",
    "isc license (iscl)": "ISC",
    "python software foundation license": "PSF-2.0",
    "psf": "PSF-2.0",
    "psfl": "PSF-2.0",
    "public domain": "Public-Domain",
    "the unlicense": "Unlicense",
    "unlicensed": "UNLICENSED",  # npm: 사용 허락 없음(비공개) — Unlicense 와 다르다
}

_TOKEN = re.compile(r"\(|\)|[^\s()]+")


def _category_of_id(lic: str) -> str:
    """단일 라이선스 표기의 분류."""
    s = lic.strip()
    s = ALIASES.get(s.lower(), s)
    u = s.upper()

    if u == "UNLICENSED":
        return "restricted"
    if u.startswith("LICENSEREF-") or "SEE LICENSE" in u:
        return "unknown"
    if s in PERMISSIVE_IDS or u.startswith(("BSD-", "APACHE-", "MIT", "CC0", "ZPL-", "UPL-", "AFL-")):
        return "permissive"
    if u.startswith(("AGPL", "SSPL")):
        return "network-copyleft"
    if u.startswith(("LGPL", "MPL-", "EPL-", "CDDL-", "EUPL-", "CPL-", "MS-RL", "OSL-")):
        return "weak-copyleft"
    if u.startswith("GPL"):
        return "strong-copyleft"
    if u.startswith(("CC-BY-NC", "CC-BY-ND", "BUSL-", "ELASTIC-", "POLYFORM-", "COMMONS-CLAUSE")):
        return "restricted"

    # PyPI classifier 같은 자연어 표기
    low = s.lower()
    if "affero" in low or "agpl" in low:
        return "network-copyleft"
    if "lesser" in low or "library general public" in low or "lgpl" in low:
        return "weak-copyleft"
    if "general public license" in low or re.search(r"\bgpl", low):
        return "strong-copyleft"
    if "mozilla" in low or "eclipse public" in low:
        return "weak-copyleft"
    if re.search(r"\b(mit|bsd|apache|isc)\b", low) or "public domain" in low:
        return "permissive"
    if "non-commercial" in low or "noncommercial" in low or "proprietary" in low:
        return "restricted"
    return "unknown"


def _rank(cat: str) -> int:
    return CATEGORIES[cat][1]


def _pick(cats: list[str], most_restrictive: bool) -> str:
    known = [c for c in cats if c != "unknown"]
    if not known:
        return "unknown"
    return (max if most_restrictive else min)(known, key=_rank)


def _parse(tokens: list[str], i: int = 0) -> tuple[str, int]:
    """SPDX 식 파서. 우선순위는 WITH > AND > OR. (분류, 다음 토큰 위치)를 반환."""
    or_terms: list[str] = []
    and_terms: list[str] = []
    cur: str | None = None
    while i < len(tokens):
        t = tokens[i]
        if t == "(":
            cur, i = _parse(tokens, i + 1)
            continue
        if t == ")":
            i += 1
            break
        if t == "AND":
            and_terms.append(cur or "unknown")
            cur = None
        elif t == "OR":
            and_terms.append(cur or "unknown")
            or_terms.append(_pick(and_terms, most_restrictive=True))
            and_terms, cur = [], None
        elif t == "WITH":
            # GPL + 링크 예외(Classpath, GCC 등)는 약한 카피레프트 수준으로 본다
            if cur == "strong-copyleft":
                cur = "weak-copyleft"
            i += 1  # 예외 이름 건너뜀
        else:
            cur = _category_of_id(t)
        i += 1
    and_terms.append(cur or "unknown")
    or_terms.append(_pick(and_terms, most_restrictive=True))
    return _pick(or_terms, most_restrictive=False), i


# SPDX 연산자는 대문자. "GPLv2 or later" 같은 자연어 표기와 구분하려고 대소문자를 구분한다.
_SPDX_OPERATOR = re.compile(r"\s(AND|OR|WITH)\s")


def classify(expr: str) -> str:
    """라이선스 표기(SPDX 식 또는 자연어) -> CATEGORIES 키."""
    expr = (expr or "").strip()
    if not expr:
        return "unknown"
    if not _SPDX_OPERATOR.search(expr):
        return _category_of_id(expr.strip("()"))
    return _parse(_TOKEN.findall(expr))[0]


def package_category(pkg: Package) -> str:
    """여러 라이선스가 따로 표기된 경우 보수적으로 가장 제약이 강한 쪽을 택한다."""
    return _pick([classify(lic) for lic in pkg.licenses], most_restrictive=True)


# --- 프로젝트 라이선스 감지 -------------------------------------------------

_LICENSE_FILES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING", "COPYING.md")

_FILE_SIGNATURES = [
    ("gnu affero general public license", "AGPL-3.0"),
    ("gnu lesser general public license", "LGPL-3.0"),
    ("mozilla public license", "MPL-2.0"),
    ("apache license", "Apache-2.0"),
    ("gnu general public license", "GPL"),
    ("permission is hereby granted, free of charge", "MIT"),
    ("redistribution and use in source and binary forms", "BSD-3-Clause"),
    ("this is free and unencumbered software", "Unlicense"),
    ("permission to use, copy, modify, and/or distribute", "ISC"),
]


def detect_project_license(root: Path) -> str | None:
    for name in _LICENSE_FILES:
        f = root / name
        if not f.is_file():
            continue
        head = f.read_text(encoding="utf-8", errors="ignore")[:4000].lower()
        for sig, lic in _FILE_SIGNATURES:
            if sig in head:
                if lic == "GPL":
                    return "GPL-3.0" if "version 3" in head else "GPL-2.0"
                return lic
    return None


# --- 위험 규칙 --------------------------------------------------------------


def _finding(pkg: Package, cat: str, level: str, reason: str, action: str) -> LicenseFinding:
    return LicenseFinding(
        package=pkg.name,
        version=pkg.version,
        license=" / ".join(pkg.licenses) if pkg.licenses else "(표기 없음)",
        category=cat,
        level=level,
        reason=reason,
        action=action,
    )


def evaluate(packages: list[Package], project_license: str | None) -> list[LicenseFinding]:
    """프로젝트 라이선스 기준으로 위험한 의존성 라이선스를 찾는다.

    project_license 가 없으면 '소스 비공개 배포(상용)' 를 가정한다.
    """
    proj_cat = classify(project_license) if project_license else None
    proj_is_gpl = proj_cat in ("strong-copyleft", "network-copyleft")
    proj_is_agpl = proj_cat == "network-copyleft"
    proj_label = f"프로젝트 라이선스({project_license or '비공개/상용 배포 가정'})와 충돌"

    findings = []
    for pkg in packages:
        cat = package_category(pkg)
        if cat == "permissive":
            continue
        if cat == "network-copyleft":
            if proj_is_agpl:
                findings.append(_finding(pkg, cat, "low",
                    "프로젝트도 AGPL 계열이라 호환됩니다.",
                    "저작권·라이선스 고지만 유지하세요."))
            else:
                findings.append(_finding(pkg, cat, "high",
                    f"AGPL 계열은 네트워크로 서비스만 제공해도 전체 소스 공개 의무가 생깁니다. ({proj_label})",
                    "대체 라이브러리로 교체하거나, 서비스 전체를 AGPL로 공개할지 결정하세요."))
        elif cat == "strong-copyleft":
            if proj_is_gpl:
                findings.append(_finding(pkg, cat, "low",
                    "프로젝트도 GPL 계열입니다. GPL-2.0-only 와 GPL-3.0 은 서로 호환되지 않으니 버전을 확인하세요.",
                    "의존성의 GPL 버전(only / or-later)을 확인하세요."))
            else:
                findings.append(_finding(pkg, cat, "high",
                    f"GPL 계열을 포함해 배포하면 프로젝트 전체를 GPL로 소스 공개해야 합니다. ({proj_label})",
                    "MIT·Apache-2.0 등 허용형 대체 라이브러리를 찾거나, 배포 형태(내부용/서버 전용)를 검토하세요."))
        elif cat == "weak-copyleft":
            is_lgpl = any("LGPL" in lic.upper() or "LESSER" in lic.upper() for lic in pkg.licenses)
            if is_lgpl:
                findings.append(_finding(pkg, cat, "medium",
                    "LGPL은 동적 링크로 쓰면 괜찮지만, 정적 링크·수정 배포 시 해당 부분 소스 공개 의무가 있습니다.",
                    "수정하지 말고 동적 링크(별도 패키지)로 사용하세요. 고지문을 포함하세요."))
            else:
                findings.append(_finding(pkg, cat, "low",
                    "MPL·EPL 등은 수정한 파일만 공개하면 됩니다.",
                    "라이브러리 파일을 직접 수정했다면 그 파일을 공개하세요. 고지문을 포함하세요."))
        elif cat == "restricted":
            findings.append(_finding(pkg, cat, "high",
                "상업적 이용 제한·비공개(UNLICENSED) 등 사용 허락이 제한된 라이선스입니다.",
                "라이선스 원문을 확인하고 필요하면 별도 계약을 맺거나 대체하세요."))
        else:
            findings.append(_finding(pkg, cat, "info",
                "라이선스 정보를 찾지 못했거나 알 수 없는 표기입니다.",
                "패키지 저장소(npm·PyPI 등)에서 라이선스를 직접 확인하세요."))

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: (order[f.level], f.package.lower()))
    return findings


def category_counts(packages: list[Package]) -> dict[str, int]:
    counts = {k: 0 for k in CATEGORIES}
    for pkg in packages:
        counts[package_category(pkg)] += 1
    return counts
