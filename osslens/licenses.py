"""라이선스 위험 규칙.

카피레프트 계열과 라이선스 미확인 패키지를 찾아 한국어 설명을 붙인다.
법률 자문이 아니라 "검토가 필요한 항목"을 알려 주는 용도다.
"""

import re
from dataclasses import dataclass

# (규칙 키, 정규식, 위험도, 분류, 설명). 위에서부터 먼저 맞는 규칙을 쓴다.
# LGPL·AGPL이 GPL 정규식에도 걸리지 않도록 GPL 규칙은 앞에 L/A가 없는 경우만 잡는다.
LICENSE_RULES = [
    ("AGPL", re.compile(r"\bAGPL|AFFERO", re.I), "high", "강한 카피레프트 (네트워크)",
     "AGPL 계열: 이 라이브러리를 포함한 서비스를 네트워크로 제공하기만 해도 "
     "전체 소스 코드를 공개해야 할 수 있습니다. 상용·비공개 서비스라면 사용 전 반드시 검토하세요."),
    ("SSPL", re.compile(r"\bSSPL|SERVER SIDE PUBLIC", re.I), "high", "서비스 제공 제한",
     "SSPL: 이 소프트웨어를 서비스 형태로 제공하면 서비스 운영에 쓰인 모든 코드의 공개를 요구합니다. "
     "OSI 승인 오픈소스 라이선스가 아니므로 사용 전 법무 검토가 필요합니다."),
    ("LGPL", re.compile(r"\bLGPL|LESSER GENERAL PUBLIC|LIBRARY GENERAL PUBLIC", re.I), "medium",
     "약한 카피레프트",
     "LGPL 계열: 동적 링크로 사용하면 대체로 문제가 없지만, 라이브러리 자체를 수정하거나 "
     "정적 링크·번들링하면 해당 부분의 소스 공개 의무가 생길 수 있습니다."),
    ("GPL", re.compile(r"(?<![LA])GPL|GENERAL PUBLIC LICENSE", re.I), "high", "강한 카피레프트",
     "GPL 계열: 이 라이브러리와 결합해 배포하는 프로그램 전체를 GPL로 공개해야 할 수 있습니다. "
     "배포(앱·설치 파일 제공) 계획이 있다면 대체 라이브러리나 상용 라이선스를 검토하세요."),
]

UNKNOWN_VALUES = {"", "UNKNOWN", "NOASSERTION", "NONE", "UNLICENSED", "SEE LICENSE IN LICENSE"}
UNKNOWN_NOTE = (
    "라이선스 정보를 찾지 못했습니다. 라이선스가 없으면 원칙적으로 저작권자 허락 없이 "
    "사용·배포할 수 없으므로, 패키지 저장소나 원본 저장소에서 직접 확인하세요. "
    "(requirements.txt처럼 라이선스 정보가 없는 목록 파일만 있으면 이렇게 표시됩니다.)"
)
DUAL_NOTE = (
    " 단, 이 패키지는 다른 라이선스와 함께 제공되는 이중 라이선스(OR)이므로 "
    "허용 라이선스 쪽을 선택하면 의무를 피할 수 있습니다."
)

RISK_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass
class LicenseFinding:
    package: str
    version: str
    package_type: str
    license: str
    risk: str  # high / medium / low
    category: str
    note: str


def _match_rule(expr):
    for key, pattern, risk, category, note in LICENSE_RULES:
        if pattern.search(expr):
            return key, risk, category, note
    return None


def classify_license(expr):
    """하나의 라이선스 표현식을 분류한다. 문제 없으면 None."""
    expr = (expr or "").strip()
    if expr.upper() in UNKNOWN_VALUES:
        return "low", "라이선스 미확인", UNKNOWN_NOTE
    alternatives = [a.strip(" ()") for a in re.split(r"\s+OR\s+", expr, flags=re.I)]
    matched = [_match_rule(a) for a in alternatives]
    hits = [m for m in matched if m]
    if not hits:
        return None
    hits.sort(key=lambda m: RISK_ORDER[m[1]])
    _, risk, category, note = hits[0]
    if len(hits) < len(alternatives):
        # 카피레프트가 아닌 대안이 있는 이중 라이선스
        return "low", category + " (이중 라이선스)", note + DUAL_NOTE
    return risk, category, note


def check_licenses(packages):
    findings = []
    for pkg in packages:
        licenses = pkg.licenses or [""]
        results = []
        for lic in licenses:
            res = classify_license(lic)
            if res:
                results.append((lic, res))
        if not results:
            continue
        # 확인된 라이선스가 하나라도 있으면 "미확인" 항목은 무시한다.
        known = [r for r in results if r[1][1] != "라이선스 미확인"]
        if known:
            results = known
        elif len(results) < len(licenses):
            continue
        lic, (risk, category, note) = min(results, key=lambda r: RISK_ORDER[r[1][0]])
        findings.append(LicenseFinding(
            package=pkg.name,
            version=pkg.version,
            package_type=pkg.type,
            license=", ".join(pkg.licenses) if pkg.licenses else "(없음)",
            risk=risk,
            category=category,
            note=note,
        ))
    findings.sort(key=lambda f: (RISK_ORDER[f.risk], f.package.lower()))
    return findings
