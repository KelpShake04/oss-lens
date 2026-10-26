"""리포트 전 단계에서 공유하는 데이터 구조."""

from __future__ import annotations

from dataclasses import dataclass, field

# grype 심각도 순서 (높을수록 위험)
SEVERITY_ORDER = ["Unknown", "Negligible", "Low", "Medium", "High", "Critical"]
SEVERITY_KO = {
    "Critical": "치명",
    "High": "높음",
    "Medium": "중간",
    "Low": "낮음",
    "Negligible": "무시 가능",
    "Unknown": "미상",
}

# 라이선스 위험 등급
LICENSE_LEVELS = ["info", "low", "medium", "high"]
LICENSE_LEVEL_KO = {"high": "높음", "medium": "중간", "low": "낮음", "info": "확인 필요"}


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


@dataclass
class Package:
    name: str
    version: str
    type: str  # syft 패키지 타입: npm, python, go-module, java-archive ...
    purl: str = ""
    licenses: list[str] = field(default_factory=list)
    locations: list[str] = field(default_factory=list)


@dataclass
class Vulnerability:
    id: str
    severity: str
    package: str
    version: str
    pkg_type: str
    description: str = ""
    cvss_score: float | None = None
    epss: float | None = None  # 30일 내 악용 확률 (0~1)
    known_exploited: bool = False  # CISA KEV 등재 여부
    fix_versions: list[str] = field(default_factory=list)
    fix_state: str = "unknown"  # fixed / not-fixed / wont-fix / unknown
    urls: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    locations: list[str] = field(default_factory=list)
    score: float = 0.0  # risk.py 에서 계산

    @property
    def severity_ko(self) -> str:
        return SEVERITY_KO.get(self.severity, self.severity)


@dataclass
class LicenseFinding:
    package: str
    version: str
    license: str  # 원본 표기
    category: str  # licenses.CATEGORIES 키
    level: str  # info / low / medium / high
    reason: str
    action: str

    @property
    def level_ko(self) -> str:
        return LICENSE_LEVEL_KO.get(self.level, self.level)


@dataclass
class Explanation:
    summary: str
    impact: str
    action: str
    source: str  # "llm" 또는 "rule"


@dataclass
class Report:
    target: str
    project_license: str | None
    packages: list[Package]
    vulnerabilities: list[Vulnerability]
    license_findings: list[LicenseFinding]
    explanations: dict[str, Explanation]  # key: risk.vuln_key()
    top_keys: list[str]
    generated_at: str
    tool_versions: dict[str, str] = field(default_factory=dict)
    llm_model: str | None = None
    notes: list[str] = field(default_factory=list)
