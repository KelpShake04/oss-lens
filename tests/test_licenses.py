import pytest

from oss_lens.licenses import classify, detect_project_license, evaluate, package_category
from oss_lens.models import Package


@pytest.mark.parametrize("expr,expected", [
    ("MIT", "permissive"),
    ("Apache-2.0", "permissive"),
    ("BSD-3-Clause", "permissive"),
    ("Apache 2.0", "permissive"),
    ("BSD License", "permissive"),
    ("HPND", "permissive"),
    ("GPL-2.0-or-later", "strong-copyleft"),
    ("GPL-3.0-only", "strong-copyleft"),
    ("AGPL-3.0", "network-copyleft"),
    ("SSPL-1.0", "network-copyleft"),
    ("LGPL-3.0-or-later", "weak-copyleft"),
    ("MPL-2.0", "weak-copyleft"),
    ("BUSL-1.1", "restricted"),
    ("CC-BY-NC-4.0", "restricted"),
    ("UNLICENSED", "restricted"),  # npm 비공개 표기
    ("Unlicense", "permissive"),
    ("SEE LICENSE IN LICENSE.txt", "unknown"),
    ("", "unknown"),
    # PyPI classifier 등 자연어 표기
    ("GNU General Public License v2 or later (GPLv2+)", "strong-copyleft"),
    ("GNU Lesser General Public License v3 (LGPLv3)", "weak-copyleft"),
    ("GNU Affero General Public License v3", "network-copyleft"),
    ("Mozilla Public License 2.0 (MPL 2.0)", "weak-copyleft"),
    # SPDX 식
    ("(BSD-3-Clause OR GPL-2.0)", "permissive"),
    ("MIT AND GPL-3.0-only", "strong-copyleft"),
    ("(MIT OR Apache-2.0) AND LGPL-2.1-only", "weak-copyleft"),
    ("GPL-2.0-only WITH Classpath-exception-2.0", "weak-copyleft"),
    ("Apache-2.0 WITH LLVM-exception", "permissive"),
    ("LicenseRef-custom OR MIT", "permissive"),
])
def test_classify(expr, expected):
    assert classify(expr) == expected


def test_package_category_is_conservative_for_multiple_entries():
    assert package_category(Package("a", "1", "python", licenses=["MIT", "GPL-3.0"])) == "strong-copyleft"
    assert package_category(Package("a", "1", "python")) == "unknown"


def _pkgs():
    return [
        Package("ok", "1", "npm", licenses=["MIT"]),
        Package("gpl", "1", "npm", licenses=["GPL-2.0-or-later"]),
        Package("agpl", "1", "npm", licenses=["AGPL-3.0-only"]),
        Package("lgpl", "1", "npm", licenses=["LGPL-3.0-or-later"]),
        Package("mpl", "1", "npm", licenses=["MPL-2.0"]),
        Package("nc", "1", "npm", licenses=["CC-BY-NC-4.0"]),
        Package("none", "1", "python"),
    ]


def test_evaluate_closed_source_project():
    levels = {f.package: f.level for f in evaluate(_pkgs(), None)}
    assert "ok" not in levels
    assert levels == {"gpl": "high", "agpl": "high", "nc": "high", "lgpl": "medium", "mpl": "low", "none": "info"}


def test_evaluate_findings_sorted_by_level():
    order = [f.level for f in evaluate(_pkgs(), None)]
    assert order == sorted(order, key=["high", "medium", "low", "info"].index)


def test_evaluate_gpl_project_accepts_gpl_deps():
    levels = {f.package: f.level for f in evaluate(_pkgs(), "GPL-3.0-only")}
    assert levels["gpl"] == "low"
    assert levels["agpl"] == "high"  # GPL 프로젝트라도 AGPL 은 별도 의무


def test_evaluate_agpl_project():
    levels = {f.package: f.level for f in evaluate(_pkgs(), "AGPL-3.0-only")}
    assert levels["gpl"] == "low"
    assert levels["agpl"] == "low"


def test_evaluate_reason_mentions_project_license():
    f = next(f for f in evaluate(_pkgs(), "MIT") if f.package == "gpl")
    assert "MIT" in f.reason


@pytest.mark.parametrize("text,expected", [
    ("Apache License\nVersion 2.0, January 2004", "Apache-2.0"),
    ("MIT License\n\nPermission is hereby granted, free of charge, to any person", "MIT"),
    ("GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007", "GPL-3.0"),
    ("GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991", "GPL-2.0"),
    ("GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3", "AGPL-3.0"),
    ("Copyright me. All rights reserved.", None),
])
def test_detect_project_license(tmp_path, text, expected):
    (tmp_path / "LICENSE").write_text(text)
    assert detect_project_license(tmp_path) == expected


def test_detect_project_license_missing(tmp_path):
    assert detect_project_license(tmp_path) is None
