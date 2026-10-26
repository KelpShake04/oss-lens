"""syft(SBOM)·grype(취약점) 실행 래퍼."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


class ScanError(RuntimeError):
    pass


INSTALL_HINT = {
    "syft": "brew install syft  (또는 https://github.com/anchore/syft#installation)",
    "grype": "brew install grype  (또는 https://github.com/anchore/grype#installation)",
}


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise ScanError(f"'{name}' 실행 파일을 찾을 수 없습니다. 설치: {INSTALL_HINT.get(name, name)}")
    return path


def tool_version(name: str) -> str | None:
    path = shutil.which(name)
    if not path:
        return None
    try:
        out = subprocess.run([path, "version", "-o", "json"], capture_output=True, text=True, timeout=30)
        return json.loads(out.stdout).get("version")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


# syft 가 패키지 이름·버전으로 공개 저장소에서 라이선스를 조회하게 하는 설정 (코드는 전송하지 않음)
REMOTE_LICENSE_ENV = {
    "SYFT_PYTHON_SEARCH_REMOTE_LICENSES": "true",
    "SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES": "true",
    "SYFT_GOLANG_SEARCH_REMOTE_LICENSES": "true",
}


def _run(cmd: list[str], timeout: int, env: dict | None = None) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            env={**os.environ, **env} if env else None,
        )
    except subprocess.TimeoutExpired as e:
        raise ScanError(f"시간 초과({timeout}초): {' '.join(cmd)}") from e
    if proc.returncode != 0:
        raise ScanError(f"실행 실패 (exit {proc.returncode}): {' '.join(cmd)}\n{proc.stderr.strip()}")
    return proc


def run_syft(target: Path, out_path: Path, remote_licenses: bool = False, timeout: int = 900) -> dict:
    """target 폴더의 SBOM(syft-json)을 만들어 out_path에 저장하고 반환."""
    syft = require_tool("syft")
    _run(
        [syft, "scan", f"dir:{target}", "-o", f"syft-json={out_path}", "-q"],
        timeout,
        env=REMOTE_LICENSE_ENV if remote_licenses else None,
    )
    return json.loads(out_path.read_text(encoding="utf-8"))


def run_grype(sbom_path: Path, out_path: Path, timeout: int = 900) -> dict:
    """SBOM을 grype로 검사.

    --by-cve 는 쓰지 않는다: ID 만 CVE 로 바꾸고 자세한 NVD 설명을 버린다.
    CVE 기준 정리는 parsers.parse_grype 가 한다.
    """
    grype = require_tool("grype")
    proc = _run([grype, f"sbom:{sbom_path}", "-o", "json", "-q"], timeout)
    out_path.write_text(proc.stdout, encoding="utf-8")
    return json.loads(proc.stdout)


def clone_github(url: str) -> Path:
    """GitHub 저장소를 임시 폴더에 얕게 복제. 호출자가 정리 책임."""
    git = shutil.which("git")
    if not git:
        raise ScanError("GitHub URL 입력에는 git이 필요합니다.")
    dest = Path(tempfile.mkdtemp(prefix="oss-lens-"))
    _run([git, "clone", "--depth", "1", "--quiet", url, str(dest / "repo")], timeout=600)
    return dest / "repo"
