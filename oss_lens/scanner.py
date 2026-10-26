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


_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "out", "dist", "build"}
_NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")


def _walk(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        yield Path(dirpath), set(filenames)


def first_party_packages(root: Path) -> set[tuple[str, str]]:
    """package-lock.json 에 적힌 프로젝트 자신(루트·워크스페이스)의 (이름, 버전).

    배포 주소(resolved)가 없다는 것만으로는 판단할 수 없다: 다른 패키지에 묶여 배포되는
    의존성(inBundle)도 resolved 가 비어 있다.
    """
    found = set()
    for d, files in _walk(root):
        for lock in ("package-lock.json", "npm-shrinkwrap.json"):
            if lock not in files:
                continue
            try:
                data = json.loads((d / lock).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if data.get("name"):
                found.add((data["name"], data.get("version", "")))
            for key, entry in (data.get("packages") or {}).items():
                if key and "node_modules/" not in key and entry.get("name"):  # 워크스페이스
                    found.add((entry["name"], entry.get("version", "")))
    return found


def coverage_gaps(root: Path, limit: int = 5) -> list[str]:
    """syft 가 의존성을 찾지 못하는 경우 (검사에서 조용히 빠지는 것을 알리기 위해)."""
    unlocked, unpinned = [], []
    for d, files in _walk(root):
        rel_dir = d.relative_to(root).as_posix()
        prefix = "" if rel_dir == "." else f"/{rel_dir}"
        if "package.json" in files and not files.intersection(_NPM_LOCKS):
            unlocked.append(f"{prefix}/package.json")
        for name in sorted(files):
            if not (name.startswith("requirements") and name.endswith(".txt")):
                continue
            try:
                lines = (d / name).read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for line in lines:
                spec = line.split("#", 1)[0].strip()
                if spec and not spec.startswith("-") and "==" not in spec and "@" not in spec:
                    unpinned.append(f"{spec} ({prefix}/{name})")
    notes = []
    if unlocked:
        notes.append(
            f"lock 파일이 없는 package.json {len(unlocked)}개는 의존성을 찾지 못했습니다: "
            f"{', '.join(unlocked[:limit])}. npm install 로 package-lock.json 을 만든 뒤 다시 검사하세요."
        )
    if unpinned:
        notes.append(
            f"버전을 고정하지 않은(== 없는) requirements 항목 {len(unpinned)}개는 검사에서 빠졌습니다: "
            f"{', '.join(unpinned[:limit])}. pip freeze 로 버전을 고정하면 검사할 수 있습니다."
        )
    return notes


def clone_github(url: str) -> Path:
    """GitHub 저장소를 임시 폴더에 얕게 복제. 호출자가 정리 책임."""
    git = shutil.which("git")
    if not git:
        raise ScanError("GitHub URL 입력에는 git이 필요합니다.")
    dest = Path(tempfile.mkdtemp(prefix="oss-lens-"))
    _run([git, "clone", "--depth", "1", "--quiet", url, str(dest / "repo")], timeout=600)
    return dest / "repo"
