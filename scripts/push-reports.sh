#!/usr/bin/env bash
# 맥에서 만든 리포트를 안드로이드 공기계(보기 전용 서버)로 올린다. 저장소 폴더에서 실행:
#   scripts/push-reports.sh <폰 주소> [out 폴더]
#   <폰 주소>: Tailscale 앱에 보이는 폰 이름(예: galaxy-s10) 또는 100.x.y.z
#              로그인이 안 되면 Termux 에서 whoami 로 본 이름을 붙인다 (예: u0_a123@galaxy-s10)
set -euo pipefail
PHONE="${1:?사용법: scripts/push-reports.sh <폰 Tailscale 이름 또는 IP> [out 폴더]}"
OUT="${2:-out}"

cd "$OUT"
shopt -s nullglob
# report.html·report.json 만 보낸다 (syft·grype 원본과 AI 캐시는 보내지 않음)
files=(*/report.html */report.json)
if [ ${#files[@]} -eq 0 ]; then
  echo "올릴 리포트가 없습니다: $OUT (먼저 oss-lens scan 을 실행하세요)"
  exit 1
fi
tar -cf - "${files[@]}" | ssh -p 8022 "$PHONE" 'mkdir -p ~/oss-lens-reports && tar -xf - -C ~/oss-lens-reports'
echo "리포트 $(( ${#files[@]} / 2 ))개를 올렸습니다 → http://${PHONE#*@}:8765/"
