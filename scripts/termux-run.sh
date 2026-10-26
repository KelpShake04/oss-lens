#!/usr/bin/env bash
# 안드로이드 공기계(Termux)에서 보기 전용 웹 서버를 켠다.
# Tailscale 이 켜져 있으면 Tailscale 주소(100.x.y.z)에만 열어, 같은 Wi-Fi 의 다른 사람에게는 보이지 않게 한다.
set -euo pipefail
cd ~/oss-lens
termux-wake-lock 2>/dev/null || true  # 화면이 꺼져도 계속 동작
sshd 2>/dev/null || true              # 맥에서 리포트를 올릴 때 쓰는 SSH (포트 8022, 이미 켜져 있으면 무시)

# Tailscale DNS(100.100.100.100) 쪽으로 나가는 인터페이스 주소 = 이 폰의 Tailscale 주소 (UDP connect 는 패킷을 보내지 않음)
TS_IP=$(python - <<'PY'
import socket
try:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("100.100.100.100", 53))
        ip = s.getsockname()[0]
    print(ip if ip.startswith("100.") else "")
except OSError:
    print("")
PY
)

if [ -n "$TS_IP" ]; then
  HOST="$TS_IP"
else
  echo "! Tailscale 주소를 찾지 못했습니다. Tailscale 앱이 켜져 있는지 확인하세요. (임시로 같은 Wi-Fi 에 엽니다)"
  HOST=0.0.0.0
fi
exec python -m oss_lens web --view-only --host "$HOST" --port 8765 --no-browser -o ~/oss-lens-reports
