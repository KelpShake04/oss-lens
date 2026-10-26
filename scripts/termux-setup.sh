#!/usr/bin/env bash
# 안드로이드 공기계(Termux)에 oss-lens 보기 전용 웹 서버를 설치한다. 폰의 Termux 에서 실행:
#   pkg install -y git && git clone https://github.com/KelpShake04/oss-lens ~/oss-lens && bash ~/oss-lens/scripts/termux-setup.sh
#   (저장소가 비공개면 git clone 대신: pkg install -y gh && gh auth login && gh repo clone KelpShake04/oss-lens ~/oss-lens)
# 자세한 안내: docs/deploy-android.md
set -euo pipefail

echo "[1/4] 패키지 설치 (python, git, openssh)"
pkg update -y
pkg install -y python git openssh

echo "[2/4] 리포트 폴더 만들기: ~/oss-lens-reports"
mkdir -p ~/oss-lens-reports

echo "[3/4] 폰을 켤 때 자동 실행 등록 (Termux:Boot 앱을 설치하고 한 번 열어 두면 동작)"
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/oss-lens <<'EOF'
#!/data/data/com.termux/files/usr/bin/sh
termux-wake-lock
sshd
nohup bash ~/oss-lens/scripts/termux-run.sh > ~/oss-lens.log 2>&1 &
EOF
chmod +x ~/.termux/boot/oss-lens

echo "[4/4] 맥에서 리포트를 올릴 때 쓸 SSH 비밀번호를 정합니다 (나중에 passwd 로 바꿀 수 있음)"
passwd || echo "  비밀번호 설정을 건너뛰었습니다. 맥의 SSH 키를 ~/.ssh/authorized_keys 에 넣어도 됩니다."

cat <<EOF

설치 끝. 서버 켜기:
  bash ~/oss-lens/scripts/termux-run.sh
EOF
