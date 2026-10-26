# 안드로이드 공기계에 리포트 웹 서버 올리기

폰에는 **웹(리포트 보기)만** 올리고, 검사는 지금처럼 맥에서 한다. 폰에서 syft·grype·AI 를 돌리기엔 무겁기 때문이다.
접속은 Tailscale(내 기기끼리만 연결되는 사설망)로 하므로, 밖에서도 내 기기로는 보이고 다른 사람에게는 보이지 않는다.

```
맥: oss-lens scan → scripts/push-reports.sh ──(Tailscale·SSH)──▶ 폰: oss-lens web --view-only
                                                               ▲
                                    어디서나 내 기기(Tailscale 켬) ──┘  http://<폰 이름>:8765
```

## 1. 폰 준비
- Wi-Fi 에 연결하고 충전기를 꽂아 둔다
- **Tailscale** 앱 설치 → 로그인 (맥과 같은 계정)
- **Termux** 설치: [F-Droid](https://f-droid.org/packages/com.termux/) 판 (Termux 공식 권장)
- (선택) 폰을 다시 켰을 때 자동 실행: **Termux:Boot** 를 Termux 와 같은 곳(F-Droid)에서 설치하고 한 번 열어 둔다
- 설정 → 애플리케이션 → Termux → 배터리 → **제한 없음** (화면이 꺼져도 서버가 멈추지 않게)

## 2. 폰에서 설치
Termux 를 열고 입력한다. 중간에 SSH 비밀번호를 두 번 묻는다 (맥에서 리포트를 올릴 때 쓴다).
```bash
pkg install -y git && git clone https://github.com/KelpShake04/oss-lens ~/oss-lens && bash ~/oss-lens/scripts/termux-setup.sh
```

## 3. 폰에서 서버 켜기
```bash
bash ~/oss-lens/scripts/termux-run.sh
```
`다른 기기에서 접속: http://100.x.y.z:8765/` 가 나오면 성공이다. Termux 는 닫지 말고 홈 버튼으로 나간다.
Tailscale 주소에만 열리므로 같은 Wi-Fi 의 다른 사람은 접속할 수 없다.

## 4. 맥에서 리포트 올리기
맥에도 Tailscale 을 설치하고 같은 계정으로 로그인한다. 폰 이름은 Tailscale 앱의 기기 목록에 보인다 (예: `galaxy-s10`).
```bash
cd ~/oss-lens && source .venv/bin/activate
oss-lens scan https://github.com/OWASP/NodeGoat        # 평소처럼 검사
scripts/push-reports.sh galaxy-s10                     # out/ 의 리포트를 폰으로 (report.html·report.json 만)
```
비밀번호를 매번 넣기 싫으면 한 번만: `ssh-copy-id -p 8022 galaxy-s10`

## 5. 어디서나 보기
Tailscale 을 켠 내 기기(폰·노트북)의 브라우저에서 `http://galaxy-s10:8765` (또는 `http://100.x.y.z:8765`).

## 업데이트
```bash
cd ~/oss-lens && git pull      # 폰 Termux 에서. 그다음 서버를 껐다 켠다 (Ctrl+C → termux-run.sh)
```

## 문제 해결
| 증상 | 확인할 것 |
|---|---|
| 주소가 안 열림 | 폰·접속 기기 모두 Tailscale 이 켜져 있는지, Termux 에서 서버가 돌고 있는지 |
| `Tailscale 주소를 찾지 못했습니다` | 폰의 Tailscale 앱을 켠 뒤 `termux-run.sh` 를 다시 실행 |
| 올리기에서 로그인 실패 | Termux 에서 `whoami` 로 본 이름을 붙여 `scripts/push-reports.sh u0_a123@galaxy-s10` |
| 올리기에서 연결 거부 | Termux 에서 `sshd` 실행 (termux-run.sh 가 켜 주지만 Termux 를 완전히 닫으면 꺼짐) |
| 화면이 꺼지면 접속 안 됨 | 배터리 최적화 해제(1단계), Termux 알림의 Acquire wakelock |
