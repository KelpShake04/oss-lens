# vulnerable-demo

oss-lens 시연용 프로젝트. **일부러 취약한 옛 버전과 주의가 필요한 라이선스를 넣었다. 실제로 설치·사용하지 말 것.**

```bash
oss-lens scan examples/vulnerable-demo
```

| 파일 | 들어 있는 것 |
|---|---|
| `requirements.txt` | Django 3.1.0, Jinja2 2.11.2, PyYAML 5.3.1, requests 2.25.0, urllib3 1.26.4, Pillow 8.0.0 |
| `package-lock.json` | lodash 4.17.15, minimist 1.2.5, ejs 3.1.6, axios 0.21.0, jsonwebtoken 8.5.1, node-forge 0.10.0 등 |

기대 결과
- 치명(Critical) 취약점: minimist(프로토타입 오염), ejs(템플릿 주입), PyYAML(임의 코드 실행) 등
- 라이선스 경고: `@ckeditor/ckeditor5-build-classic` (GPL-2.0-or-later, 비공개 배포 시 충돌),
  `@img/sharp-libvips-linux-x64` (LGPL-3.0-or-later)
- `node-forge` 는 `(BSD-3-Clause OR GPL-2.0)` 이중 라이선스라 허용형으로 판단
- `requirements.txt` 는 라이선스 표기가 없어 '확인 필요'로 나온다. `--remote-licenses` 를 쓰면 PyPI에서 조회

LICENSE 파일이 없으므로 '비공개/상용 배포' 프로젝트로 가정해 판단한다 (스타트업 앱 시나리오).
