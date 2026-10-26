# vulnerable-sample (시연용)

oss-lens 시연 영상용 샘플 프로젝트입니다. **의도적으로 오래되고 취약한 버전**을 고정한 의존성 목록 파일만 들어 있으며, 라이브러리 코드는 포함하지 않습니다. 실제 프로젝트에 이 버전들을 쓰지 마세요.

| 파일 | 내용 | 시연 포인트 |
|------|------|-------------|
| `requirements.txt` | requests 2.19.0, Django 2.2.0, PyYAML 5.1 | 알려진 CVE 다수. requirements.txt에는 라이선스 정보가 없어 "라이선스 미확인"으로 표시됨 |
| `package.json` / `package-lock.json` | lodash 4.17.4, minimist 1.2.0, tinymce 7.0.0 | lodash·minimist 프로토타입 오염 취약점, tinymce 7(GPL-2.0-or-later) 라이선스 경고 |

syft는 `package.json`만으로는 의존성을 잡지 않고 lock 파일을 읽기 때문에 `package-lock.json`을 함께 둡니다 (lock 파일의 `license` 필드로 라이선스도 확인됨).

```bash
python -m osslens scan demo/vulnerable-sample -o report.html
```
