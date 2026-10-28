# oss-lens 실행 이미지: Python + syft + grype + git. LLM(Ollama)은 호스트 것을 OLLAMA_HOST 로 쓴다.
FROM python:3.12-slim

ARG SYFT_VERSION=1.55.0
ARG GRYPE_VERSION=0.121.0
ARG TARGETARCH

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git \
 && rm -rf /var/lib/apt/lists/*

# 공식 릴리스 tarball 을 받아 checksums.txt 로 sha256 검증 후 설치
RUN set -eu; arch="${TARGETARCH:-$(dpkg --print-architecture)}"; cd /tmp; \
    for t in "syft:${SYFT_VERSION}" "grype:${GRYPE_VERSION}"; do \
      n="${t%%:*}"; v="${t##*:}"; f="${n}_${v}_linux_${arch}.tar.gz"; \
      base="https://github.com/anchore/${n}/releases/download/v${v}"; \
      curl -fsSLO "${base}/${f}"; curl -fsSLO "${base}/${n}_${v}_checksums.txt"; \
      grep " ${f}\$" "${n}_${v}_checksums.txt" | sha256sum -c -; \
      tar -xzf "${f}" -C /usr/local/bin "${n}"; rm -f /tmp/*; \
    done; \
    syft version >/dev/null; grype version >/dev/null

WORKDIR /opt/oss-lens
COPY pyproject.toml README.md LICENSE ./
COPY oss_lens ./oss_lens
COPY examples ./examples
RUN pip install --no-cache-dir .

RUN useradd --create-home --uid 1000 app \
 && mkdir -p /cache/grype /work/out \
 && chown -R app:app /cache /work
USER app
WORKDIR /work

# grype 취약점 DB 는 볼륨(/cache/grype)에 받아 두고 재사용. 결과는 /work/out/<이름>/
ENV GRYPE_DB_CACHE_DIR=/cache/grype \
    OLLAMA_HOST=http://host.docker.internal:11434 \
    PYTHONUNBUFFERED=1
VOLUME ["/cache/grype", "/work/out"]
EXPOSE 8765

ENTRYPOINT ["oss-lens"]
CMD ["--help"]
