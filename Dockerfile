# syntax=docker/dockerfile:1.7
#
# Hermes' container is assembled from a completed managed release bundle.
# Supply the unpacked, verified bundle as a named BuildKit context:
#   docker build --build-context hermes_bundle=/path/to/bundle .
# There is deliberately no source/venv/frontend build fallback here. The
# release bundle is the single runtime artifact for releases and containers.
FROM hermes_bundle AS bundle

FROM ghcr.io/astral-sh/uv:0.11.6-python3.13-trixie@sha256:b3c543b6c4f23a5f2df22866bd7857e5d304b67a564f4feab6ac22044dde719b AS uv_source

FROM debian:13.4 AS final

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV HERMES_HOME=/opt/data
ENV HERMES_WRITE_SAFE_ROOT=/opt/data
ENV HERMES_DISABLE_LAZY_INSTALLS=1
ENV HERMES_LAZY_INSTALL_TARGET=/opt/data/lazy-packages
# The baked slot has a fixed local name. Runtime code still resolves it through
# current.txt; these two surface overrides follow the release-bundle layout.
ENV HERMES_WEB_DIST=/opt/hermes/versions/docker/ui/web/dist
ENV HERMES_TUI_DIR=/opt/hermes/versions/docker/ui/tui
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/data/ms-playwright
ENV PATH="/usr/local/bin:/opt/hermes/bin:/opt/hermes/versions/docker/runtime/venv/bin:/opt/hermes/versions/docker/runtime/node/bin:/opt/hermes/versions/docker/runtime/tools:/opt/data/.local/bin:${PATH}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates curl iputils-ping ripgrep ffmpeg gcc g++ make cmake \
      libffi-dev libolm-dev procps git openssh-client docker-cli xz-utils && \
    rm -rf /var/lib/apt/lists/*

# ---------- s6-overlay ----------
ARG TARGETARCH
ARG S6_OVERLAY_VERSION=3.2.3.0
ARG S6_OVERLAY_NOARCH_SHA256=b720f9d9340efc8bb07528b9743813c836e4b02f8693d90241f047998b4c53cf
ARG S6_OVERLAY_X86_64_SHA256=a93f02882c6ed46b21e7adb5c0add86154f01236c93cd82c7d682722e8840563
ARG S6_OVERLAY_AARCH64_SHA256=0952056ff913482163cc30e35b2e944b507ba1025d78f5becbb89367bf344581
ARG S6_OVERLAY_SYMLINKS_SHA256=a60dc5235de3ecbcf874b9c1f18d73263ab99b289b9329aa950e8729c4789f0e
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz /tmp/
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-symlinks-noarch.tar.xz /tmp/
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) s6_arch=x86_64; s6_sha="${S6_OVERLAY_X86_64_SHA256}" ;; \
      arm64) s6_arch=aarch64; s6_sha="${S6_OVERLAY_AARCH64_SHA256}" ;; \
      *) echo "Unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --retry 3 -o /tmp/s6-overlay-arch.tar.xz \
      "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-${s6_arch}.tar.xz"; \
    printf '%s  %s\n' "${S6_OVERLAY_NOARCH_SHA256}" /tmp/s6-overlay-noarch.tar.xz > /tmp/s6.sha256; \
    printf '%s  %s\n' "${S6_OVERLAY_SYMLINKS_SHA256}" /tmp/s6-overlay-symlinks-noarch.tar.xz >> /tmp/s6.sha256; \
    printf '%s  %s\n' "$s6_sha" /tmp/s6-overlay-arch.tar.xz >> /tmp/s6.sha256; \
    sha256sum -c /tmp/s6.sha256; \
    tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz; \
    tar -C / -Jxpf /tmp/s6-overlay-arch.tar.xz; \
    tar -C / -Jxpf /tmp/s6-overlay-symlinks-noarch.tar.xz; \
    rm /tmp/s6-overlay-*.tar.xz /tmp/s6.sha256; \
    ln -sf /init /usr/bin/tini

RUN useradd -u 10000 -m -d /opt/data hermes
COPY --chmod=0755 --from=uv_source /usr/local/bin/uv /usr/local/bin/uvx /usr/local/bin/

# ---------- Managed install ----------
# Keep the verified bundle byte-for-byte as an immutable slot. Stable launchers
# are copies of the bundle's native busybox-style binary; container glue lives
# elsewhere and never overwrites bin/hermes or bin/hermes-updater.
COPY --from=bundle / /opt/hermes/versions/docker/
RUN set -eu; \
    test -f /opt/hermes/versions/docker/manifest.json; \
    test -x /opt/hermes/versions/docker/bin/hermes; \
    test -x /opt/hermes/versions/docker/bin/hermes-updater; \
    mkdir -p /opt/hermes/bin /opt/data; \
    printf 'docker\n' > /opt/hermes/current.txt; \
    cp /opt/hermes/versions/docker/bin/hermes /opt/hermes/bin/hermes; \
    cp /opt/hermes/versions/docker/bin/hermes-updater /opt/hermes/bin/hermes-updater; \
    printf 'docker\n' > /opt/hermes/versions/docker/.install_method; \
    chmod -R a+rX,go-w /opt/hermes

# Container-only supervision and privilege-drop code is intentionally outside
# the signed slot. /usr/local/bin/hermes is the docker-exec shim; it delegates
# to the preserved native stable launcher at /opt/hermes/bin/hermes.
COPY --link --chmod=a+rX,go-w docker/ /opt/docker/
COPY --chmod=0755 docker/hermes-exec-shim.sh /usr/local/bin/hermes
COPY docker/s6-rc.d/ /etc/s6-overlay/s6-rc.d/
RUN mkdir -p /etc/cont-init.d && \
    printf '#!/command/with-contenv sh\nexec /opt/docker/stage2-hook.sh\n' > /etc/cont-init.d/01-hermes-setup && \
    chmod +x /etc/cont-init.d/01-hermes-setup
COPY --chmod=0755 docker/cont-init.d/015-supervise-perms /etc/cont-init.d/015-supervise-perms
COPY --chmod=0755 docker/cont-init.d/02-reconcile-profiles /etc/cont-init.d/02-reconcile-profiles

ARG HERMES_GIT_SHA=
RUN if [ -n "$HERMES_GIT_SHA" ]; then \
      printf '%s\n' "$HERMES_GIT_SHA" > /opt/hermes/versions/docker/.hermes_build_sha; \
    fi

WORKDIR /opt/hermes
VOLUME [ "/opt/data" ]
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD ["/opt/hermes/bin/hermes", "--version"]
ENTRYPOINT [ "/init", "/opt/docker/main-wrapper.sh" ]
CMD [ ]
