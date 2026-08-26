# syntax=docker/dockerfile:1

# ---- build stage --------------------------------------------------------
FROM rust:1.96-slim-trixie AS build
WORKDIR /app

# Native build dependencies (reqwest -> openssl-sys needs OpenSSL headers).
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependency compilation separately from source.
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release && rm -rf src

COPY migrations ./migrations
COPY assets ./assets
COPY src ./src
# Touch main so cargo rebuilds with the real sources.
RUN touch src/main.rs && cargo build --release

# ---- runtime stage ------------------------------------------------------
# The runtime image bundles node (npx), uv (uvx), and go because stdio backend
# MCP servers are launched (and git-sourced ones built) as child processes
# inside this container.
FROM debian:trixie-slim AS runtime
WORKDIR /app

# `nftables` is used by the entrypoint to restrict sandbox-UID network egress;
# `mount` (util-linux) is already present and is used to remount /proc hidepid.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl xz-utils libssl3 git nftables \
    && rm -rf /var/lib/apt/lists/*

# Node.js (provides npx) — pinned to the current Active LTS line.
ENV NODE_VERSION=24.18.0
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) node_arch="x64" ;; \
      arm64) node_arch="arm64" ;; \
      *) echo "unsupported arch $arch" && exit 1 ;; \
    esac; \
    tarball="node-v${NODE_VERSION}-linux-${node_arch}.tar.xz"; \
    curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/${tarball}" -o /tmp/node.tar.xz; \
    # Verify the download against the release's signed SHASUMS before extracting.
    curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt" -o /tmp/SHASUMS256.txt; \
    grep " ${tarball}\$" /tmp/SHASUMS256.txt | sed 's#[^ ]*$#/tmp/node.tar.xz#' | sha256sum -c -; \
    tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 \
      --exclude='*/CHANGELOG.md' --exclude='*/LICENSE' --exclude='*/README.md'; \
    rm /tmp/node.tar.xz /tmp/SHASUMS256.txt; \
    node --version; npx --version

# uv (provides uv / uvx for Python-based MCP servers), via the official installer,
# pinned to a specific version for reproducible builds.
ENV UV_VERSION=0.11.26
RUN curl -LsSf "https://astral.sh/uv/${UV_VERSION}/install.sh" | env UV_INSTALL_DIR=/usr/local/bin sh \
    && uv --version && uvx --version

# Go toolchain, for building Go-based MCP servers from git sources at runtime
# (gitsrc.rs runs `go build` on demand). go.dev publishes per-file checksums
# rather than a SHASUMS file, so both arch digests are pinned here. Adds ~250MB
# unpacked. CGO_ENABLED/GOFLAGS are set per-invocation by the hub, not
# globally, so backend child processes are not polluted.
ENV GO_VERSION=1.26.5 \
    GO_SHA256_AMD64=5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053 \
    GO_SHA256_ARM64=fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) go_arch="amd64"; go_sha="$GO_SHA256_AMD64" ;; \
      arm64) go_arch="arm64"; go_sha="$GO_SHA256_ARM64" ;; \
      *) echo "unsupported arch $arch" && exit 1 ;; \
    esac; \
    tarball="go${GO_VERSION}.linux-${go_arch}.tar.gz"; \
    curl -fsSL "https://go.dev/dl/${tarball}" -o /tmp/go.tar.gz; \
    echo "${go_sha}  /tmp/go.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/go.tar.gz -C /usr/local; \
    rm /tmp/go.tar.gz; \
    ln -s /usr/local/go/bin/go /usr/local/bin/go; \
    go version

COPY --from=build /app/target/release/mcp_hub /usr/local/bin/mcp_hub
# The AGPL text travels with the binary it covers.
COPY LICENSE /app/LICENSE
# Static web assets are read at runtime from the working directory.
COPY static /app/static
# Entrypoint applies best-effort runtime hardening (proc hidepid + egress) then
# execs the hub. See the script for the capabilities it needs.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# The hub runs as root *on purpose*: it drops each user's stdio subprocesses to
# an unprivileged per-user UID (HUB_SANDBOX_UID_BASE + the user's slot) so they
# cannot read the master key or the secrets DB. Set the base to 0 to disable.
#
# The entrypoint additionally hardens the runtime when the matching capability is
# present (both are best-effort and skipped with a log line otherwise):
#   HUB_HIDEPID=1           remount /proc hidepid=2     (needs CAP_SYS_ADMIN)
#   HUB_EGRESS_HARDENING=1  sandbox-UID egress firewall (needs CAP_NET_ADMIN)
# Set either to 0 to opt out.
ENV HUB_DB_PATH=/data/hub.db \
    HUB_ENV_DIR=/data/envs \
    HUB_LISTEN=0.0.0.0:8080 \
    HUB_SANDBOX_UID_BASE=20000 \
    HUB_HIDEPID=1 \
    HUB_EGRESS_HARDENING=1
VOLUME ["/data"]
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
