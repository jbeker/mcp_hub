# syntax=docker/dockerfile:1

# ---- build stage --------------------------------------------------------
FROM rust:1.90-slim-bookworm AS build
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
COPY src ./src
# Touch main so cargo rebuilds with the real sources.
RUN touch src/main.rs && cargo build --release

# ---- runtime stage ------------------------------------------------------
# The runtime image bundles node (npx) and uv (uvx) because stdio backend
# MCP servers are launched as child processes inside this container.
FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl xz-utils libssl3 git \
    && rm -rf /var/lib/apt/lists/*

# Node.js (provides npx) — pinned major version.
ENV NODE_VERSION=22.11.0
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) node_arch="x64" ;; \
      arm64) node_arch="arm64" ;; \
      *) echo "unsupported arch $arch" && exit 1 ;; \
    esac; \
    curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.xz" \
      -o /tmp/node.tar.xz; \
    tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 \
      --exclude='*/CHANGELOG.md' --exclude='*/LICENSE' --exclude='*/README.md'; \
    rm /tmp/node.tar.xz; \
    node --version; npx --version

# uv (provides uv / uvx for Python-based MCP servers), via the official installer.
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh \
    && uv --version && uvx --version

COPY --from=build /app/target/release/mcp_hub /usr/local/bin/mcp_hub
# Static web assets are read at runtime from the working directory.
COPY static /app/static

# The hub runs as root *on purpose*: it drops each user's stdio subprocesses to
# an unprivileged per-user UID (HUB_SANDBOX_UID_BASE + the user's slot) so they
# cannot read the master key or the secrets DB. Set the base to 0 to disable.
ENV HUB_DB_PATH=/data/hub.db \
    HUB_ENV_DIR=/data/envs \
    HUB_LISTEN=0.0.0.0:8080 \
    HUB_SANDBOX_UID_BASE=20000
VOLUME ["/data"]
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/mcp_hub"]
