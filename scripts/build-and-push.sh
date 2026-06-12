#!/usr/bin/env bash
# Build the hub image and push it to the private registry.
#
# Tags the image with both the current git short-SHA (for traceability and
# rollback) and `latest` (what the deployment's `pull_policy: always` tracks).
#
#   ./scripts/build-and-push.sh
#
# Overrides via environment:
#   REGISTRY  registry host            (default registry.confusticate.com)
#   PLATFORM  target platform(s)       (default linux/amd64)
set -euo pipefail

REGISTRY="${REGISTRY:-registry.confusticate.com}"
IMAGE="$REGISTRY/mcp_hub"
PLATFORM="${PLATFORM:-linux/amd64}"

# Run from the repo root so the Docker build context is right.
cd "$(dirname "$0")/.."

TAG="$(git rev-parse --short HEAD)"
if [[ -n "$(git status --porcelain)" ]]; then
    echo "warning: working tree has uncommitted changes;" \
         "the image will not match commit $TAG" >&2
fi

# buildx handles cross-building (e.g. an arm64 Mac targeting linux/amd64)
# and pushes in the same step.
docker buildx build \
    --platform "$PLATFORM" \
    --tag "$IMAGE:$TAG" \
    --tag "$IMAGE:latest" \
    --push \
    .

echo "pushed $IMAGE:$TAG and $IMAGE:latest"
