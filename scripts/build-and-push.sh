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

# Refuse to ship a commit that exists only on this machine. A pushed image
# whose source was never pushed becomes the sole copy of deployed code — which
# is exactly how the 1e90964 build's source was lost. Override with FORCE=1.
if ! git branch -r --contains HEAD 2>/dev/null | grep -q .; then
    echo "error: HEAD ($TAG) is not on any remote branch — push it first so the" \
         "image's source is recoverable. Set FORCE=1 to override." >&2
    [[ "${FORCE:-}" == "1" ]] || exit 1
    echo "FORCE=1 set; building from an unpushed commit anyway." >&2
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
