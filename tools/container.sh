#!/usr/bin/env bash
# Runs a command in the pinned gate container (tools/container/Dockerfile) with the repository at
# /src, as the calling user. The image tag is the hash of the Dockerfile, built on first use.
#
#   tools/container.sh tools/gate.sh        every gate job
#   tools/container.sh                      a shell
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TAG=$(sha256sum "$ROOT/tools/container/Dockerfile" | cut -c1-16)
IMAGE=${GATE_IMAGE:-maillookalike-gate:$TAG}
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -t "$IMAGE" "$ROOT/tools/container"
fi
TTY=()
[[ -t 0 && -t 1 ]] && TTY=(-it)
JOBS=${GATE_JOBS:-4}
exec docker run --rm "${TTY[@]}" --cpus "$JOBS" --user "$(id -u):$(id -g)" \
  -e HOME=/tmp -e CMAKE_BUILD_PARALLEL_LEVEL="$JOBS" -e CTEST_PARALLEL_LEVEL="$JOBS" -e FUZZ_SECONDS -e CI \
  -v "$ROOT:/src" -w /src "$IMAGE" "${@:-bash}"
