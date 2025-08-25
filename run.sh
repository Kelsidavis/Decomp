#!/usr/bin/env bash
# run.sh — convenience wrapper; builds exporter image (if needed) and runs full pipeline
set -euo pipefail

: "${GHIDRA_IMAGE:=decomp-ghidra-llm:latest}"

build_image_if_missing() {
  if ! docker image inspect "$GHIDRA_IMAGE" >/dev/null 2>&1; then
    echo "[run] building Ghidra exporter image: $GHIDRA_IMAGE"
    docker build -t "$GHIDRA_IMAGE" -f Dockerfile .
  fi
}

case "${1:-}" in
  build-image)
    build_image_if_missing
    echo "[run] image ready: $GHIDRA_IMAGE"
    ;;
  *)
    # Default: run full pipeline (auto-detects local GHIDRA_HOME; falls back to docker image)
    build_image_if_missing || true
    exec ./full_run.sh "${@}"
    ;;
esac

