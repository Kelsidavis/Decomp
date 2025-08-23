#!/usr/bin/env bash
set -euo pipefail

# ---------------- config (override via env or flags) ----------------
IMG_NAME="${IMG_NAME:-ghidra-llm:latest}"
WORK_DIR="${WORK_DIR:-$HOME/Desktop/decomp/work}"
LLM_ENDPOINT_DEFAULT="${LLM_ENDPOINT_DEFAULT:-http://host.docker.internal:8080/v1/chat/completions}"
LLM_MODEL_DEFAULT="${LLM_MODEL_DEFAULT:-qwen3-14b-q5}"
CODE_LANG_DEFAULT="${CODE_LANG_DEFAULT:-auto}"     # auto|c|cpp
HUMANIZE_DEFAULT="${HUMANIZE_DEFAULT:-apply}"      # off|suggest|apply
BUILD_REC_DEFAULT="${BUILD_REC_DEFAULT:-0}"        # 1 to try 'make' on applied project
DEBUG_DEFAULT="${DEBUG_DEFAULT:-1}"

# ---------------- flags ----------------
EXE_ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --exe) EXE_ARG="${2:-}"; shift 2 ;;
    --model) LLM_MODEL_DEFAULT="${2:-}"; shift 2 ;;
    --endpoint) LLM_ENDPOINT_DEFAULT="${2:-}"; shift 2 ;;
    --lang) CODE_LANG_DEFAULT="${2:-}"; shift 2 ;;
    --humanize) HUMANIZE_DEFAULT="${2:-}"; shift 2 ;;
    --build) BUILD_REC_DEFAULT="1"; shift 1 ;;
    --no-cache) NO_CACHE="--no-cache"; shift 1 ;;
    -h|--help)
      echo "Usage: $0 [--exe /path/to/target.exe] [--model NAME] [--endpoint URL] [--lang auto|c|cpp] [--humanize off|suggest|apply] [--build] [--no-cache]"
      exit 0
      ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

# ---------------- prerequisites ----------------
command -v docker >/dev/null || { echo "[!] docker not found"; exit 1; }
mkdir -p "$WORK_DIR"
[[ -w "$WORK_DIR" ]] || { echo "[!] WORK_DIR not writable: $WORK_DIR"; exit 1; }

echo "[*] Rebuilding Docker image: $IMG_NAME"
docker build ${NO_CACHE:-} -t "$IMG_NAME" .

# ---------------- target selection ----------------
if [[ -n "$EXE_ARG" ]]; then
  exe="$EXE_ARG"
else
  # pick exactly one .exe in WORK_DIR
  mapfile -t exes < <(ls "$WORK_DIR"/*.exe 2>/dev/null || true)
  if (( ${#exes[@]} == 0 )); then
    echo "[!] No .exe file found in $WORK_DIR (use --exe to specify)"
    exit 1
  fi
  exe="${exes[0]}"
  if (( ${#exes[@]} > 1 )); then
    echo "[!] Multiple .exe found; using first: $(basename "$exe")"
  fi
fi

[[ -f "$exe" ]] || { echo "[!] EXE not found: $exe"; exit 1; }

base=$(basename "$exe")
stem="${base%.*}"

echo "============================================="
echo "[*] Target: $base"
echo "    Work : $WORK_DIR"
echo "    Lang : $CODE_LANG_DEFAULT"
echo "============================================="

# ---------------- run ----------------
docker run --rm -it \
  --user "$(id -u):$(id -g)" \
  --add-host=host.docker.internal:host-gateway \
  -v "$WORK_DIR":/work \
  -e GHIDRA_PROJECT_DIR="/tmp/ghidra_proj_${stem}" \
  -e GHIDRA_PROJECT_NAME="proj_${stem}" \
  -e BINARY_PATH="/work/$base" \
  -e OUT_JSON="/work/${stem}_out.json" \
  -e REPORT_MD="/work/${stem}_report.md" \
  -e LLM_ENDPOINT="${LLM_ENDPOINT_DEFAULT}" \
  -e LLM_MODEL="${LLM_MODEL_DEFAULT}" \
  -e MAX_FUNC_TOKENS=5000 \
  -e CODE_LANG="${CODE_LANG_DEFAULT}" \
  -e HUMANIZE_MODE="${HUMANIZE_DEFAULT}" \
  -e BUILD_RECOVERED="${BUILD_REC_DEFAULT}" \
  -e DEBUG="${DEBUG_DEFAULT}" \
  "$IMG_NAME"

echo
echo "[✓] Finished: $base"
echo "    → recovered_project/ inside $WORK_DIR"
echo "    → run.<timestamp>.log in $WORK_DIR (full pipeline log)"

