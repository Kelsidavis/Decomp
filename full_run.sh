#!/usr/bin/env bash
set -euo pipefail

# ---------------- config ----------------
IMG_NAME="${IMG_NAME:-ghidra-llm:latest}"
WORK_DIR="${WORK_DIR:-$HOME/Desktop/decomp/work}"
LLM_ENDPOINT_DEFAULT="${LLM_ENDPOINT_DEFAULT:-http://host.docker.internal:8080/v1/chat/completions}"
LLM_MODEL_DEFAULT="${LLM_MODEL_DEFAULT:-qwen3-14b-q5}"
CODE_LANG_DEFAULT="${CODE_LANG_DEFAULT:-auto}"
HUMANIZE_DEFAULT="${HUMANIZE_DEFAULT:-apply}"
BUILD_REC_DEFAULT="${BUILD_REC_DEFAULT:-0}"
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
      echo "Usage: $0 [--exe path.exe] [--model NAME] [--endpoint URL] [--lang auto|c|cpp] [--humanize off|suggest|apply] [--build] [--no-cache]"
      exit 0
      ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

# ---------------- prerequisites ----------------
command -v docker >/dev/null || { echo "[!] docker not found"; exit 1; }
mkdir -p "$WORK_DIR"
[[ -w "$WORK_DIR" ]] || { echo "[!] WORK_DIR not writable: $WORK_DIR"; exit 1; }

STAMP="$(date +%Y%m%d-%H%M%S)"
LOG="$WORK_DIR/run.${STAMP}.log"
PIPE_START=$(date +%s)

# ---------------- helpers ----------------
ts_and_progress() {
  local start_epoch="$1"
  awk -v start="$start_epoch" '
    function hms(sec,  h, m, s) { h=int(sec/3600); m=int((sec%3600)/60); s=sec%60;
      return sprintf("%02d:%02d:%02d", h,m,s) }
    {
      now = systime()
      line = $0
      if (match(line, /\[llm\] progress[[:space:]]+([0-9]+)\/([0-9]+)/, m)) {
        done = m[1]+0; total=m[2]+0
        elapsed = now - start
        pct = (total>0)? int(100*done/total) : 0
        rate = (elapsed>0 && done>0)? done/elapsed : 0
        remain = (rate>0)? int( (total-done)/rate ) : -1
        eta = (remain>=0)? hms(remain) : "??:??:??"
        printf("[%s] %s | %d%% | elapsed %s | ETA %s\n",
               strftime("%H:%M:%S", now), line, pct, hms(elapsed), eta)
        fflush()
      } else {
        printf("[%s] %s\n", strftime("%H:%M:%S", now), line)
        fflush()
      }
    }'
}

# ---------------- target selection ----------------
if [[ -n "$EXE_ARG" ]]; then
  exe="$EXE_ARG"
else
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
echo " Log    : $LOG"
echo "============================================="

# ---------------- stage 1: docker analysis ----------------
echo "[*] Rebuilding Docker image: $IMG_NAME"
docker build ${NO_CACHE:-} -t "$IMG_NAME" .

docker run --rm -i \
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
  "$IMG_NAME" 2>&1 | ts_and_progress "$PIPE_START" | tee "$LOG"

# ---------------- stage 2: humanize ----------------
echo "[*] Running humanize.sh automatically…" | tee -a "$LOG"
"$SCRIPT_DIR/humanize.sh" --topn 500 --min-size 16 2>&1 | ts_and_progress "$PIPE_START" | tee -a "$LOG"

# ---------------- stage 3: reimplement ----------------
echo "[*] Running reimplement.sh automatically…" | tee -a "$LOG"
"$SCRIPT_DIR/reimplement.sh" 2>&1 | ts_and_progress "$PIPE_START" | tee -a "$LOG"

PIPE_ELAPSED=$(( $(date +%s) - PIPE_START ))
printf "=============================================\n"
echo "[✓] Full pipeline complete: $base"
echo "Artifacts:"
echo "  - recovered_project/        → raw decompile"
echo "  - recovered_project_human/  → with LLM-renamed funcs"
echo "  - recovered_project_impl/   → with re-implemented funcs"
echo "  - run.<timestamp>.log       → $LOG"
echo "Total time: $(printf "%02d:%02d:%02d" $((PIPE_ELAPSED/3600)) $(((PIPE_ELAPSED%3600)/60)) $((PIPE_ELAPSED%60)))"
printf "=============================================\n"

