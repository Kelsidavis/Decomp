#!/usr/bin/env bash
# humanize.sh — analyze + humanize with logging, cache/resume, ETA
set -euo pipefail

: "${LLM_ENDPOINT:=http://127.0.0.1:8080/v1/chat/completions}"
: "${LLM_MODEL:=Qwen3-14B-UD-Q5_K_XL.gguf}"
: "${HUNT_LLM_CONCURRENCY:=6}"
: "${HUNT_LLM_MAX_TOKENS:=224}"
: "${HUNT_MIN_SIZE:=0}"
: "${HUNT_TOPN:=1000}"
: "${HUNT_CACHE:=1}"
: "${ENABLE_CAPA:=1}"
: "${ENABLE_YARA:=1}"
: "${ENABLE_FLOSS:=1}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p work/logs
STAMP="$(date +%Y%m%d-%H%M%S)"
LOG="work/logs/pipeline.${STAMP}.log"

# Timestamped progress filter (gawk if available; sh fallback)
have_gawk=0
command -v gawk >/dev/null 2>&1 && have_gawk=1

_ts_filter_gawk() {
  local start_epoch="$1"
  gawk -v start="$start_epoch" '
    function hms(sec,  h, m, s) { h=int(sec/3600); m=int((sec%3600)/60); s=sec%60; return sprintf("%02d:%02d:%02d", h,m,s) }
    {
      now = systime(); line = $0
      if (match(line, /\[(llm|humanize|reimpl)\] progress[[:space:]]+([0-9]+)\/([0-9]+)/, m)) {
        done=m[2]+0; total=m[3]+0; elapsed=now-start; pct=(total>0)?int(100*done/total):0;
        rate=(elapsed>0 && done>0)? done/elapsed:0; remain=(rate>0)? int((total-done)/rate):-1; eta=(remain>=0)? hms(remain):"??:??:??";
        printf("[%s] %s | %d%% | elapsed %s | ETA %s\n", strftime("%H:%M:%S", now), line, pct, hms(elapsed), eta); fflush();
      } else { printf("[%s] %s\n", strftime("%H:%M:%S", now), line); fflush(); }
    }'
}
_ts_filter_sh() {
  local start_epoch="$1"
  while IFS= read -r line; do
    if [[ "$line" =~ \[(llm|humanize|reimpl)\]\ progress[[:space:]]+([0-9]+)/([0-9]+) ]]; then
      now=$(date +%s)
      done=${BASH_REMATCH[2]}
      total=${BASH_REMATCH[3]}
      elapsed=$((now-start_epoch))
      if (( elapsed > 0 && done > 0 )); then
        remain=$(( (total - done) * elapsed / done ))
      else
        remain=-1
      fi
      if (( remain >= 0 )); then printf -v ETA "%02d:%02d:%02d" $((remain/3600)) $(((remain%3600)/60)) $((remain%60)); else ETA="??:??:??"; fi
      pct=$(( total>0 ? (100*done)/total : 0 ))
      printf "[%s] %s | %s%% | elapsed %02d:%02d:%02d | ETA %s\n" \
        "$(date +%T)" "$line" "$pct" $((elapsed/3600)) $(((elapsed%3600)/60)) $((elapsed%60)) "$ETA"
    else
      printf "[%s] %s\n" "$(date +%T)" "$line"
    fi
  done
}
_ts_and_progress() { local s="$1"; if (( have_gawk )); then _ts_filter_gawk "$s"; else _ts_filter_sh "$s"; fi }

# Log to file
exec > >(stdbuf -oL -eL tee -a "$LOG") 2>&1

echo "==============================================="
echo " Function Hunt → Humanize pipeline"
echo " Timestamp:    $STAMP"
echo " Log:          $LOG"
echo " LLM:          $LLM_MODEL @ $LLM_ENDPOINT"
echo " HUNT_TOPN:    ${HUNT_TOPN}   HUNT_MIN_SIZE: ${HUNT_MIN_SIZE}"
echo " CAPA/YARA:    ${ENABLE_CAPA}/${ENABLE_YARA}   FLOSS: ${ENABLE_FLOSS}"
echo "==============================================="

# Stage: analyze
AN_START=$(date +%s)
stdbuf -oL -eL python3 tools/function_hunt/run_autodiscover.py | _ts_and_progress "$AN_START"

JSONL="work/hunt/functions.labeled.jsonl"
if [[ ! -s "$JSONL" ]]; then
  echo "[error] expected mapping not found: $JSONL"
  exit 1
fi
echo "[ok] mapping ready: $JSONL"

# Stage: humanize
SRC_DIR="work/recovered_project/src"
OUT_DIR="work/recovered_project_human"
HU_START=$(date +%s)
stdbuf -oL -eL python3 tools/humanize_source.py \
  --src-dir "$SRC_DIR" \
  --out-dir "$OUT_DIR" \
  --mapping "$JSONL" | _ts_and_progress "$HU_START"

echo "[done] artifacts:"
echo "  - $JSONL"
echo "  - $OUT_DIR"
echo "Log: $LOG"

