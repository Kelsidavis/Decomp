#!/usr/bin/env bash
# humanize.sh — analyze + humanize with logging, cache/resume, and clean stage/heartbeat display
set -euo pipefail

# ---------- Defaults ----------
: "${LLM_ENDPOINT:=http://127.0.0.1:8080/v1/chat/completions}"
: "${LLM_MODEL:=Qwen3-14B-UD-Q5_K_XL.gguf}"

: "${HUNT_TOPN:=1000}"
: "${HUNT_MIN_SIZE:=0}"
: "${HUNT_CACHE:=1}"
: "${HUMANIZE_RESUME:=1}"

# Enrich toggles (default ON)
: "${ENABLE_CAPA:=1}"
: "${ENABLE_YARA:=1}"
: "${ENABLE_FLOSS:=1}"

# AST helpers
: "${FAKE_LIBC_DIR:=$PWD/tools/fake_libc_include}"

# ---------- Args ----------
RESET_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset-run) RESET_RUN=1; shift ;;
    --topn)      export HUNT_TOPN="${2:-$HUNT_TOPN}"; shift 2 ;;
    --min-size)  export HUNT_MIN_SIZE="${2:-$HUNT_MIN_SIZE}"; shift 2 ;;
    --no-capa)   ENABLE_CAPA=0; shift ;;
    --no-yara)   ENABLE_YARA=0; shift ;;
    --no-floss)  ENABLE_FLOSS=0; shift ;;
    *) echo "[warn] unknown arg: $1" >&2; shift ;;
  esac
done
export ENABLE_CAPA ENABLE_YARA ENABLE_FLOSS FAKE_LIBC_DIR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p work/logs
STAMP="$(date +%Y%m%d-%H%M%S)"
LOG="work/logs/pipeline.${STAMP}.log"

# ---------- Formatter (timestamps + progress + heartbeat + stage timings) ----------
have_gawk=0; command -v gawk >/dev/null 2>&1 && have_gawk=1

_ts_format_gawk() {
  gawk '
    function hms(sec,  h, m, s){h=int(sec/3600);m=int((sec%3600)/60);s=sec%60;return sprintf("%02d:%02d:%02d",h,m,s)}
    BEGIN{start=systime()}
    {
      line=$0; now=systime(); ts=strftime("%H:%M:%S", now)
      # progress lines from label/humanize/reimpl
      if (match(line, /\[(llm|humanize|reimpl)\] progress[[:space:]]+([0-9]+)\/([0-9]+)/, m)) {
        done=m[2]+0; total=m[3]+0; elapsed=now-start; pct=(total>0)?int(100*done/total):0;
        rate=(elapsed>0 && done>0)? done/elapsed:0;
        remain=(rate>0)? int((total-done)/rate):-1; eta=(remain>=0)? hms(remain):"??:??:??";
        printf("[%s] %s | %d%% | elapsed %s | ETA %s\n", ts, line, pct, hms(elapsed), eta); fflush(); next
      }
      # heartbeat from run_autodiscover
      if (line ~ /^\[hunt\] heartbeat/) {
        printf("[%s] %s\n", ts, line); fflush(); next
      }
      # stage start/stop from run_autodiscover (enrich sub-stages etc.)
      if (line ~ /^\[hunt\] >>> / || line ~ /^\[hunt\] <<< /) {
        printf("[%s] %s\n", ts, line); fflush(); next
      }
      # default
      printf("[%s] %s\n", ts, line); fflush();
    }'
}

_ts_format_sh() {
  local start_epoch="$(date +%s)"
  while IFS= read -r line; do
    local now ts; now=$(date +%s); ts="$(date +%T)"
    if [[ "$line" =~ \[(llm|humanize|reimpl)\]\ progress[[:space:]]+([0-9]+)/([0-9]+) ]]; then
      local done="${BASH_REMATCH[2]}" total="${BASH_REMATCH[3]}"
      local elapsed=$((now-start_epoch))
      local pct=0; (( total > 0 )) && pct=$(( 100*done / total ))
      local remain=-1
      if (( elapsed>0 && done>0 )); then
        remain=$(( (total-done) * elapsed / done ))
      fi
      local ETA="??:??:??"
      if (( remain >= 0 )); then printf -v ETA "%02d:%02d:%02d" $((remain/3600)) $(((remain%3600)/60)) $((remain%60)); fi
      printf "[%s] %s | %d%% | elapsed %02d:%02d:%02d | ETA %s\n" "$ts" "$line" "$pct" $((elapsed/3600)) $(((elapsed%3600)/60)) $((elapsed%60)) "$ETA"
      continue
    fi
    printf "[%s] %s\n" "$ts" "$line"
  done
}

_fmt() { if (( have_gawk )); then _ts_format_gawk; else _ts_format_sh; fi }

# ---------- Header ----------
{
  echo "==============================================="
  echo " Function Hunt → Humanize pipeline"
  echo " Timestamp:    $STAMP"
  echo " Log:          $LOG"
  echo " LLM:          $LLM_MODEL @ $LLM_ENDPOINT"
  echo " HUNT_TOPN:    ${HUNT_TOPN}   HUNT_MIN_SIZE: ${HUNT_MIN_SIZE}"
  echo " CAPA/YARA:    ${ENABLE_CAPA}/${ENABLE_YARA}   FLOSS: ${ENABLE_FLOSS}"
  echo "==============================================="
} | tee -a "$LOG"

# Optional cleanup for resume
if [[ "$RESET_RUN" == "1" ]]; then
  rm -f work/hunt/functions.labeled.jsonl work/hunt/.progress work/humanize.progress
  echo "[reset] cleared hunt mapping and progress" | tee -a "$LOG"
fi

# ---------- Analyze (discover → enrich → label) ----------
AN_START=$(date +%s)
stdbuf -oL -eL python3 tools/function_hunt/run_autodiscover.py \
  2>&1 | _fmt | tee -a "$LOG"

JSONL="work/hunt/functions.labeled.jsonl"
if [[ ! -s "$JSONL" ]]; then
  echo "[error] expected mapping not found: $JSONL" | tee -a "$LOG"
  exit 1
fi
echo "[ok] mapping ready: $JSONL" | tee -a "$LOG"

# ---------- Humanize ----------
SRC_DIR="work/recovered_project/src"
OUT_DIR="work/recovered_project_human"
HU_START=$(date +%s)
stdbuf -oL -eL python3 tools/humanize_source.py \
  --src-dir "$SRC_DIR" \
  --out-dir "$OUT_DIR" \
  --mapping "$JSONL" \
  2>&1 | _fmt | tee -a "$LOG"

{
  echo "[done] artifacts:"
  echo "  - $JSONL"
  echo "  - $OUT_DIR"
  echo "Log: $LOG"
} | tee -a "$LOG"

