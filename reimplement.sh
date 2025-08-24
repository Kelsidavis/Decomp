#!/usr/bin/env bash
set -euo pipefail

# ---------------- config ----------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${WORK_DIR:-$SCRIPT_DIR/work}"
SRC_DIR="$WORK_DIR/recovered_project/src"
OUT_DIR="$WORK_DIR/recovered_project_impl/src"
LABELS="$WORK_DIR/hunt/functions.labeled.jsonl"
LOG_DIR="$WORK_DIR/logs"
STAMP="$(date +%Y%m%d-%H%M%S)"
LOG="$LOG_DIR/reimplement.$STAMP.log"

LLM_ENDPOINT="${LLM_ENDPOINT:-http://127.0.0.1:8080/v1/chat/completions}"
LLM_MODEL="${LLM_MODEL:-qwen3-14b-q5}"

mkdir -p "$OUT_DIR" "$LOG_DIR"

# ---------------- helpers ----------------
ts_and_progress() {
  local start_epoch="$1"
  awk -v start="$start_epoch" '
    function hms(sec,  h, m, s) { h=int(sec/3600); m=int((sec%3600)/60); s=sec%60;
      return sprintf("%02d:%02d:%02d", h,m,s) }
    {
      now = systime()
      line = $0
      if (match(line, /\[reimpl\].*([0-9]+)\/([0-9]+)/, m)) {
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

# ---------------- run ----------------
echo "==============================================="
echo " Function Re-implementation Pipeline"
echo " Timestamp:   $STAMP"
echo " Src:         $SRC_DIR"
echo " Out:         $OUT_DIR"
echo " Labels:      $LABELS"
echo " Log:         $LOG"
echo " LLM:         $LLM_MODEL @ $LLM_ENDPOINT"
echo "==============================================="

START=$(date +%s)

python3 "$SCRIPT_DIR/tools/reimplement.py" \
  --src-dir "$SRC_DIR" \
  --out-dir "$OUT_DIR" \
  --labels "$LABELS" \
  --endpoint "$LLM_ENDPOINT" \
  --model "$LLM_MODEL" 2>&1 | ts_and_progress "$START" | tee "$LOG"

ELAPSED=$(( $(date +%s) - START ))
printf "===============================================\n"
echo "[✓] Re-implementation complete."
echo " Output: $OUT_DIR"
echo " Log:    $LOG"
echo " Total runtime: $(printf "%02d:%02d:%02d" $((ELAPSED/3600)) $(((ELAPSED%3600)/60)) $((ELAPSED%60)))"
printf "===============================================\n"

