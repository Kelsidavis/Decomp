#!/usr/bin/env bash
# reimplement.sh — synthesize function bodies with ETA/timestamps
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${WORK_DIR:-$SCRIPT_DIR/work}"
SRC_DIR="$WORK_DIR/recovered_project/src"
OUT_DIR="$WORK_DIR/recovered_project_impl/src"
LABELS="$WORK_DIR/hunt/functions.labeled.jsonl"
LOG_DIR="$WORK_DIR/logs"
STAMP="$(date +%Y%m%d-%H%M%S)"
LOG="$LOG_DIR/reimplement.$STAMP.log"

LLM_ENDPOINT="${LLM_ENDPOINT:-http://127.0.0.1:8080/v1/chat/completions}"
LLM_MODEL="${LLM_MODEL:-qwen3-14b}"

mkdir -p "$OUT_DIR" "$LOG_DIR"

have_gawk=0; command -v gawk >/dev/null 2>&1 && have_gawk=1
_ts_filter_gawk() { local s="$1"; gawk -v start="$s" '
  function hms(x, h,m,s){h=int(x/3600);m=int((x%3600)/60);s=x%60;return sprintf("%02d:%02d:%02d",h,m,s)}
  { now=systime(); line=$0; if (match(line,/\[reimpl\] progress[[:space:]]+([0-9]+)\/([0-9]+)/,m)){
      done=m[1]+0; total=m[2]+0; elapsed=now-start; pct=(total?int(100*done/total):0);
      rate=(elapsed>0 && done>0)? done/elapsed:0; remain=(rate>0)? int((total-done)/rate):-1; eta=(remain>=0)? hms(remain):"??:??:??";
      printf("[%s] %s | %d%% | elapsed %s | ETA %s\n", strftime("%H:%M:%S",now), line, pct, hms(elapsed), eta);
    } else { printf("[%s] %s\n", strftime("%H:%M:%S",now), line); } fflush(); }'
}
_ts_filter_sh() { 
  local s="$1"
  while IFS= read -r line; do
    if [[ "$line" =~ \[reimpl\]\ progress[[:space:]]+([0-9]+)/([0-9]+) ]]; then
      now=$(date +%s); done=${BASH_REMATCH[1]}; total=${BASH_REMATCH[2]}; elapsed=$((now-s));
      rate=$(awk -v d="$done" -v e="$elapsed" 'BEGIN{ if (e>0) printf "%.6f", d/e; else print 0 }')
      remain=$(awk -v r="$rate" -v t="$total" -v d="$done" 'BEGIN{ if (r>0) printf "%.0f", (t-d)/r; else print -1 }')
      if (( remain >= 0 )); then
        printf -v ETA "%02d:%02d:%02d" $((remain/3600)) $(((remain%3600)/60)) $((remain%60))
      else
        ETA="??:??:??"
      fi
      pct=$(( total>0 ? (100*done)/total : 0 ))
      printf "[%s] %s | %s%% | elapsed %02d:%02d:%02d | ETA %s\n" \
        "$(date +%T)" "$line" "$pct" $((elapsed/3600)) $(((elapsed%3600)/60)) $((elapsed%60)) "$ETA"
    else
      printf "[%s] %s\n" "$(date +%T)" "$line"
    fi
  done
}
_ts_and_progress(){ local s="$1"; if (( have_gawk )); then _ts_filter_gawk "$s"; else _ts_filter_sh "$s"; fi }

START=$(date +%s)
exec > >(stdbuf -oL -eL tee -a "$LOG") 2>&1

echo "==============================================="
echo " Function Re-implementation Pipeline"
echo " Timestamp:   $STAMP"
echo " Src:         $SRC_DIR"
echo " Out:         $OUT_DIR"
echo " Labels:      $LABELS"
echo " Log:         $LOG"
echo " LLM:         $LLM_MODEL @ $LLM_ENDPOINT"
echo "==============================================="

stdbuf -oL -eL python3 "$SCRIPT_DIR/tools/reimplement.py" \
  --src-dir "$SRC_DIR" \
  --out-dir "$OUT_DIR" \
  --labels "$LABELS" \
  --endpoint "$LLM_ENDPOINT" \
  --model "$LLM_MODEL" | _ts_and_progress "$START"

ELAPSED=$(( $(date +%s) - START ))
printf "===============================================\n"
echo "[✓] Re-implementation complete."
echo " Output: $OUT_DIR"
echo " Log:    $LOG"
echo " Total runtime: $(printf "%02d:%02d:%02d" $((ELAPSED/3600)) $(((ELAPSED%3600)/60)) $((ELAPSED%60)))"
printf "===============================================\n"

