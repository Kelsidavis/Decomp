#!/usr/bin/env bash
# humanize.sh — analyze + humanize with logging, cache/resume, ETA, and env bootstrap
set -euo pipefail

# ---------- knobs (override via env) ----------
: "${LLM_ENDPOINT:=http://127.0.0.1:8080/v1/chat/completions}"
: "${LLM_MODEL:=Qwen3-14B-UD-Q5_K_XL.gguf}"
: "${HUNT_LLM_CONCURRENCY:=6}"
: "${HUNT_LLM_MAX_TOKENS:=224}"
: "${HUNT_MIN_SIZE:=0}"
: "${HUNT_TOPN:=1000}"
: "${HUNT_CACHE:=1}"

# bootstrap controls
: "${BOOTSTRAP:=1}"               # create .venv + install deps if needed
: "${REQUIREMENTS:=}"             # optional path to requirements.txt (installed into venv if set)
: "${PIN_PYCC:=pycparser}"        # allow pin, e.g. pycparser==2.21

RESET_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset-run) RESET_RUN=1; shift ;;
    --topn)      export HUNT_TOPN="${2:-$HUNT_TOPN}"; shift 2 ;;
    --min-size)  export HUNT_MIN_SIZE="${2:-$HUNT_MIN_SIZE}"; shift 2 ;;
    --no-bootstrap) BOOTSTRAP=0; shift ;;
    *) echo "[warn] unknown arg: $1" >&2; shift ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---------- lightweight bootstrap ----------
_activate_venv() {
  # prefer repo-local venv
  if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    # already in a venv
    return 0
  fi
  if [[ -d "$SCRIPT_DIR/.venv" ]]; then
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/.venv/bin/activate"
    return 0
  fi
  return 1
}

_bootstrap_env() {
  [[ "$BOOTSTRAP" == "1" ]] || return 0
  if ! command -v python3 >/dev/null 2>&1; then
    echo "[bootstrap] python3 not found; continuing without AST mode"
    export HUMANIZE_AST=0
    return 0
  fi

  if ! _activate_venv; then
    echo "[bootstrap] creating repo-local venv: .venv"
    python3 -m venv "$SCRIPT_DIR/.venv"
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/.venv/bin/activate"
    python -m pip install --upgrade pip >/dev/null 2>&1 || true
    python -m pip install --upgrade wheel >/dev/null 2>&1 || true
  fi

  # If requirements.txt provided, install it first (quietly).
  if [[ -n "$REQUIREMENTS" && -f "$REQUIREMENTS" ]]; then
    echo "[bootstrap] installing requirements from $REQUIREMENTS"
    python -m pip install --no-cache-dir -r "$REQUIREMENTS"
  fi

  # Ensure needed packages
  python - <<'PY' || true
try:
    import requests
    import pycparser
    print("ok")
except Exception as e:
    raise SystemExit(1)
PY

  if [[ "${PIPESTATUS[0]}" -ne 0 ]]; then
    echo "[bootstrap] installing requests + ${PIN_PYCC}"
    python -m pip install --no-cache-dir requests "${PIN_PYCC}"
  fi

  # prefer AST renamer when available
  python - <<'PY'
import os, sys
try:
    import pycparser
    print("AST=1")
except Exception:
    print("AST=0")
PY

  if grep -q "AST=1" <(python - <<'PY'
try:
    import pycparser; print("AST=1")
except Exception:
    print("AST=0")
PY
  ); then
    export HUMANIZE_AST=1
  else
    export HUMANIZE_AST=0
  fi
}

_bootstrap_env

# ---------- logging + progress formatting ----------
mkdir -p work/logs
STAMP="$(date +%Y%m%d-%H%M%S)"
LOG="work/logs/pipeline.${STAMP}.log"

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

_ts_and_progress() {
  local start_epoch="$1"
  if (( have_gawk )); then _ts_filter_gawk "$start_epoch"; else _ts_filter_sh "$start_epoch"; fi
}

PIPE_START=$(date +%s)
exec > >(stdbuf -oL -eL tee -a "$LOG") 2>&1

echo "==============================================="
echo " Function Hunt → Humanize pipeline"
echo " Timestamp:    $STAMP"
echo " Log:          $LOG"
echo " LLM:          $LLM_MODEL @ $LLM_ENDPOINT"
echo " Bootstrap:    ${BOOTSTRAP} (venv: ${VIRTUAL_ENV:-none})"
echo " HUMANIZE_AST: ${HUMANIZE_AST:-0}"
echo "==============================================="

# ---------- optional reset of prior run artifacts ----------
if [[ "$RESET_RUN" == "1" ]]; then
  rm -f work/hunt/functions.labeled.jsonl work/hunt/.progress
  echo "[reset] cleared work/hunt/functions.labeled.jsonl and .progress"
fi

# ---------- analyze / label ----------
AN_START=$(date +%s)
stdbuf -oL -eL python3 tools/function_hunt/run_autodiscover.py | _ts_and_progress "$AN_START"

JSONL="work/hunt/functions.labeled.jsonl"
if [[ ! -s "$JSONL" ]]; then
  echo "[error] expected mapping not found: $JSONL"
  exit 1
fi
echo "[ok] mapping ready: $JSONL"

# ---------- humanize stage ----------
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

