#!/usr/bin/env bash
# full_run.sh — end-to-end pipeline (decompile → humanize → reimplement)
# Logs to work/logs/full_run.<timestamp>.log

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# -------- Defaults (override via env) --------
: "${WORK_DIR:=work}"
: "${LLM_ENDPOINT:=http://127.0.0.1:8080/v1/chat/completions}"
: "${LLM_MODEL:=Qwen3-14B-UD-Q5_K_XL.gguf}"

# Humanize defaults
: "${HUNT_TOPN:=1000}"
: "${HUNT_MIN_SIZE:=0}"
: "${ENABLE_FLOSS:=1}"

# Reimplement defaults
: "${REIMPL_THRESHOLD:=0.78}"
: "${REIMPL_MAX_FNS:=120}"

# -------- Logging --------
mkdir -p "$WORK_DIR/logs"
STAMP="$(date +%Y%m%d-%H%M%S)"
LOG="$WORK_DIR/logs/full_run.${STAMP}.log"
exec > >(stdbuf -oL -eL tee -a "$LOG") 2>&1

trap 'echo "[error] pipeline failed (line $LINENO). See: $LOG"; exit 1' ERR

banner() {
  echo "=================================================="
  echo " $*"
  echo " Timestamp: $STAMP"
  echo " Log: $LOG"
  echo "=================================================="
}

llm_check() {
  if ! command -v curl >/dev/null 2>&1; then
    echo "[warn] curl not found — skipping LLM endpoint check"
    return 0
  fi
  echo "[ok] checking LLM endpoint… ($LLM_ENDPOINT)"
  # tiny health probe; tolerant of different server shapes
  if ! curl -sS -m 2 -H 'Content-Type: application/json' \
      -d '{"model":"'"${LLM_MODEL}"'","messages":[{"role":"user","content":"ping"}],"max_tokens":2}' \
      "$LLM_ENDPOINT" >/dev/null; then
    echo "[warn] LLM endpoint not reachable or refusing requests. Pipeline will continue, but labels/re-impl may degrade."
  else
    echo "[ok] LLM endpoint responding."
  fi
}

summary_line() {
  printf "%-22s %s\n" "$1" "$2"
}

# -------- Header --------
banner "FULL RUN — Decompile → Humanize → Re-implement"
summary_line "WORK_DIR:" "$WORK_DIR"
summary_line "LLM_MODEL:" "${LLM_MODEL:-<none>}"
summary_line "LLM_ENDPOINT:" "${LLM_ENDPOINT:-<none>}"
summary_line "HUNT_TOPN:" "$HUNT_TOPN"
summary_line "HUNT_MIN_SIZE:" "$HUNT_MIN_SIZE"
summary_line "REIMPL_THRESHOLD:" "$REIMPL_THRESHOLD"
summary_line "REIMPL_MAX_FNS:" "$REIMPL_MAX_FNS"
echo

llm_check
echo

# -------- Stage 1: Base workflow (your existing run.sh) --------
if [[ -x ./run.sh ]]; then
  echo "---- [1/3] Running base workflow: ./run.sh ----"
  ./run.sh
  echo "---- [1/3] run.sh complete ----"
else
  echo "[warn] ./run.sh not found or not executable — skipping base stage"
fi
echo

# -------- Stage 2: Humanize (analyze + label + rename) --------
if [[ ! -x ./humanize.sh ]]; then
  echo "[error] humanize.sh not found or not executable"; exit 2
fi

echo "---- [2/3] Humanize source (Function Hunt + LLM) ----"
# Pass through key env; humanize.sh already handles venv, FLOSS, progress, etc.
HUNT_TOPN="$HUNT_TOPN" \
HUNT_MIN_SIZE="$HUNT_MIN_SIZE" \
ENABLE_FLOSS="$ENABLE_FLOSS" \
LLM_ENDPOINT="$LLM_ENDPOINT" \
LLM_MODEL="$LLM_MODEL" \
./humanize.sh

echo "---- [2/3] humanize.sh complete ----"
echo

# Expected artifacts from humanize:
MAPPING="work/hunt/functions.labeled.jsonl"
SRC_HUMAN="work/recovered_project_human/src"
if [[ ! -s "$MAPPING" ]]; then
  echo "[error] expected mapping missing: $MAPPING"; exit 3
fi
if [[ ! -d "$SRC_HUMAN" ]]; then
  echo "[warn] humanized src dir not found: $SRC_HUMAN (continuing)"
fi

# -------- Stage 3: Re-implementation (AST-safe body replacement + tests) --------
if [[ ! -x ./reimplement.sh ]]; then
  echo "[error] reimplement.sh not found or not executable"; exit 4
fi

echo "---- [3/3] Re-implementation stage ----"
REIMPL_THRESHOLD="$REIMPL_THRESHOLD" \
REIMPL_MAX_FNS="$REIMPL_MAX_FNS" \
LLM_ENDPOINT="$LLM_ENDPOINT" \
LLM_MODEL="$LLM_MODEL" \
./reimplement.sh

echo "---- [3/3] reimplement.sh complete ----"
echo

# -------- Summary --------
HUMAN_OUT="work/recovered_project_human/src"
REIMPL_OUT="work/recovered_project_reimpl/src"
REPORT_MD="work/hunt/report.md"

echo "================= SUMMARY ================="
[[ -f "$REPORT_MD" ]]   && summary_line "Report:" "$REPORT_MD"
[[ -f "$MAPPING" ]]     && summary_line "Mapping:" "$MAPPING"
[[ -d "$HUMAN_OUT" ]]   && summary_line "Humanized src:" "$HUMAN_OUT"
[[ -d "$REIMPL_OUT" ]]  && summary_line "Re-impl src:" "$REIMPL_OUT"
summary_line "Log:" "$LOG"
echo "==========================================="
echo "[ok] full pipeline finished successfully."

