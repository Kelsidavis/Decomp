#!/usr/bin/env bash
# reimplement.sh — run AST-safe re-implementation with progress & ETA
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

: "${SRC_DIR:=work/recovered_project_human/src}"
: "${OUT_DIR:=work/recovered_project_reimpl/src}"
: "${TESTS_DIR:=work/reimplement/tests}"
: "${MAPPING:=work/hunt/functions.labeled.jsonl}"

: "${REIMPL_THRESHOLD:=0.78}"
: "${REIMPL_MAX_FNS:=120}"

# LLM (optional)
: "${LLM_ENDPOINT:=http://127.0.0.1:8080/v1/chat/completions}"
: "${LLM_MODEL:=Qwen3-14B-UD-Q5_K_XL.gguf}"
: "${REIMPL_MAX_TOKENS:=768}"

# venv bootstrap (reuse humanize’s pattern)
if [[ -z "${VIRTUAL_ENV:-}" && -x "$(command -v python3)" ]]; then
  if [[ ! -d "$SCRIPT_DIR/.venv" ]]; then
    python3 -m venv "$SCRIPT_DIR/.venv"
    source "$SCRIPT_DIR/.venv/bin/activate"
    python -m pip install --upgrade pip wheel >/dev/null 2>&1 || true
    python -m pip install --no-cache-dir pycparser requests >/dev/null 2>&1 || true
  else
    source "$SCRIPT_DIR/.venv/bin/activate"
  fi
fi

# logging
mkdir -p work/logs
STAMP="$(date +%Y%m%d-%H%M%S)"
LOG="work/logs/reimplement.${STAMP}.log"
exec > >(stdbuf -oL -eL tee -a "$LOG") 2>&1

echo "=============================================="
echo " Re-implementation Stage"
echo " Timestamp: $STAMP"
echo " SRC_DIR  : $SRC_DIR"
echo " OUT_DIR  : $OUT_DIR"
echo " TESTS    : $TESTS_DIR"
echo " MAPPING  : $MAPPING"
echo " LLM      : ${LLM_MODEL:-<none>} @ ${LLM_ENDPOINT:-<none>}"
echo " THRESH   : $REIMPL_THRESHOLD  MAX_FNS: $REIMPL_MAX_FNS"
echo "=============================================="

if [[ ! -s "$MAPPING" ]]; then
  echo "[error] mapping not found: $MAPPING"
  exit 1
fi
if [[ ! -d "$SRC_DIR" ]]; then
  echo "[error] src dir not found: $SRC_DIR"
  exit 1
fi

PY=tools/reimplement.py
if [[ ! -f "$PY" ]]; then
  echo "[error] missing tools/reimplement.py"
  exit 1
fi

python3 "$PY" \
  --src-dir "$SRC_DIR" \
  --mapping "$MAPPING" \
  --out-dir "$OUT_DIR" \
  --tests-dir "$TESTS_DIR" \
  --threshold "$REIMPL_THRESHOLD" \
  --max-fns "$REIMPL_MAX_FNS" \
  --llm-endpoint "$LLM_ENDPOINT" \
  --model "$LLM_MODEL" \
  --max-tokens "$REIMPL_MAX_TOKENS"

echo "[ok] reimplementation complete"
echo " - sources: $OUT_DIR"
echo " - tests  : $TESTS_DIR"
echo " - log    : $LOG"

