#!/usr/bin/env bash
# humanize.sh — analyze + humanize in one go, with sane defaults and logging
export LLM_ENDPOINT=http://127.0.0.1:8080/v1/chat/completions
export LLM_MODEL=Qwen3-14B-UD-Q5_K_XL.gguf
export HUNT_LLM_CONCURRENCY=8
export HUNT_LLM_MAX_TOKENS=256
export HUNT_MIN_SIZE=0
export HUNT_TOPN=1000
set -euo pipefail

# ---------- defaults (override via env or flags) ----------
: "${LLM_ENDPOINT:=}"        # e.g. http://127.0.0.1:8080/v1/chat/completions
: "${LLM_MODEL:=}"           # e.g. Qwen3-14B-UD-Q5_K_XL.gguf
: "${HUNT_TOPN:=}"           # e.g. 200
: "${HUNT_LIMIT:=}"          # hard cap count
: "${HUNT_MIN_SIZE:=}"       # e.g. 24 to skip tiny stubs
: "${HUNT_CAPA:=1}"          # empty to disable
: "${HUNT_YARA:=1}"          # empty to disable
: "${SKIP_RESOURCES:=}"      # set 1 to skip RC generation

GEN_RC=
SKIP_LLM=
NO_CAPA=
NO_YARA=
TOPN_ARG=
LIMIT_ARG=
MINSZ_ARG=
SRC_DIR_ARG=
OUT_DIR_ARG=

# ---------- arg parsing ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --gen-rc) GEN_RC=1; shift ;;
    --skip-llm|--no-llm) SKIP_LLM=1; shift ;;
    --no-capa) NO_CAPA=1; shift ;;
    --no-yara) NO_YARA=1; shift ;;
    --topn) TOPN_ARG="$2"; shift 2 ;;
    --limit) LIMIT_ARG="$2"; shift 2 ;;
    --min-size) MINSZ_ARG="$2"; shift 2 ;;
    --src-dir) SRC_DIR_ARG="$2"; shift 2 ;;
    --out-dir) OUT_DIR_ARG="$2"; shift 2 ;;
    -h|--help)
      cat <<'EOF'
Usage: humanize.sh [options]

Analyze + LLM label + humanize recovered sources.

Options:
  --gen-rc                Also generate Windows app.rc (filters corrupt icons)
  --skip-llm | --no-llm   Skip LLM (fast dry-run)
  --no-capa               Disable capa enrichment
  --no-yara               Disable yara enrichment
  --topn N                Keep top N functions by size before LLM
  --limit N               Hard cap number of functions (after topn)
  --min-size N            Drop functions smaller than N bytes before LLM
  --src-dir PATH          Source tree to humanize (default auto-discover)
  --out-dir PATH          Output directory for humanized sources (default auto)

Env:
  LLM_ENDPOINT, LLM_MODEL, HUNT_TOPN, HUNT_LIMIT, HUNT_MIN_SIZE,
  HUNT_CAPA, HUNT_YARA, SKIP_RESOURCES,
  HUNT_LLM_CONCURRENCY, HUNT_LLM_MAX_TOKENS, HUNT_LLM_TIMEOUT, HUNT_LLM_RETRIES
EOF
      exit 0
      ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

# ---------- apply flags to env ----------
[[ -n "${TOPN_ARG:-}"   ]] && export HUNT_TOPN="$TOPN_ARG"
[[ -n "${LIMIT_ARG:-}"  ]] && export HUNT_LIMIT="$LIMIT_ARG"
[[ -n "${MINSZ_ARG:-}"  ]] && export HUNT_MIN_SIZE="$MINSZ_ARG"
[[ -n "${NO_CAPA:-}"    ]] && export HUNT_CAPA=
[[ -n "${NO_YARA:-}"    ]] && export HUNT_YARA=
if [[ -n "${SKIP_LLM:-}" ]]; then export LLM_ENDPOINT=; export LLM_MODEL=; fi

# ---------- setup logging ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p work/logs
STAMP="$(date +%Y%m%d-%H%M%S)"
LOG="work/logs/pipeline.${STAMP}.log"
exec > >(stdbuf -oL -eL tee -a "$LOG") 2>&1

echo "==============================================="
echo " Function Hunt → Humanize pipeline"
echo " Timestamp:    $STAMP"
echo " Log:          $LOG"
echo "-----------------------------------------------"
echo " LLM_ENDPOINT: ${LLM_ENDPOINT:-<unset>}"
echo " LLM_MODEL:    ${LLM_MODEL:-<unset>}"
echo " HUNT_TOPN:    ${HUNT_TOPN:-<unset>}   HUNT_LIMIT: ${HUNT_LIMIT:-<unset>}   HUNT_MIN_SIZE: ${HUNT_MIN_SIZE:-<unset>}"
echo " CAPA:         ${HUNT_CAPA:+on}${HUNT_CAPA:+" (on)"}${HUNT_CAPA:+" "}"
echo " YARA:         ${HUNT_YARA:+on}${HUNT_YARA:+" (on)"}${HUNT_YARA:+" "}"
[[ -n "${GEN_RC:-}"   ]] && echo " gen-rc:       enabled"
[[ -n "${SKIP_LLM:-}" ]] && echo " LLM:          skipped"
echo "==============================================="

# Require LLM unless explicitly skipped
if [[ -z "${SKIP_LLM:-}" ]]; then
  if [[ -z "${LLM_ENDPOINT:-}" || -z "${LLM_MODEL:-}" ]]; then
    echo "[error] LLM not configured. Set LLM_ENDPOINT and LLM_MODEL, or run with --skip-llm."
    exit 2
  fi
  # Quick reachability hint
  if ! curl -sSf -m 2 -H 'Content-Type: application/json' \
      -d '{"model":"'"${LLM_MODEL:-}"'","messages":[{"role":"user","content":"ping"}],"max_tokens":8}' \
      "${LLM_ENDPOINT}" >/dev/null 2>&1; then
    echo "[warn] LLM endpoint not responding; labeling may fall back."
  else
    echo "[ok] LLM endpoint responding."
  fi
fi

# ---------- 1) Analyze ----------
echo "[stage] analyze…"
python3 tools/function_hunt/run_autodiscover.py

JSONL="work/hunt/functions.labeled.jsonl"
if [[ ! -s "$JSONL" ]]; then
  echo "[error] expected mapping not found: $JSONL"
  echo "        Did analyze fail earlier in the log? Check $LOG"
  exit 1
fi
echo "[ok] mapping ready: $JSONL"

# ---------- 2) Humanize (auto-discover src/out unless provided) ----------
_autodiscover_src() {
  if [[ -n "${SRC_DIR_ARG:-}" ]]; then
    echo "$SRC_DIR_ARG"; return
  fi
  if [[ -d "work/recovered_project/src" ]]; then
    echo "work/recovered_project/src"; return
  fi
  local cand
  cand="$(find work -maxdepth 3 -type d -name src -printf '%T@ %p\n' 2>/dev/null \
          | sort -nr | awk 'NR==1{print $2}')"
  if [[ -n "$cand" ]]; then echo "$cand"; return; fi
  echo ""
}

_autodiscover_out() {
  if [[ -n "${OUT_DIR_ARG:-}" ]]; then
    echo "$OUT_DIR_ARG"; return
  fi
  local src="$1"
  if [[ -z "$src" ]]; then echo "work/recovered_project_human"; return; fi
  local parent; parent="$(dirname "$src")"
  local base;   base="$(basename "$parent")"
  echo "$(dirname "$parent")/${base}_human"
}

SRC_DIR="$(_autodiscover_src)"
OUT_DIR="$(_autodiscover_out "$SRC_DIR")"

if [[ -z "$SRC_DIR" || ! -d "$SRC_DIR" ]]; then
  echo "[error] could not locate source dir to humanize."
  echo "        Try: ./humanize.sh --src-dir work/recovered_project/src --out-dir work/recovered_project_human"
  exit 2
fi

echo "[stage] humanize…"
echo "  src : $SRC_DIR"
echo "  out : $OUT_DIR"
python3 tools/humanize_source.py \
  --src-dir "$SRC_DIR" \
  --out-dir "$OUT_DIR" \
  --mapping "$JSONL"

# ---------- 3) (optional) Generate Windows app.rc ----------
if [[ -n "${GEN_RC:-}" ]]; then
  echo "[stage] generate app.rc…"
  python3 generate_windows_build.py || true
fi

echo "==============================================="
echo "[done] pipeline complete"
echo "Artifacts:"
echo "  - work/hunt/report.md"
echo "  - work/hunt/functions.labeled.jsonl"
echo "  - $OUT_DIR  (humanized sources)"
[[ -n "${GEN_RC:-}" ]] && echo "  - work/recovered_project_win/res/app.rc (if assets exist)"
echo "Log saved to: $LOG"
echo "==============================================="

