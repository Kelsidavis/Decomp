#!/usr/bin/env bash
# full_run.sh — end-to-end: autodiscover → pre-unpack → analyze+humanize → reimplement
set -euo pipefail

# --------------- Defaults ---------------
: "${WORK_DIR:=work}"
: "${LLM_ENDPOINT:=http://127.0.0.1:8080/v1/chat/completions}"
: "${LLM_MODEL:=Qwen3-14B-UD-Q5_K_XL.gguf}"

# Hunt defaults
: "${HUNT_TOPN:=1000}"
: "${HUNT_MIN_SIZE:=0}"
: "${HUNT_CACHE:=1}"
: "${HUNT_RESUME:=1}"
: "${ENABLE_CAPA:=1}"
: "${ENABLE_YARA:=1}"
: "${ENABLE_FLOSS:=1}"

# Re-implementation defaults
: "${REIMPL_THRESHOLD:=0.78}"
: "${REIMPL_MAX_FNS:=120}"

DO_PREFLIGHT=1
RESET_RUN=0
USER_BIN=""

usage() {
  cat <<EOF
Usage: $0 [options]
  --no-preflight           Skip preflight checks
  --reset-run              Clear previous mapping/progress before run
  --bin <path>             Use this binary explicitly (skips autodiscovery)
  --topn <N>               Override HUNT_TOPN
  --min-size <N>           Override HUNT_MIN_SIZE
  --threshold <float>      Override REIMPL_THRESHOLD
  --max-fns <N>            Override REIMPL_MAX_FNS
  -h|--help                Show this help
EOF
}

# --------------- CLI ---------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-preflight) DO_PREFLIGHT=0; shift ;;
    --reset-run)    RESET_RUN=1; shift ;;
    --bin)          USER_BIN="${2:-}"; shift 2 ;;
    --topn)         export HUNT_TOPN="${2:-$HUNT_TOPN}"; shift 2 ;;
    --min-size)     export HUNT_MIN_SIZE="${2:-$HUNT_MIN_SIZE}"; shift 2 ;;
    --threshold)    export REIMPL_THRESHOLD="${2:-$REIMPL_THRESHOLD}"; shift 2 ;;
    --max-fns)      export REIMPL_MAX_FNS="${2:-$REIMPL_MAX_FNS}"; shift 2 ;;
    -h|--help)      usage; exit 0 ;;
    *) echo "[warn] unknown arg: $1" >&2; shift ;;
  esac
done

# --------------- Setup ---------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p "$WORK_DIR/logs"
STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_LOG="$WORK_DIR/logs/full_run.${STAMP}.log"

# Make sure children inherit these (fixes preflight LLM warning)
export WORK_DIR LLM_ENDPOINT LLM_MODEL HUNT_TOPN HUNT_MIN_SIZE HUNT_CACHE HUNT_RESUME ENABLE_CAPA ENABLE_YARA ENABLE_FLOSS
export REIMPL_THRESHOLD REIMPL_MAX_FNS

# tee everything to the log
exec > >(stdbuf -oL -eL tee -a "$RUN_LOG") 2>&1

echo "================================================"
echo " Decomp full run"
echo " Timestamp:     $STAMP"
echo " Log:           $RUN_LOG"
echo " Work dir:      $WORK_DIR"
echo " LLM:           $LLM_MODEL @ $LLM_ENDPOINT"
echo " HUNT_TOPN:     ${HUNT_TOPN}   HUNT_MIN: ${HUNT_MIN_SIZE}"
echo " Resume/Cache:  ${HUNT_RESUME}/${HUNT_CACHE}"
echo " CAPA/YARA:     ${ENABLE_CAPA}/${ENABLE_YARA}   FLOSS: ${ENABLE_FLOSS}"
echo " REIMPL:        threshold=${REIMPL_THRESHOLD}  max_fns=${REIMPL_MAX_FNS}"
echo "================================================"

# optional preflight
if (( DO_PREFLIGHT )); then
  if command -v python3 >/dev/null 2>&1; then
    python3 tools/preflight.py --full || echo "[preflight] continuing despite warnings"
  else
    echo "[preflight] python3 not found; skipping"
  fi
fi

# optional reset
if (( RESET_RUN )); then
  rm -f "$WORK_DIR/hunt/functions.labeled.jsonl" \
        "$WORK_DIR/hunt/label.progress" \
        "$WORK_DIR/humanize.progress" \
        "$WORK_DIR/reimpl.progress"
  echo "[reset] cleared mapping/progress files"
fi

# --------------- Autodiscover binary (work/ root only) ---------------
discover_bin() {
  local root="$WORK_DIR"
  local cand=""

  if [[ -n "$USER_BIN" && -f "$USER_BIN" ]]; then printf '%s\n' "$USER_BIN"; return 0; fi
  if [[ -n "${HUNT_BIN:-}" && -f "$HUNT_BIN" ]]; then printf '%s\n' "$HUNT_BIN"; return 0; fi
  if [[ -f "$root/primary_bin.txt" ]]; then cand="$(<"$root/primary_bin.txt")"; [[ -f "$cand" ]] && { printf '%s\n' "$cand"; return 0; }; fi

  local best="" best_size=0
  shopt -s nullglob
  for f in "$root"/*; do
    [[ -f "$f" ]] || continue
    case "${f,,}" in *.exe|*.dll|*.bin) ;; *) continue ;; esac
    if python3 - "$f" <<'PY'
import sys
p=sys.argv[1]
try:
    with open(p,'rb') as fh:
        d=fh.read(0x100)
    if d[:2] != b'MZ': raise SystemExit(1)
    if len(d) < 0x40: raise SystemExit(1)
    e = int.from_bytes(d[0x3C:0x40], 'little')
    if e <= 0 or e > 100_000_000: raise SystemExit(1)
    raise SystemExit(0)
except SystemExit as e:
    raise
except Exception:
    raise SystemExit(1)
PY
    then
      size=$(stat -c%s "$f" 2>/dev/null || wc -c <"$f")
      if (( size > best_size )); then best="$f"; best_size=$size; fi
    fi
  done
  shopt -u nullglob
  [[ -n "$best" ]] && printf '%s\n' "$best" || return 1
}

BIN="$(discover_bin || true)"
if [[ -z "${BIN:-}" ]]; then
  echo "[full] ERROR: no candidate binary at $WORK_DIR root (expected *.exe|*.dll|*.bin) and no --bin specified."
  exit 2
fi
export HUNT_BIN="$BIN"
echo "[full] autodiscovered binary: $HUNT_BIN"

# Pre-unpack SFX/packed → choose primary payload
if command -v python3 >/dev/null 2>&1; then
  python3 tools/pre_unpack.py --bin "$HUNT_BIN" --out "$WORK_DIR/extracted" --work "$WORK_DIR" || true
  if [[ -f "$WORK_DIR/primary_bin.txt" ]]; then
    export HUNT_BIN="$(<"$WORK_DIR/primary_bin.txt")"
    echo "[full] using unpacked primary: $HUNT_BIN"
  fi
else
  echo "[full] WARN: python3 missing; skipping pre-unpack"
fi

if [[ ! -f "$HUNT_BIN" ]]; then
  echo "[full] ERROR: input binary not found after pre-unpack: $HUNT_BIN"
  exit 3
fi

# Analyze + Humanize
echo "[full] starting analyze + humanize…"
./humanize.sh || { echo "[full] humanize pipeline failed"; exit 4; }

# Re-implement (always)
JSONL="$WORK_DIR/hunt/functions.labeled.jsonl"
SRC_HUMAN="$WORK_DIR/recovered_project_human/src"
OUT_REIMPL="$WORK_DIR/recovered_project_reimpl"

if [[ ! -s "$JSONL" ]]; then
  echo "[full] ERROR: mapping not found ($JSONL). Did analyze/humanize complete?"
  exit 5
fi
if [[ ! -d "$SRC_HUMAN" ]]; then
  echo "[full] ERROR: humanized source not found ($SRC_HUMAN)"
  exit 5
fi

echo "[full] starting re-implementation…"
python3 tools/reimplement.py \
  --src-dir "$SRC_HUMAN" \
  --out-dir "$OUT_REIMPL" \
  --mapping "$JSONL" \
  --threshold "$REIMPL_THRESHOLD" \
  --max-fns "$REIMPL_MAX_FNS"

echo "[full] done."
echo "Artifacts:"
echo "  - mapping : $JSONL"
echo "  - human   : $SRC_HUMAN"
echo "  - reimpl  : $OUT_REIMPL"
echo "Log: $RUN_LOG"

