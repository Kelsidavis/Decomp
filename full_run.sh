#!/usr/bin/env bash
# full_run.sh — end-to-end: autodiscover → pre-unpack → ensure export → analyze+humanize → (optional) reimplement
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
: "${REIMPL:=1}"

# AST fake headers (vendored or provided by you)
: "${FAKE_LIBC_DIR:=$PWD/tools/fake_libc_include}"
export FAKE_LIBC_DIR

# Ghidra export settings
: "${GHIDRA_IMAGE:=decomp-ghidra-llm:latest}"   # slim exporter image
: "${GHIDRA_TIMEOUT:=1800}"                      # seconds
: "${GHIDRA_SCRIPT:=simple_export.py}"           # exporter script file name

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

mkdir -p "$WORK_DIR/logs" "$WORK_DIR/snapshots"
STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_LOG="$WORK_DIR/logs/full_run.${STAMP}.log"

# Export core env for children
export WORK_DIR LLM_ENDPOINT LLM_MODEL HUNT_TOPN HUNT_MIN_SIZE HUNT_CACHE HUNT_RESUME ENABLE_CAPA ENABLE_YARA ENABLE_FLOSS
export REIMPL_THRESHOLD REIMPL_MAX_FNS

# --------------- Ghidra script dir autodetect ---------------
if [[ -d "ghidra_scripts" && -f "ghidra_scripts/${GHIDRA_SCRIPT}" ]]; then
  GHIDRA_SCRIPT_DIR="ghidra_scripts"
elif [[ -d "tools/ghidra_scripts" && -f "tools/ghidra_scripts/${GHIDRA_SCRIPT}" ]]; then
  GHIDRA_SCRIPT_DIR="tools/ghidra_scripts"
else
  echo "[full] ERROR: cannot find ${GHIDRA_SCRIPT} in ghidra_scripts/ or tools/ghidra_scripts/" >&2
  exit 2
fi
export GHIDRA_SCRIPT GHIDRA_SCRIPT_DIR

# --------------- Formatter (timestamps + progress + heartbeat + stage timings) ---------------
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
      # heartbeat & stage timing from hunt
      if (line ~ /^\[hunt\] heartbeat/ || line ~ /^\[hunt\] >>> / || line ~ /^\[hunt\] <<< /) {
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
      local done="${BASHREMATCH[2]:-${BASH_REMATCH[2]}}"
      local total="${BASHREMATCH[3]:-${BASH_REMATCH[3]}}"
      local elapsed=$((now-start_epoch))
      local pct=0; (( total > 0 )) && pct=$(( 100*done / total ))
      local remain=-1
      if (( elapsed>0 && done>0 )); then remain=$(( (total-done) * elapsed / done )); fi
      local ETA="??:??:??"
      (( remain >= 0 )) && printf -v ETA "%02d:%02d:%02d" $((remain/3600)) $(((remain%3600)/60)) $((remain%60))
      printf "[%s] %s | %d%% | elapsed %02d:%02d:%02d | ETA %s\n" "$ts" "$line" "$pct" $((elapsed/3600)) $(((elapsed%3600)/60)) $((elapsed%60)) "$ETA"
      continue
    fi
    printf "[%s] %s\n" "$ts" "$line"
  done
}
_fmt() { if (( have_gawk )); then _ts_format_gawk; else _ts_format_sh; fi }

# --------------- Header ---------------
{
  echo "================================================"
  echo " Decomp full run"
  echo " Timestamp:     $STAMP"
  echo " Log:           $RUN_LOG"
  echo " Work dir:      $WORK_DIR"
  echo " LLM:           $LLM_MODEL @ $LLM_ENDPOINT"
  echo " HUNT_TOPN:     ${HUNT_TOPN}   HUNT_MIN: ${HUNT_MIN_SIZE}"
  echo " Resume/Cache:  ${HUNT_RESUME}/${HUNT_CACHE}"
  echo " CAPA/YARA:     ${ENABLE_CAPA}/${ENABLE_YARA}   FLOSS: ${ENABLE_FLOSS}"
  echo " Export script: ${GHIDRA_SCRIPT_DIR}/${GHIDRA_SCRIPT}"
  echo " REIMPL:        threshold=${REIMPL_THRESHOLD}  max_fns=${REIMPL_MAX_FNS}"
  echo "================================================"
} | tee -a "$RUN_LOG"

# --------------- Preflight ---------------
if (( DO_PREFLIGHT )); then
  if command -v python3 >/dev/null 2>&1 && [[ -f "tools/preflight.py" ]]; then
    stdbuf -oL -eL python3 tools/preflight.py --full --strict \
      2>&1 | _fmt | tee -a "$RUN_LOG"
  else
    echo "[preflight] tools/preflight.py not found or python3 missing; skipping" | tee -a "$RUN_LOG"
  fi
fi

# --------------- Optional reset ---------------
if (( RESET_RUN )); then
  rm -f "$WORK_DIR/hunt/functions.labeled.jsonl" \
        "$WORK_DIR/hunt/label.progress" \
        "$WORK_DIR/humanize.progress" \
        "$WORK_DIR/reimpl.progress"
  echo "[reset] cleared mapping/progress files" | tee -a "$RUN_LOG"
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
except SystemExit:
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
  echo "[full] ERROR: no candidate binary at $WORK_DIR root (expected *.exe|*.dll|*.bin) and no --bin specified." | tee -a "$RUN_LOG"
  exit 2
fi
export HUNT_BIN="$BIN"
echo "[full] autodiscovered binary: $HUNT_BIN" | tee -a "$RUN_LOG"

# --------------- Pre-unpack SFX/packed → choose primary payload ---------------
if command -v python3 >/dev/null 2>&1 && [[ -f "tools/pre_unpack.py" ]]; then
  stdbuf -oL -eL python3 tools/pre_unpack.py --bin "$HUNT_BIN" --out "$WORK_DIR/extracted" --work "$WORK_DIR" \
    2>&1 | _fmt | tee -a "$RUN_LOG" || true
  if [[ -f "$WORK_DIR/primary_bin.txt" ]]; then
    export HUNT_BIN="$(<"$WORK_DIR/primary_bin.txt")"
    echo "[full] using unpacked primary: $HUNT_BIN" | tee -a "$RUN_LOG"
  fi
else
  echo "[full] NOTE: tools/pre_unpack.py not found or python3 missing; continuing with $HUNT_BIN" | tee -a "$RUN_LOG"
fi

if [[ ! -f "$HUNT_BIN" ]]; then
  echo "[full] ERROR: input binary not found after pre-unpack: $HUNT_BIN" | tee -a "$RUN_LOG"
  exit 3
fi

# --------------- Ensure Ghidra export (*_out.json) ---------------
ensure_target_out() {
  local base out
  base="$(basename "${HUNT_BIN%.*}")"
  out="$WORK_DIR/snapshots/${base}_out.json"

  # If already present and non-empty, keep it
  if [[ -s "$out" ]]; then printf '%s\n' "$out"; return 0; fi

  echo "[full] no *_out.json found — invoking Ghidra exporter…" | tee -a "$RUN_LOG"
  mkdir -p "$WORK_DIR/gh_proj" "$WORK_DIR/snapshots"

  # Prefer local GHIDRA if available
  if [[ -n "${GHIDRA_HOME:-}" && -x "$GHIDRA_HOME/support/analyzeHeadless" ]]; then
    timeout "${GHIDRA_TIMEOUT}" "$GHIDRA_HOME/support/analyzeHeadless" "$WORK_DIR/gh_proj" myproj \
      -import "$HUNT_BIN" \
      -scriptPath "$GHIDRA_SCRIPT_DIR" \
      -postScript "$GHIDRA_SCRIPT" "$out" \
      -analysisTimeoutPerFile "${GHIDRA_TIMEOUT}" \
      -deleteProject \
      2>&1 | _fmt | tee -a "$RUN_LOG"
  else
    # Docker fallback (bind mount the script dir as /scripts)
    if ! command -v docker >/dev/null 2>&1; then
      echo "[full] ERROR: neither GHIDRA_HOME nor docker present for export" | tee -a "$RUN_LOG"
      return 1
    fi
    docker run --rm \
      -v "$PWD/$WORK_DIR:/work" \
      -v "$PWD/$GHIDRA_SCRIPT_DIR:/scripts" \
      "$GHIDRA_IMAGE" bash -lc "
        mkdir -p /work/gh_proj /work/snapshots
        timeout ${GHIDRA_TIMEOUT} \"\$GHIDRA_HOME\"/support/analyzeHeadless /work/gh_proj myproj \
          -import \"$HUNT_BIN\" \
          -scriptPath /scripts \
          -postScript \"$GHIDRA_SCRIPT\" \"/work/snapshots/${base}_out.json\" \
          -analysisTimeoutPerFile ${GHIDRA_TIMEOUT} \
          -deleteProject
      " 2>&1 | _fmt | tee -a "$RUN_LOG"
  fi

  [[ -s "$out" ]] && printf '%s\n' "$out" || return 1
}

TARGET_OUT="$(ensure_target_out || true)"
if [[ -z "${TARGET_OUT:-}" ]]; then
  echo "[full] ERROR: failed to generate *_out.json; cannot continue." | tee -a "$RUN_LOG"
  exit 4
fi
export HUNT_TARGET_OUT="$TARGET_OUT"
echo "[full] export ready: $HUNT_TARGET_OUT" | tee -a "$RUN_LOG"

# --------------- Analyze + Humanize ---------------
echo "[full] starting analyze + humanize…" | tee -a "$RUN_LOG"
stdbuf -oL -eL ./humanize.sh \
  2>&1 | _fmt | tee -a "$RUN_LOG"

# --------------- Re-implement ---------------
JSONL="$WORK_DIR/hunt/functions.labeled.jsonl"
SRC_HUMAN="$WORK_DIR/recovered_project_human/src"
OUT_REIMPL="$WORK_DIR/recovered_project_reimpl"

if [[ ! -s "$JSONL" ]]; then
  echo "[full] ERROR: mapping not found ($JSONL). Did analyze/humanize complete?" | tee -a "$RUN_LOG"
  exit 5
fi
if [[ ! -d "$SRC_HUMAN" ]]; then
  echo "[full] ERROR: humanized source not found ($SRC_HUMAN)" | tee -a "$RUN_LOG"
  exit 5
fi

if [[ "$REIMPL" == "1" ]]; then
  echo "[full] starting re-implementation…" | tee -a "$RUN_LOG"
  stdbuf -oL -eL python3 tools/reimplement.py \
    --src-dir "$SRC_HUMAN" \
    --out-dir "$OUT_REIMPL" \
    --mapping "$JSONL" \
    --threshold "$REIMPL_THRESHOLD" \
    --max-fns "$REIMPL_MAX_FNS" \
    2>&1 | _fmt | tee -a "$RUN_LOG"
else
  echo "[full] re-implementation disabled (REIMPL=0)" | tee -a "$RUN_LOG"
fi

{
  echo "[full] done."
  echo "Artifacts:"
  echo "  - export  : $HUNT_TARGET_OUT"
  echo "  - mapping : $JSONL"
  echo "  - human   : $SRC_HUMAN"
  echo "  - reimpl  : $OUT_REIMPL"
  echo "Log: $RUN_LOG"
} | tee -a "$RUN_LOG"

