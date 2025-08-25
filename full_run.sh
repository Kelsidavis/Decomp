#!/usr/bin/env bash
# full_run.sh — pre-unpack → export via docker (entrypoint) → analyze+humanize
# - Guard against sourcing; must be executed
# - Heartbeat is always cleaned up via traps on EXIT/INT/TERM
set -Eeuo pipefail

# -------- guard: don't allow sourcing --------
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  echo "[error] Don't source this script. Run it as: ./full_run.sh"
  return 2 2>/dev/null || exit 2
fi

# -------------------- defaults / config --------------------
: "${WORK_DIR:=work}"
: "${GHIDRA_IMAGE:=decomp-ghidra-llm:latest}"   # slim exporter image with entrypoint
: "${GHIDRA_SCRIPT:=simple_export.py}"
if [[ -d "ghidra_scripts" ]]; then
  GHIDRA_SCRIPT_DIR="ghidra_scripts"
elif [[ -d "tools/ghidra_scripts" ]]; then
  GHIDRA_SCRIPT_DIR="tools/ghidra_scripts"
else
  GHIDRA_SCRIPT_DIR="ghidra_scripts"
fi

: "${LLM_ENDPOINT:=http://127.0.0.1:8080/v1/chat/completions}"
: "${LLM_MODEL:=Qwen3-14B-UD-Q5_K_XL.gguf}"

: "${HUNT_TOPN:=1000}"
: "${HUNT_MIN_SIZE:=0}"
: "${HUNT_CACHE:=1}"
: "${HUNT_RESUME:=1}"
: "${ENABLE_CAPA:=1}"
: "${ENABLE_YARA:=1}"
: "${ENABLE_FLOSS:=1}"

: "${HEARTBEAT_SECS:=30}"
: "${GHIDRA_TIMEOUT:=1800}"

mkdir -p "$WORK_DIR/logs" "$WORK_DIR/snapshots" "$WORK_DIR/gh_proj"

STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_LOG="$WORK_DIR/logs/full_run.${STAMP}.log"

# Clean previous "latest" pointer; keep only this run’s log if desired
: "${CLEAN_OLD_LOGS:=1}"
rm -f "$WORK_DIR/logs/latest_full_run.log" 2>/dev/null || true
ln -sfn "$(basename "$RUN_LOG")" "$WORK_DIR/logs/latest_full_run.log"
if [[ "$CLEAN_OLD_LOGS" == "1" ]]; then
  find "$WORK_DIR/logs" -maxdepth 1 -type f -name 'full_run.*.log' \
    ! -name "$(basename "$RUN_LOG")" -delete 2>/dev/null || true
fi

# Pretty timestamp wrapper for piped logs
_fmt() { while IFS= read -r line; do printf '[%s] %s\n' "$(date +%T)" "$line"; done; }

# -------- heartbeat (auto-stops via trap) --------
HB_PID=""
start_hb() {
  (
    parent_pid=$$
    while :; do
      # stop if parent pid no longer exists
      kill -0 "$parent_pid" 2>/dev/null || exit 0
      echo "[hb] alive"
      sleep "${HEARTBEAT_SECS}"
    done
  ) & HB_PID=$!
}
stop_hb() {
  if [[ -n "${HB_PID}" ]]; then
    kill "${HB_PID}" 2>/dev/null || true
    wait "${HB_PID}" 2>/dev/null || true
    HB_PID=""
  fi
}

cleanup() {
  ec=$?
  stop_hb
  exit "$ec"
}
trap cleanup EXIT INT TERM

# Stage timing helpers
stage() { STAGE_NAME="$1"; STAGE_T0="$(date +%s)"; echo "[$(date +%T)] >>> $STAGE_NAME …"; }
stage_done() { local t1="$(date +%s)"; printf "[%s] <<< %s done in %ds\n" "$(date +%T)" "$STAGE_NAME" "$((t1-STAGE_T0))"; }

# Log header
{
  echo "================================================"
  echo " Decomp full run"
  echo " Timestamp:     ${STAMP}"
  echo " Log:           ${RUN_LOG}"
  echo " Work dir:      ${WORK_DIR}"
  echo " LLM:           ${LLM_MODEL} @ ${LLM_ENDPOINT}"
  echo " HUNT_TOPN:     ${HUNT_TOPN}   HUNT_MIN: ${HUNT_MIN_SIZE}"
  echo " Resume/Cache:  ${HUNT_RESUME}/${HUNT_CACHE}"
  echo " CAPA/YARA:     ${ENABLE_CAPA}/${ENABLE_YARA}   FLOSS: ${ENABLE_FLOSS}"
  echo " Export script: ${GHIDRA_SCRIPT_DIR}/${GHIDRA_SCRIPT}"
  echo " REIMPL:        threshold=${REIMPL_MIN_CONF:-0.78}  max_fns=${REIMPL_MAX_FNS:-120}"
  echo "================================================"
} | _fmt | tee -a "$RUN_LOG"

# -------------------- autodiscover input binary --------------------
if [[ -z "${HUNT_BIN:-}" ]]; then
  cand="$(find "$WORK_DIR" -maxdepth 1 -type f -iname '*.exe' -printf '%s %p\n' 2>/dev/null | sort -nr | head -n1 | awk '{sub($1 FS,"");print}')"
  [[ -n "$cand" ]] && export HUNT_BIN="$cand"
fi
if [[ -z "${HUNT_BIN:-}" || ! -f "$HUNT_BIN" ]]; then
  echo "[full] ERROR: no input EXE found (set HUNT_BIN or place one under $WORK_DIR)" | _fmt | tee -a "$RUN_LOG"
  exit 2
fi
echo "[full] autodiscovered binary: ${HUNT_BIN}" | _fmt | tee -a "$RUN_LOG"

# -------------------- pre-unpack (SFX/wrappers) --------------------
stage "pre-unpack"; start_hb
python3 tools/pre_unpack.py \
  --bin "$HUNT_BIN" \
  --out "$WORK_DIR/extracted" \
  --work "$WORK_DIR" 2>&1 | _fmt | tee -a "$RUN_LOG" || true

if [[ -f "$WORK_DIR/primary_bin.txt" ]]; then
  host_primary="$(<"$WORK_DIR/primary_bin.txt")"
  case "$host_primary" in
    "$PWD/$WORK_DIR"/*) rel="${host_primary#"$PWD/$WORK_DIR/"}"; echo "/work/$rel" > "$WORK_DIR/primary_bin.txt" ;;
    /work/*) : ;;
    *)
      if [[ "$host_primary" == *"/work/"* ]]; then
        tail="/${host_primary#*"/work/"}"; echo "/work/${tail#/work/}" > "$WORK_DIR/primary_bin.txt"
      elif [[ "$HUNT_BIN" == "$PWD/$WORK_DIR/"* ]]; then
        rel="${HUNT_BIN#"$PWD/$WORK_DIR/"}"; echo "/work/$rel" > "$WORK_DIR/primary_bin.txt"
      fi
      ;;
  esac
  echo "[full] using unpacked primary: $(<"$WORK_DIR/primary_bin.txt")" | _fmt | tee -a "$RUN_LOG"
else
  if [[ "$HUNT_BIN" == "$PWD/$WORK_DIR/"* ]]; then
    rel="${HUNT_BIN#"$PWD/$WORK_DIR/"}"; echo "/work/$rel" > "$WORK_DIR/primary_bin.txt"
    echo "[full] primary (no-op unpack): /work/$rel" | _fmt | tee -a "$RUN_LOG"
  elif [[ "$HUNT_BIN" == "$WORK_DIR/"* ]]; then
    rel="${HUNT_BIN#"$WORK_DIR/"}"; echo "/work/$rel" > "$WORK_DIR/primary_bin.txt"
    echo "[full] primary (no-op unpack): /work/$rel" | _fmt | tee -a "$RUN_LOG"
  fi
fi
stop_hb; stage_done

# -------------------- ensure export JSON exists --------------------
base="$(basename "${HUNT_BIN%.*}")"
OUT_HOST="$WORK_DIR/snapshots/${base}_out.json"
OUT_CONT="/work/snapshots/${base}_out.json"

if [[ -s "$OUT_HOST" ]]; then
  echo "[full] export ready: $OUT_HOST" | _fmt | tee -a "$RUN_LOG"
else
  echo "[full] no *_out.json found — invoking Ghidra exporter…" | _fmt | tee -a "$RUN_LOG"
  stage "export (docker)"; start_hb
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp/gh_user \
    -e XDG_CONFIG_HOME=/tmp/gh_user/.config \
    -e JAVA_HOME=/opt/java/openjdk \
    -e GHIDRA_JAVA_HOME=/opt/java/openjdk \
    -v "$PWD/$WORK_DIR:/work" \
    -v "$PWD/$GHIDRA_SCRIPT_DIR:/scripts" \
    -e OUT_JSON="$OUT_CONT" \
    -e GHIDRA_PROJECT_DIR="/tmp/gh_proj" \
    -e GHIDRA_PROJECT_NAME="myproj" \
    -e GHIDRA_TIMEOUT="$GHIDRA_TIMEOUT" \
    -e HOST_WORK_DIR="$PWD/$WORK_DIR" \
    "$GHIDRA_IMAGE" 2>&1 | _fmt | tee -a "$RUN_LOG"
  stop_hb; stage_done

  if [[ ! -s "$OUT_HOST" ]]; then
    echo "[full] ERROR: export failed to produce $OUT_HOST" | _fmt | tee -a "$RUN_LOG"
    exit 3
  fi
fi

# -------------------- analyze + humanize --------------------
stage "analyze + humanize"; start_hb
export LLM_ENDPOINT LLM_MODEL HUNT_TOPN HUNT_MIN_SIZE HUNT_CACHE ENABLE_CAPA ENABLE_YARA ENABLE_FLOSS
./humanize.sh 2>&1 | _fmt | tee -a "$RUN_LOG"
stop_hb; stage_done

echo "[full] DONE. See log: $RUN_LOG" | _fmt | tee -a "$RUN_LOG"

