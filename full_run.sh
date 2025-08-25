#!/usr/bin/env bash
# full_run.sh — pre-unpack → ghidra export → analyze(label) with LLM4D → humanize → (opt) reimplement with Qwen
# Requires: scripts/llm/llmctl.sh, profiles/{llm4d.env,qwen14.env}
set -Eeuo pipefail

# ---- guard: don't source ----
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  echo "[error] Don't source this script. Run it as: ./full_run.sh"
  return 2 2>/dev/null || exit 2
fi

# -------------------- config --------------------
: "${WORK_DIR:=work}"
: "${GHIDRA_IMAGE:=decomp-ghidra-llm:latest}"
: "${GHIDRA_SCRIPT:=simple_export.py}"
if [[ -d "ghidra_scripts" ]]; then
  GHIDRA_SCRIPT_DIR="ghidra_scripts"
elif [[ -d "tools/ghidra_scripts" ]]; then
  GHIDRA_SCRIPT_DIR="tools/ghidra_scripts"
else
  GHIDRA_SCRIPT_DIR="ghidra_scripts"
fi

# LLM control (single port 8080)
: "${LLMCTL:=scripts/llm/llmctl.sh}"
: "${LLM_PROFILE_LABEL:=llm4d}"     # for analyze/label
: "${LLM_PROFILE_REIMPL:=qwen14}"   # for re-implement

# Pipeline knobs
: "${HUNT_TOPN:=1000}"
: "${HUNT_MIN_SIZE:=0}"
: "${HUNT_CACHE:=1}"
: "${HUNT_RESUME:=1}"
: "${ENABLE_CAPA:=1}"
: "${ENABLE_YARA:=1}"
: "${ENABLE_FLOSS:=1}"

# Re-implement stage
: "${REIMPL_ENABLE:=1}"             # set 0 to skip
: "${REIMPL_MIN_CONF:=0.78}"
: "${REIMPL_MAX_FNS:=120}"

# Infra
: "${HEARTBEAT_SECS:=30}"
: "${GHIDRA_TIMEOUT:=1800}"
: "${CLEAN_OLD_LOGS:=1}"

mkdir -p "$WORK_DIR/logs" "$WORK_DIR/snapshots" "$WORK_DIR/gh_proj"

STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_LOG="$WORK_DIR/logs/full_run.${STAMP}.log"

# fresh "latest" pointer; prune old logs if desired
rm -f "$WORK_DIR/logs/latest_full_run.log" 2>/dev/null || true
ln -sfn "$(basename "$RUN_LOG")" "$WORK_DIR/logs/latest_full_run.log"
if [[ "$CLEAN_OLD_LOGS" == "1" ]]; then
  find "$WORK_DIR/logs" -maxdepth 1 -type f -name 'full_run.*.log' \
    ! -name "$(basename "$RUN_LOG")" -delete 2>/dev/null || true
fi

_fmt(){ while IFS= read -r line; do printf '[%s] %s\n' "$(date +%T)" "$line"; done; }

# ---- heartbeat (auto-clean) ----
HB_PID=""
start_hb(){
  (
    parent=$$
    while :; do
      kill -0 "$parent" 2>/dev/null || exit 0
      echo "[hb] alive"
      sleep "$HEARTBEAT_SECS"
    done
  ) & HB_PID=$!
}
stop_hb(){
  if [[ -n "${HB_PID}" ]]; then
    kill "$HB_PID" 2>/dev/null || true
    wait "$HB_PID" 2>/dev/null || true
    HB_PID=""
  fi
}
cleanup(){ ec=$?; stop_hb; exit "$ec"; }
trap cleanup EXIT INT TERM

stage(){ STAGE_NAME="$1"; STAGE_T0="$(date +%s)"; echo "[$(date +%T)] >>> $STAGE_NAME …"; }
stage_done(){ local t1="$(date +%s)"; printf "[%s] <<< %s done in %ds\n" "$(date +%T)" "$STAGE_NAME" "$((t1-STAGE_T0))"; }

# ---- LLM profile helpers (single port 8080) ----
need_llmctl(){ [[ -x "$LLMCTL" ]] || { echo "[full] ERROR: LLM controller not found: $LLMCTL" | _fmt | tee -a "$RUN_LOG"; exit 3; }; }
use_profile(){
  local prof="$1"
  need_llmctl
  # switch always (ensures only one server runs, VRAM safe)
  "$LLMCTL" switch "$prof" | _fmt | tee -a "$RUN_LOG"
  # export env for this stage
  eval "$("$LLMCTL" env "$prof")"
  export LLM_ENDPOINT LLM_MODEL
  echo "[full] LLM active: $prof  → $LLM_MODEL @ $LLM_ENDPOINT" | _fmt | tee -a "$RUN_LOG"
}

# ---- header ----
{
  echo "================================================"
  echo " Decomp full run"
  echo " Timestamp:     ${STAMP}"
  echo " Log:           ${RUN_LOG}"
  echo " Work dir:      ${WORK_DIR}"
  echo " HUNT_TOPN:     ${HUNT_TOPN}   HUNT_MIN: ${HUNT_MIN_SIZE}"
  echo " Resume/Cache:  ${HUNT_RESUME}/${HUNT_CACHE}"
  echo " CAPA/YARA:     ${ENABLE_CAPA}/${ENABLE_YARA}   FLOSS: ${ENABLE_FLOSS}"
  echo " Export script: ${GHIDRA_SCRIPT_DIR}/${GHIDRA_SCRIPT}"
  echo " LLM profiles:  label=${LLM_PROFILE_LABEL}  reimpl=${LLM_PROFILE_REIMPL}"
  echo " REIMPL:        enabled=${REIMPL_ENABLE}  threshold=${REIMPL_MIN_CONF}  max_fns=${REIMPL_MAX_FNS}"
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

# -------------------- export via docker (Ghidra headless) --------------------
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

# -------------------- analyze (label) with LLM4Decompile --------------------
stage "analyze(label) with profile: ${LLM_PROFILE_LABEL}"; start_hb
use_profile "$LLM_PROFILE_LABEL"
export HUNT_TOPN HUNT_MIN_SIZE HUNT_CACHE HUNT_RESUME ENABLE_CAPA ENABLE_YARA ENABLE_FLOSS
# Call the analyzer directly so we can change model later before humanize
stdbuf -oL -eL python3 tools/function_hunt/run_autodiscover.py 2>&1 | _fmt | tee -a "$RUN_LOG"
stop_hb; stage_done

JSONL="work/hunt/functions.labeled.jsonl"
if [[ ! -s "$JSONL" ]]; then
  echo "[full] ERROR: expected mapping not found: $JSONL" | _fmt | tee -a "$RUN_LOG"
  exit 4
fi

# -------------------- humanize (no LLM) --------------------
stage "humanize (AST-safe rename)"; start_hb
SRC_DIR="work/recovered_project/src"
OUT_DIR="work/recovered_project_human"
mkdir -p "$(dirname "$OUT_DIR")"
stdbuf -oL -eL python3 tools/humanize_source.py \
  --src-dir "$SRC_DIR" \
  --out-dir "$OUT_DIR" \
  --mapping "$JSONL" 2>&1 | _fmt | tee -a "$RUN_LOG"
stop_hb; stage_done

# -------------------- re-implement (Qwen) --------------------
if [[ "$REIMPL_ENABLE" == "1" ]]; then
  stage "re-implement with profile: ${LLM_PROFILE_REIMPL}"; start_hb
  use_profile "$LLM_PROFILE_REIMPL"
  export REIMPL_MIN_CONF REIMPL_MAX_FNS
  if [[ -x "./reimplement.sh" ]]; then
    stdbuf -oL -eL ./reimplement.sh 2>&1 | _fmt | tee -a "$RUN_LOG"
  else
    # Call python directly if no wrapper
    stdbuf -oL -eL python3 tools/reimplement.py \
      --src-dir "$OUT_DIR" \
      --mapping "$JSONL" \
      --min-conf "$REIMPL_MIN_CONF" \
      --max-fns "$REIMPL_MAX_FNS" 2>&1 | _fmt | tee -a "$RUN_LOG"
  fi
  stop_hb; stage_done
else
  echo "[full] re-implement disabled (REIMPL_ENABLE=0)" | _fmt | tee -a "$RUN_LOG"
fi

echo "[full] DONE. See log: $RUN_LOG" | _fmt | tee -a "$RUN_LOG"

