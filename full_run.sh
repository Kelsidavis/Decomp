#!/usr/bin/env bash
# full_run.sh — pre-unpack → ghidra export → analyze(label w/ LLM4D) → humanize → (opt) reimplement w/ Qwen
# Requires: scripts/llm/llmctl.sh, profiles/{llm4d.env,qwen14.env}, ghidra_scripts/simple_export.py
set -Eeuo pipefail

# If RUN_LOG isn't set yet, create a default one early so we can tail it on errors
: "${RUN_LOG:=work/logs/full_run.$(date +%Y%m%d-%H%M%S).log}"
mkdir -p "$(dirname "$RUN_LOG")"

# Set to 0 to disable the pause (or export PAUSE_ON_EXIT=0)
: "${PAUSE_ON_EXIT:=1}"

_pause_if_tty() { [[ "$PAUSE_ON_EXIT" == "1" && -t 0 && -t 1 ]]; }
_on_error() {
  local ec=$? line=${BASH_LINENO[0]} cmd=${BASH_COMMAND}
  echo -e "\n[full_run] ERROR exit=$ec at line $line: $cmd" | tee -a "$RUN_LOG"
  # show the last chunk of the run log so you see the cause
  tail -n 120 "$RUN_LOG" 2>/dev/null || true
  if _pause_if_tty; then read -rp "Press Enter to close..."; fi
  exit "$ec"
}
_on_exit() {
  local ec=$?
  [[ $ec -eq 0 ]] || return
  if _pause_if_tty; then read -rp "Press Enter to close..."; fi
}
trap _on_error ERR
trap _on_exit  EXIT

# ---- Rules directories (project-root/rules) ----
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$SCRIPT_DIR}"
RULES_DIR="${RULES_DIR:-$PROJECT_ROOT/rules}"

: "${CAPA_RULES:=$RULES_DIR/capa}"
: "${YARA_RULES_DIR:=$RULES_DIR/yara}"
export CAPA_RULES YARA_RULES_DIR

# Ensure our wrappers (e.g., bin/capa) are found first
export PATH="$PROJECT_ROOT/bin:$PATH"

echo "[full_run] CAPA_RULES=${CAPA_RULES}"
echo "[full_run] YARA_RULES_DIR=${YARA_RULES_DIR}"

: "${BOOTSTRAP_RULES:=0}"   # set to 1 to auto-clone rules on first run
if [[ "$BOOTSTRAP_RULES" == "1" ]]; then
  [[ -d "$CAPA_RULES/.git" ]] || { mkdir -p "$CAPA_RULES"; git clone --depth=1 https://github.com/mandiant/capa-rules "$CAPA_RULES"; }
  [[ -d "$YARA_RULES_DIR/.git" ]] || { mkdir -p "$YARA_RULES_DIR"; git clone --depth=1 https://github.com/Yara-Rules/rules "$YARA_RULES_DIR"; }
fi

# Gracefully disable CAPA/YARA when rules are missing
: "${ENABLE_CAPA:=1}"
: "${ENABLE_YARA:=1}"
if [[ "$ENABLE_CAPA" == "1" && ! -d "$CAPA_RULES" ]]; then
  echo "[full_run] WARN: CAPA_RULES not found at '$CAPA_RULES' → disabling CAPA." | tee -a "$RUN_LOG"
  ENABLE_CAPA=0
fi
if [[ "$ENABLE_YARA" == "1" && ! -d "$YARA_RULES_DIR" ]]; then
  echo "[full_run] WARN: YARA_RULES_DIR not found at '$YARA_RULES_DIR' → disabling YARA." | tee -a "$RUN_LOG"
  ENABLE_YARA=0
fi

# ---- FLOSS timeout (seconds) ----
: "${FLOSS_TIMEOUT:=600}"
export FLOSS_TIMEOUT
echo "[full_run] FLOSS_TIMEOUT=${FLOSS_TIMEOUT}s"

# ---- guard: don't source ----
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  echo "[error] Don't source this script. Run it as: ./full_run.sh"
  return 2 2>/dev/null || exit 2
fi

# -------------------- config --------------------
: "${WORK_DIR:=work}"

# LLM readiness grace for llmctl (tiny sleep after spawn)
: "${LLM_GRACE:=1.2}"
export LLM_GRACE

# Ghidra container & script location
: "${GHIDRA_IMAGE:=decomp-ghidra-llm:latest}"
if [[ -d "ghidra_scripts" ]]; then
  GHIDRA_SCRIPT_DIR="ghidra_scripts"
elif [[ -d "tools/ghidra_scripts" ]]; then
  GHIDRA_SCRIPT_DIR="tools/ghidra_scripts"
else
  GHIDRA_SCRIPT_DIR="ghidra_scripts"
fi
: "${GHIDRA_SCRIPT:=simple_export.py}"

# LLM control (single port 8080)
: "${LLMCTL:=scripts/llm/llmctl.sh}"
: "${LLM_PROFILE_LABEL:=llm4d}"     # for analyze/label
: "${LLM_PROFILE_REIMPL:=qwen14}"   # for re-implement

# Pipeline knobs
: "${HUNT_TOPN:=10000}"
: "${HUNT_MIN_SIZE:=0}"
: "${HUNT_CACHE:=1}"
: "${HUNT_RESUME:=1}"
: "${ENABLE_FLOSS:=1}"

# Exporter knobs (read by ghidra_scripts/simple_export.py inside container)
: "${GHIDRA_TIMEOUT:=9000}"          # headless wrapper will be allowed up to this many seconds
: "${EXPORT_FLUSH_EVERY:=500}"       # rewrite valid JSON every N functions
: "${DECOMPILE_SEC:=12}"             # per-function decompiler budget
: "${EXPORT_TOPN:=${HUNT_TOPN}}"     # mirror HUNT_TOPN unless explicitly overridden
: "${SKIP_PSEUDO:=0}"                # 1 = metadata-only export (no decompile text)

# Re-implement stage
: "${REIMPL_ENABLE:=1}"              # set 0 to skip reimplementation
: "${REIMPL_MIN_CONF:=0.78}"
: "${REIMPL_MAX_FNS:=120}"

# Infra
: "${HEARTBEAT_SECS:=30}"
: "${CLEAN_OLD_LOGS:=1}"             # prune older full_run.*.log files

mkdir -p "$WORK_DIR/logs" "$WORK_DIR/snapshots" "$WORK_DIR/gh_proj" 2>/dev/null || true

STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_LOG="$WORK_DIR/logs/full_run.${STAMP}.log"

# Start fresh: clear latest pointer and optionally old logs
rm -f "$WORK_DIR/logs/latest_full_run.log" 2>/dev/null || true
ln -sfn "$(basename "$RUN_LOG")" "$WORK_DIR/logs/latest_full_run.log"
if [[ "$CLEAN_OLD_LOGS" == "1" ]]; then
  find "$WORK_DIR/logs" -maxdepth 1 -type f -name 'full_run.*.log' \
    ! -name "$(basename "$RUN_LOG")" -delete 2>/dev/null || true
fi

# Pretty timestamp pipe
_fmt(){ while IFS= read -r line; do printf '[%s] %s\n' "$(date +%T)" "$line"; done; }

# ---- heartbeat (auto cleaned) ----
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

# ---- LLM profile helpers (ensures single server on port 8080) ----
need_llmctl(){ [[ -x "$LLMCTL" ]] || { echo "[full] ERROR: LLM controller not found: $LLMCTL" | _fmt | tee -a "$RUN_LOG"; exit 3; }; }
use_profile(){
  local prof="$1"
  need_llmctl
  "$LLMCTL" switch "$prof" | _fmt | tee -a "$RUN_LOG"
  # Export env for this stage
  eval "$("$LLMCTL" env "$prof")"
  export LLM_ENDPOINT LLM_MODEL
  echo "[full] LLM active: $prof  → $LLM_MODEL @ $LLM_ENDPOINT" | _fmt | tee -a "$RUN_LOG"
}

# ---- header ----
{
  echo "==============================================="
  echo " Decomp full run"
  echo " Timestamp:     ${STAMP}"
  echo " Log:           ${RUN_LOG}"
  echo " Work dir:      ${WORK_DIR}"
  echo " HUNT_TOPN:     ${HUNT_TOPN}   HUNT_MIN: ${HUNT_MIN_SIZE}"
  echo " Resume/Cache:  ${HUNT_RESUME}/${HUNT_CACHE}"
  echo " CAPA/YARA:     ${ENABLE_CAPA}/${ENABLE_YARA}   FLOSS: ${ENABLE_FLOSS}"
  echo " Export script: ${GHIDRA_SCRIPT_DIR}/${GHIDRA_SCRIPT}"
  echo " LLM profiles:  label=${LLM_PROFILE_LABEL}  reimpl=${LLM_PROFILE_REIMPL}"
  echo " REIMPL:        threshold=${REIMPL_MIN_CONF}  max_fns=${REIMPL_MAX_FNS}"
  echo "==============================================="
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

# Resolve container path for BINARY_PATH and /work/primary_bin.txt
BIN_CONT=""
if [[ -f "$WORK_DIR/primary_bin.txt" ]]; then
  host_primary="$(<"$WORK_DIR/primary_bin.txt")"
  case "$host_primary" in
    /work/*) BIN_CONT="$host_primary" ;;
    "$PWD/$WORK_DIR"/*)
      rel="${host_primary#"$PWD/$WORK_DIR/"}"; BIN_CONT="/work/$rel"
      echo "$BIN_CONT" > "$WORK_DIR/primary_bin.txt"
      ;;
    "$WORK_DIR"/*)
      rel="${host_primary#"$WORK_DIR/"}"; BIN_CONT="/work/$rel"
      echo "$BIN_CONT" > "$WORK_DIR/primary_bin.txt"
      ;;
    *)
      if [[ "$HUNT_BIN" == "$PWD/$WORK_DIR/"* ]]; then
        rel="${HUNT_BIN#"$PWD/$WORK_DIR/"}"; BIN_CONT="/work/$rel"
        echo "$BIN_CONT" > "$WORK_DIR/primary_bin.txt"
      else
        # fallback: copy file name only under /work
        BIN_CONT="/work/$(basename "$HUNT_BIN")"
        echo "$BIN_CONT" > "$WORK_DIR/primary_bin.txt"
      fi
      ;;
  esac
else
  if [[ "$HUNT_BIN" == "$PWD/$WORK_DIR/"* ]]; then
    rel="${HUNT_BIN#"$PWD/$WORK_DIR/"}"; BIN_CONT="/work/$rel"
  elif [[ "$HUNT_BIN" == "$WORK_DIR/"* ]]; then
    rel="${HUNT_BIN#"$WORK_DIR/"}"; BIN_CONT="/work/$rel"
  else
    BIN_CONT="/work/$(basename "$HUNT_BIN")"
  fi
  echo "$BIN_CONT" > "$WORK_DIR/primary_bin.txt"
fi
echo "[full] using unpacked primary: $BIN_CONT" | _fmt | tee -a "$RUN_LOG"
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
    -e GHIDRA_OVERRIDE_JAVA=1 \
    -v "$PWD/$WORK_DIR:/work" \
    -v "$PWD/$GHIDRA_SCRIPT_DIR:/scripts" \
    -e BINARY_PATH="$BIN_CONT" \
    -e OUT_JSON="$OUT_CONT" \
    -e GHIDRA_PROJECT_DIR="/tmp/gh_proj" \
    -e GHIDRA_PROJECT_NAME="myproj" \
    -e GHIDRA_TIMEOUT="$GHIDRA_TIMEOUT" \
    -e HOST_WORK_DIR="$PWD/$WORK_DIR" \
    -e EXPORT_FLUSH_EVERY="$EXPORT_FLUSH_EVERY" \
    -e EXPORT_TOPN="$EXPORT_TOPN" \
    -e DECOMPILE_SEC="$DECOMPILE_SEC" \
    -e SKIP_PSEUDO="$SKIP_PSEUDO" \
    "$GHIDRA_IMAGE" 2>&1 | _fmt | tee -a "$RUN_LOG"
  stop_hb; stage_done

  if [[ ! -s "$OUT_HOST" ]]; then
    echo "[full] ERROR: export failed to produce $OUT_HOST" | _fmt | tee -a "$RUN_LOG"
    exit 3
  fi
fi

echo "[diag] capa -> $(command -v capa)"
echo "[diag] yara -> $(command -v yara)"

# -------------------- analyze (label) with LLM4Decompile --------------------
stage "analyze(label) with profile: ${LLM_PROFILE_LABEL}"; start_hb
use_profile "$LLM_PROFILE_LABEL"
export HUNT_TOPN HUNT_MIN_SIZE HUNT_CACHE HUNT_RESUME ENABLE_CAPA ENABLE_YARA ENABLE_FLOSS
stdbuf -oL -eL python3 tools/function_hunt/run_autodiscover.py 2>&1 | _fmt | tee -a "$RUN_LOG"
stop_hb; stage_done

JSONL="$WORK_DIR/hunt/functions.labeled.jsonl"
if [[ ! -s "$JSONL" ]]; then
  echo "[full] ERROR: expected mapping not found: $JSONL" | _fmt | tee -a "$RUN_LOG"
  exit 4
fi

# -------------------- humanize (no LLM) --------------------
stage "humanize (AST-safe rename)"; start_hb
SRC_DIR="$WORK_DIR/recovered_project/src"
OUT_DIR="$WORK_DIR/recovered_project_human"
if [[ -d "$SRC_DIR" ]]; then
  mkdir -p "$(dirname "$OUT_DIR")"
  stdbuf -oL -eL python3 tools/humanize_source.py \
    --src-dir "$SRC_DIR" \
    --out-dir "$OUT_DIR" \
    --mapping "$JSONL" 2>&1 | _fmt | tee -a "$RUN_LOG"
else
  echo "[humanize] src not found ($SRC_DIR) — skipping" | _fmt | tee -a "$RUN_LOG"
fi
stop_hb; stage_done

# -------------------- re-implement (Qwen) --------------------
if [[ "$REIMPL_ENABLE" == "1" ]]; then
  stage "re-implement with profile: ${LLM_PROFILE_REIMPL}"; start_hb
  use_profile "$LLM_PROFILE_REIMPL"
  export REIMPL_MIN_CONF REIMPL_MAX_FNS
  if [[ -x "./reimplement.sh" ]]; then
    stdbuf -oL -eL ./reimplement.sh 2>&1 | _fmt | tee -a "$RUN_LOG"
  else
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

