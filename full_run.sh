#!/usr/bin/env bash
# full_run.sh — pre-unpack → ghidra export → analyze(label w/ LLM4D) → humanize → (opt) reimplement w/ Qwen
# Requires: scripts/llm/llmctl.sh, profiles/{llm4d.env,qwen14.env}, ghidra_scripts/simple_export.py
set -Eeuo pipefail

# If RUN_LOG isn't set yet, create a default one early so we can tail it on errors
: "${RUN_LOG:=work/logs/full_run.$(date +%Y%m%d-%H%M%S).log}"
mkdir -p "$(dirname "$RUN_LOG")"

# Pretty timestamp pipe
_fmt(){ while IFS= read -r line; do printf '[%s] %s\n' "$(date +%T)" "$line"; done; }

# Stream a command into the logfile while preserving the command's actual exit code
runlog() {
  # $@ is the command to run
  set +o pipefail
  "$@" 2>&1 | _fmt | tee -a "$RUN_LOG"
  local ec=${PIPESTATUS[0]}
  set -o pipefail
  return "$ec"
}

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

# ---- Rules & signatures (project-root/rules) ----
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$SCRIPT_DIR}"
RULES_DIR="${RULES_DIR:-$PROJECT_ROOT/rules}"

: "${CAPA_RULES:=$RULES_DIR/capa}"
: "${YARA_RULES_DIR:=$RULES_DIR/yara}"
: "${CAPA_SIGNATURES:=$RULES_DIR/sigs}"   # capa "sigs" bundle (library/function IDs)
export CAPA_RULES YARA_RULES_DIR CAPA_SIGNATURES

# Force python -m capa to see our data files (helps some versions)
export CAPA_DATADIR="$CAPA_SIGNATURES"

# Make sure our wrappers win
export PATH="$PROJECT_ROOT/bin:$PATH"

{
  echo "[diag] PATH prefix: $PROJECT_ROOT/bin"
  echo "[diag] capa -> $(command -v capa)"
  echo "[diag] yara -> $(command -v yara)"
  echo "[diag] CAPA_RULES=$CAPA_RULES"
  echo "[diag] CAPA_SIGNATURES=$CAPA_SIGNATURES"
  echo "[diag] CAPA_DATADIR=$CAPA_DATADIR"
  echo "[diag] YARA_RULES_DIR=$YARA_RULES_DIR"
  echo "[diag] timeout -> $(command -v timeout)"
  echo "[diag] REIMPL_ENABLE=$REIMPL_ENABLE"
} | _fmt | tee -a "$RUN_LOG"
echo "[full_run] CAPA_RULES=${CAPA_RULES}"
echo "[full_run] YARA_RULES_DIR=${YARA_RULES_DIR}"
echo "[full_run] CAPA_SIGNATURES=${CAPA_SIGNATURES}"

: "${BOOTSTRAP_RULES:=0}"   # set to 1 to auto-clone rules/signatures on first run
if [[ "$BOOTSTRAP_RULES" == "1" ]]; then
  [[ -d "$CAPA_RULES/.git" ]] || { mkdir -p "$CAPA_RULES"; git clone --depth=1 https://github.com/mandiant/capa-rules "$CAPA_RULES"; }
  [[ -d "$YARA_RULES_DIR/.git" ]] || { mkdir -p "$YARA_RULES_DIR"; git clone --depth=1 https://github.com/Yara-Rules/rules "$YARA_RULES_DIR"; }
  # fetch capa signatures (sparse checkout of only sigs/)
  if [[ ! -d "$CAPA_SIGNATURES" || -z "$(ls -A "$CAPA_SIGNATURES" 2>/dev/null)" ]]; then
    echo "[rules] fetching capa signatures into $CAPA_SIGNATURES" | _fmt | tee -a "$RUN_LOG"
    tmpdir="$(mktemp -d)"
    git -C "$tmpdir" clone --depth=1 --filter=blob:none --sparse https://github.com/mandiant/capa
    git -C "$tmpdir/capa" sparse-checkout set sigs
    mkdir -p "$CAPA_SIGNATURES"
    rsync -a "$tmpdir/capa/sigs/" "$CAPA_SIGNATURES/" 2>/dev/null || cp -R "$tmpdir/capa/sigs/." "$CAPA_SIGNATURES/"
    rm -rf "$tmpdir"
  fi
fi

# Gracefully disable CAPA/YARA when inputs are missing
: "${ENABLE_CAPA:=1}"
: "${ENABLE_YARA:=1}"
if [[ "$ENABLE_CAPA" == "1" && ! -d "$CAPA_RULES" ]]; then
  echo "[full_run] WARN: CAPA_RULES not found at '$CAPA_RULES' → disabling CAPA." | tee -a "$RUN_LOG"
  ENABLE_CAPA=0
fi
# also require signatures for capa
if [[ "$ENABLE_CAPA" == "1" && ( ! -d "$CAPA_SIGNATURES" || -z "$(ls -A "$CAPA_SIGNATURES" 2>/dev/null)" ) ]]; then
  echo "[full_run] WARN: CAPA_SIGNATURES missing/empty at '$CAPA_SIGNATURES' → disabling CAPA." | tee -a "$RUN_LOG"
  ENABLE_CAPA=0
fi
if [[ "$ENABLE_YARA" == "1" && ! -d "$YARA_RULES_DIR" ]]; then
  echo "[full_run] WARN: YARA_RULES_DIR not found at '$YARA_RULES_DIR' → disabling YARA." | tee -a "$RUN_LOG"
  ENABLE_YARA=0
fi

# ---- FLOSS timeout (seconds) ----
: "${FLOSS_TIMEOUT:=2000}"
export FLOSS_TIMEOUT
# run_autodiscover.py reads HUNT_FLOSS_TIMEOUT, so mirror it here
: "${HUNT_FLOSS_TIMEOUT:=${FLOSS_TIMEOUT}}"
export HUNT_FLOSS_TIMEOUT
echo "[full_run] FLOSS_TIMEOUT=${FLOSS_TIMEOUT}s"
echo "[full_run] HUNT_FLOSS_TIMEOUT=${HUNT_FLOSS_TIMEOUT}s"

# ---- CAPA timeout (seconds) ----
: "${CAPA_TIMEOUT:=1200}"
export CAPA_TIMEOUT
echo "[full_run] CAPA_TIMEOUT=${CAPA_TIMEOUT}s"

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
: "${HUNT_TOPN:=50000}"
: "${HUNT_MIN_SIZE:=5}"
: "${HUNT_CACHE:=1}"
: "${HUNT_RESUME:=1}"
: "${ENABLE_FLOSS:=1}"

# Exporter knobs (read by ghidra_scripts/simple_export.py inside container)
: "${GHIDRA_TIMEOUT:=172800}"          # headless wrapper will be allowed up to this many seconds
: "${EXPORT_FLUSH_EVERY:=1000}"       # rewrite valid JSON every N functions
: "${DECOMPILE_SEC:=7}"             # per-function decompiler budget
: "${EXPORT_TOPN:=${HUNT_TOPN}}"     # mirror HUNT_TOPN unless explicitly overridden
: "${SKIP_PSEUDO:=0}"                # 1 = metadata-only export (no decompile text)

# Re-implement stage
: "${REIMPL_ENABLE:=1}"              # set 0 to skip reimplementation
: "${REIMPL_MIN_CONF:=0.78}"
: "${REIMPL_MAX_FNS:=10000}"

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
  if ! runlog "$LLMCTL" switch "$prof"; then
    echo "[full] WARN: LLM profile switch failed for '$prof' — continuing without this stage" | _fmt | tee -a "$RUN_LOG"
    return 1
  fi
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
  mkdir -p "$WORK_DIR/recovered_project/src"
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
    -e OUT_SRC_DIR="/work/recovered_project/src" \
    -e GHIDRA_PROJECT_DIR="/tmp/gh_proj" \
    -e GHIDRA_PROJECT_NAME="myproj" \
    -e GHIDRA_TIMEOUT="$GHIDRA_TIMEOUT" \
    -e HOST_WORK_DIR="$PWD/$WORK_DIR" \
    -e EXPORT_FLUSH_EVERY="$EXPORT_FLUSH_EVERY" \
    -e EXPORT_TOPN="$EXPORT_TOPN" \
    -e DECOMPILE_SEC="$DECOMPILE_SEC" \
    -e SKIP_PSEUDO="$SKIP_PSEUDO" \
    "$GHIDRA_IMAGE" \
    /opt/ghidra/support/analyzeHeadless \
      "/tmp/gh_proj" "myproj" \
      -import "$BIN_CONT" \
      -scriptPath /scripts \
      -postScript simple_export.py 2>&1 | _fmt | tee -a "$RUN_LOG"
  stop_hb; stage_done

  if [[ ! -s "$OUT_HOST" ]]; then
    echo "[full] ERROR: export failed to produce $OUT_HOST" | _fmt | tee -a "$RUN_LOG"
    exit 3
  fi
fi

# -------------------- detect programming language --------------------
DETECTED_LANG="c"  # default
if [[ -s "$OUT_HOST" && -f "tools/detect_language.py" ]]; then
  echo "[full] detecting programming language..." | _fmt | tee -a "$RUN_LOG"
  LANG_RESULT=$(python3 tools/detect_language.py "$OUT_HOST" 2>/dev/null) || true
  if echo "$LANG_RESULT" | grep -q "Detected language: CPP"; then
    DETECTED_LANG="cpp"
    echo "[full] detected C++ (auto-detected)" | _fmt | tee -a "$RUN_LOG"
  elif echo "$LANG_RESULT" | grep -q "Detected language: C"; then
    DETECTED_LANG="c"
    echo "[full] detected C (auto-detected)" | _fmt | tee -a "$RUN_LOG"
  fi
  # Log analysis details
  echo "$LANG_RESULT" | grep -E "(Confidence|Reason|mangled_symbols|thiscall_count)" | while read line; do
    echo "[full] $line" | _fmt | tee -a "$RUN_LOG"
  done
fi
export DETECTED_LANG

# -------------------- process extracted assets --------------------
if [[ -d "$WORK_DIR/extracted" && -f "$WORK_DIR/extracted/summary.json" ]]; then
  EXTRACTED_ASSETS=$(python3 -c "import json,sys; j=json.load(sys.stdin); print(len([x for x in j.get('extracted',[]) if x.endswith('.ico') or x.endswith('.bmp') or x.endswith('.cur')]))" < "$WORK_DIR/extracted/summary.json" 2>/dev/null || echo "0")
  if [[ "$EXTRACTED_ASSETS" -gt "0" ]]; then
    echo "[full] processing $EXTRACTED_ASSETS extracted assets..." | _fmt | tee -a "$RUN_LOG"
    stage "asset-processing"; start_hb
    
    # Process PE resources and fix ICO files
    if [[ -f "fix_pe_resources.py" && -d "$WORK_DIR/extracted/7z" ]]; then
      python3 fix_pe_resources.py "$WORK_DIR/extracted/7z" 2>&1 | _fmt | tee -a "$RUN_LOG" || true
    fi
    
    # Embed assets into C source code
    if [[ -f "embed_assets.py" ]]; then
      python3 embed_assets.py "$WORK_DIR/extracted" "$WORK_DIR/recovered_project" 2>&1 | _fmt | tee -a "$RUN_LOG" || true
    fi
    
    # Generate Windows resource scripts
    if [[ -f "generate_windows_build.py" ]]; then
      python3 generate_windows_build.py "$WORK_DIR/recovered_project" 2>&1 | _fmt | tee -a "$RUN_LOG" || true
    fi
    
    stop_hb; stage_done
  else
    echo "[full] no extractable assets found" | _fmt | tee -a "$RUN_LOG"
  fi
fi

# -------------------- apply language-specific formatting --------------------
if [[ "$DETECTED_LANG" == "cpp" && -d "$WORK_DIR/recovered_project/src" ]]; then
  echo "[full] applying C++ formatting (detected language: $DETECTED_LANG)..." | _fmt | tee -a "$RUN_LOG"
  stage "cpp-formatting"; start_hb
  
  # Rename .c files to .cpp
  find "$WORK_DIR/recovered_project/src" -name "*.c" -exec bash -c 'mv "$1" "${1%.c}.cpp"' _ {} \;
  
  # Update Makefile for C++
  if [[ -f "$WORK_DIR/recovered_project/Makefile" ]]; then
    sed -i 's/CC=gcc/CXX=g++/g' "$WORK_DIR/recovered_project/Makefile"
    sed -i 's/\$(wildcard src\/\*\.c)/$(wildcard src\/*.cpp)/g' "$WORK_DIR/recovered_project/Makefile"
    sed -i 's/OBJS=\$(SRCS:\.c=\.o)/OBJS=$(SRCS:.cpp=.o)/g' "$WORK_DIR/recovered_project/Makefile"
    sed -i 's/\$(CC)/$(CXX)/g' "$WORK_DIR/recovered_project/Makefile"
  fi
  
  # Run humanize_project if available to apply C++ specific improvements
  if [[ -f "humanize_project.py" ]]; then
    python3 humanize_project.py --lang cpp "$WORK_DIR/recovered_project" 2>&1 | _fmt | tee -a "$RUN_LOG" || true
  fi
  
  stop_hb; stage_done
elif [[ "$DETECTED_LANG" == "c" ]]; then
  echo "[full] using C formatting (detected language: $DETECTED_LANG)" | _fmt | tee -a "$RUN_LOG"
fi

# -------------------- analyze (label) with LLM4Decompile --------------------
stage "analyze(label) with profile: ${LLM_PROFILE_LABEL}"; start_hb
use_profile "$LLM_PROFILE_LABEL"
export HUNT_TOPN HUNT_MIN_SIZE HUNT_CACHE HUNT_RESUME ENABLE_CAPA ENABLE_YARA ENABLE_FLOSS CAPA_SIGNATURES
stdbuf -oL -eL python3 tools/function_hunt/run_autodiscover.py 2>&1 | _fmt | tee -a "$RUN_LOG"
stop_hb; stage_done

JSONL="$WORK_DIR/hunt/functions.labeled.jsonl"
if [[ ! -s "$JSONL" ]]; then
  echo "[full] ERROR: expected mapping not found: $JSONL" | _fmt | tee -a "$RUN_LOG"
  exit 4
fi

# --------------------in case of malfunction create the directory we need ----------------------
: "${SYNTHESIZE_SRC:=1}"
if [[ "$SYNTHESIZE_SRC" == "1" && ! -d "$WORK_DIR/recovered_project/src" ]]; then
  echo "[prep] synthesizing per-function stubs from labels → $WORK_DIR/recovered_project/src" | _fmt | tee -a "$RUN_LOG"
  python3 - "$JSONL" "$WORK_DIR/recovered_project/src" <<'PY'
import os, sys, json, re
jsonl_path, out_dir = sys.argv[1:]
os.makedirs(out_dir, exist_ok=True)
def to_int(a):
    if a is None: return None
    if isinstance(a, int): return a
    s=str(a).strip().lower()
    try: return int(s,16) if s.startswith("0x") else int(s,10)
    except: return None
def san(s):
    s = re.sub(r'[^0-9A-Za-z_]+', '_', (s or 'func')); return (s or 'func')[:128]
count=0
with open(jsonl_path, 'r', encoding='utf-8') as f:
  for line in f:
    try: o = json.loads(line)
    except: continue
    addr = to_int(o.get('addr') or o.get('start') or (o.get('function') or {}).get('addr'))
    if addr is None: continue
    name = o.get('best_name') or o.get('name') or f"func_{addr:#x}"
    base = f"{san(name)}_{addr:#x}.c"
    path = os.path.join(out_dir, base)
    if os.path.exists(path): continue
    with open(path,'w',encoding='utf-8') as w:
      w.write(f"// stub generated from labels; address: {addr:#x}\n\n")
      w.write(f"void {san(name)}(void) {{\n  /* implemented in reimplement step */\n}}\n")
    count += 1
print(f"[prep] wrote {count} stubs")
PY
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

if [[ "$REIMPL_ENABLE" == "1" ]]; then
  stage "re-implement with profile: ${LLM_PROFILE_REIMPL}"; start_hb
  if ! use_profile "$LLM_PROFILE_REIMPL"; then
    echo "[full] re-implement disabled: failed to switch LLM profile" | _fmt | tee -a "$RUN_LOG"
    stop_hb; stage_done
  else
    export REIMPL_MIN_CONF REIMPL_MAX_FNS
    REIMPL_IN_DIR="$WORK_DIR/recovered_project"
    REIMPL_OUT_DIR="$WORK_DIR/recovered_project_reimpl/src"
    mkdir -p "$REIMPL_OUT_DIR"
    if [[ -x "./reimplement.sh" ]]; then
      runlog ./reimplement.sh
    else
      runlog python3 tools/reimplement.py \
        --src-dir "$REIMPL_IN_DIR" \
        --mapping "$JSONL" \
        --out-dir "$REIMPL_OUT_DIR" \
        --threshold "$REIMPL_MIN_CONF" \
        --max-fns "$REIMPL_MAX_FNS"
    fi
    stop_hb; stage_done
  fi
else
  echo "[full] re-implement disabled (REIMPL_ENABLE=0)" | _fmt | tee -a "$RUN_LOG"
fi

# -------------------- finalize project with detected language --------------------
if [[ -d "$WORK_DIR/recovered_project/src" ]]; then
  echo "[full] finalizing project structure for $DETECTED_LANG..." | _fmt | tee -a "$RUN_LOG"
  
  # Generate or update Makefile based on detected language
  if [[ ! -f "$WORK_DIR/recovered_project/Makefile" ]]; then
    MAKEFILE_CONTENT="CC=gcc
CFLAGS=-Wall -Wextra -O2 -Iinclude
SRCS=\$(wildcard src/*.c)
OBJS=\$(SRCS:.c=.o)
BIN=recovered_bin

all: \$(BIN)

\$(BIN): \$(OBJS)
	\$(CC) \$(CFLAGS) -o \$@ \$^

clean:
	rm -f \$(OBJS) \$(BIN)"

    if [[ "$DETECTED_LANG" == "cpp" ]]; then
      MAKEFILE_CONTENT=$(echo "$MAKEFILE_CONTENT" | sed 's/CC=gcc/CXX=g++/g' | sed 's/wildcard src\/\*\.c/wildcard src\/*.cpp/g' | sed 's/SRCS:\.c=\.o/SRCS:.cpp=.o/g' | sed 's/\$(CC)/$(CXX)/g')
    fi
    
    echo "$MAKEFILE_CONTENT" > "$WORK_DIR/recovered_project/Makefile"
    echo "[full] generated Makefile for $DETECTED_LANG" | _fmt | tee -a "$RUN_LOG"
  fi
  
  # Create simple README
  if [[ ! -f "$WORK_DIR/recovered_project/README.md" ]]; then
    cat > "$WORK_DIR/recovered_project/README.md" << EOF
# Recovered Project

This project was decompiled and recovered using the decomp toolkit.

## Language: $(echo "$DETECTED_LANG" | tr '[:lower:]' '[:upper:]')

## Build Instructions

\`\`\`bash
make clean && make
\`\`\`

## Structure

- \`src/\` - Recovered source code files
- \`include/\` - Header files (including embedded resources)
- \`Makefile\` - Build configuration

## Assets

This project includes $(ls "$WORK_DIR/recovered_project/include/" 2>/dev/null | wc -l) embedded resource files.

EOF
    echo "[full] generated README.md" | _fmt | tee -a "$RUN_LOG"
  fi
  
  # Count generated files
  C_FILES=$(find "$WORK_DIR/recovered_project/src" -name "*.c" 2>/dev/null | wc -l)
  CPP_FILES=$(find "$WORK_DIR/recovered_project/src" -name "*.cpp" 2>/dev/null | wc -l)
  TOTAL_FILES=$((C_FILES + CPP_FILES))
  
  echo "[full] project complete: $TOTAL_FILES source files (C: $C_FILES, C++: $CPP_FILES)" | _fmt | tee -a "$RUN_LOG"
fi
